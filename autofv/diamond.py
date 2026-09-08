"""The bounded diamond scheduler and sole candidate-acceptance path."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from pathlib import Path, PurePosixPath
from typing import Any

from . import probes, worker
from .contracts import ContractError, ContractInconclusive, _sha256
from .model import _model_request, _parallel_model_requests
from .run_state import (
    _RunState,
    _canonical_sha256,
    _checkpoint_if_enabled,
    _event_once,
    _external_call,
    _node_update,
)

def _statement_fingerprint(run: dict[str, Any], graph: dict[str, Any]) -> str:
    spec = graph["supplied_specs"][graph["frozen_targets"][0]]
    source = worker.read_project_file(run, graph["source_paths"][spec]).decode("utf-8")
    name = spec.removeprefix("probe:").rsplit(".", 1)[-1]
    lines = source.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.lstrip().startswith(f"theorem {name}")),
        None,
    )
    if start is None:
        raise ContractError("supplied target statement is missing from its source")
    statement: list[str] = []
    for line in lines[start:]:
        if ":=" in line:
            statement.append(line.split(":=", 1)[0].rstrip())
            break
        statement.append(line)
    else:
        raise ContractError("supplied target statement has no theorem body")
    return hashlib.sha256("\n".join(statement).encode("utf-8")).hexdigest()


def _statement_record(response: dict[str, Any], policy_sha256: str) -> dict[str, Any]:
    payload = response["payload"]
    text = payload["text"]
    return {
        "declaration": payload["declaration"],
        "kind": "theorem",
        "canon": text,
        "canonical_sha256": _canonical_sha256({"kind": "theorem", "canon": text}),
        "model_fingerprint": payload["text_sha256"],
        "consumer_fingerprints": [
            value
            for value in response["statement_fingerprints"]
            if value != payload["text_sha256"]
        ],
        "native_decide_policy_sha256": policy_sha256,
        "status": "provisional",
    }


def _candidate_binding_is_current(
    fingerprints: list[str],
    policy_sha256: str,
    current_fingerprints: list[str],
    current_policy_sha256: str,
) -> bool:
    """Return whether candidate inputs are a non-empty subset of current truth."""
    return (
        isinstance(fingerprints, list)
        and bool(fingerprints)
        and all(isinstance(value, str) for value in fingerprints)
        and fingerprints == sorted(set(fingerprints))
        and isinstance(current_fingerprints, list)
        and all(isinstance(value, str) for value in current_fingerprints)
        and set(fingerprints) <= set(current_fingerprints)
        and isinstance(policy_sha256, str)
        and isinstance(current_policy_sha256, str)
        and hmac.compare_digest(policy_sha256, current_policy_sha256)
    )


def _lane_descriptors(
    run: dict[str, Any],
    graph: dict[str, Any],
    nodes: list[str],
    *,
    base_commit: str | None = None,
) -> list[dict[str, Any]]:
    """Describe private one-file lanes without granting canonical-tree access."""
    root = (
        str(Path(run["run_root"]) / "lanes")
        if Path(run.get("project_dir", "/volume/work/project")).is_dir()
        else "/volume/lanes"
    )
    base = base_commit or run.get("accepted", {}).get(
        "accepted_commit", run["base_commit"]
    )
    lanes = []
    assigned = set()
    for node in nodes:
        leaf = node.rsplit(".", 1)[-1].lower()
        if re.fullmatch(r"[a-z0-9-]+", leaf) is None:
            raise ContractError("proof node cannot form a safe lane identity")
        path = graph["source_paths"].get(node)
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.suffix != ".lean"
            or path in assigned
        ):
            raise ContractError("proof lane must own one distinct safe Lean path")
        assigned.add(path)
        request_id = f"proof-{leaf}-001"
        lane_root = f"{root}/{request_id}"
        lanes.append(
            {
                "schema": "autofv-proof-lane/v1",
                "lane_id": request_id,
                "request_id": request_id,
                "node": node,
                "base_commit": base,
                "assigned_path": path,
                "worktree_path": f"{lane_root}/work",
                "cache_path": f"{lane_root}/cache",
                "result_path": f"{lane_root}/result/candidate.json",
            }
        )
    return lanes


def _worker_lane(lane: dict[str, Any]) -> dict[str, Any]:
    return {
        key: lane[key]
        for key in (
            "schema",
            "lane_id",
            "request_id",
            "node",
            "base_commit",
            "assigned_path",
            "worktree_path",
            "cache_path",
            "result_path",
        )
    }


def _candidate_record(
    response: dict[str, Any], lane: dict[str, Any], policy_sha256: str
) -> dict[str, Any]:
    """Bind an untrusted lane response to its frozen inputs and private path."""
    if response.get("kind") != "patch":
        raise ContractError("proof lane returned a non-patch result")
    payload = response.get("payload", {})
    patch = payload.get("patch")
    path = lane.get("assigned_path")
    if (
        response.get("request_id") != lane.get("request_id")
        or response.get("assigned_path") != path
        or payload.get("assigned_path") != path
        or payload.get("base_commit") != response.get("base_commit")
        or not isinstance(patch, str)
        or not patch.startswith(f"diff --git a/{path} b/{path}\n")
        or patch.count("diff --git ") != 1
        or payload.get("patch_sha256") != hashlib.sha256(patch.encode()).hexdigest()
    ):
        raise ContractError("proof lane result escaped its assignment")
    local_gate = {
        "schema": "autofv-lane-gate-receipt/v1",
        "lane_id": lane["lane_id"],
        "request_id": lane["request_id"],
        "assigned_path": path,
        "source_base_commit": response["base_commit"],
        "checked_base_commit": lane["base_commit"],
        "patch_sha256": payload["patch_sha256"],
        "statement_fingerprints": response["statement_fingerprints"],
        "native_decide_policy_sha256": policy_sha256,
        "status": "passed",
        "checks": [
            "assigned_path_scope",
            "patch_sha256",
            "statement_fingerprint_binding",
            "native_decide_policy_binding",
        ],
    }
    body = {
        "schema": "autofv-candidate/v1",
        "lane_id": lane["lane_id"],
        "request_id": lane["request_id"],
        "node": lane["node"],
        "base_commit": response["base_commit"],
        "checked_base_commit": lane["base_commit"],
        "assigned_path": lane["assigned_path"],
        "worktree_path": lane["worktree_path"],
        "cache_path": lane["cache_path"],
        "result_path": lane["result_path"],
        "patch_sha256": payload.get("patch_sha256"),
        "statement_fingerprints": response.get("statement_fingerprints"),
        "native_decide_policy_sha256": policy_sha256,
        "native_decide_inventory_delta": [],
        "local_gate_receipt": local_gate,
        "local_gate_receipt_sha256": _canonical_sha256(local_gate),
        "result_sha256": _canonical_sha256(response),
    }
    return {
        **body,
        "candidate_sha256": _canonical_sha256(body),
        "response": response,
    }


def _proof_ready_nodes(graph: dict[str, Any], accepted_nodes: set[str]) -> list[str]:
    dependencies = {node: set() for node in graph["selected_nodes"]}
    for consumer, dependency in graph["term_dependencies"]:
        dependencies[consumer].add(dependency)
    return sorted(
        node
        for node, required in dependencies.items()
        if node not in accepted_nodes and required <= accepted_nodes
    )


def _checkpoint_candidate(
    state: _RunState,
    candidate: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Deduplicate and gate one candidate under the sole canonical writer."""
    lock = state.setdefault("_accept_lock", threading.Lock())
    with lock:
        response = candidate.get("response")
        body = {
            key: value
            for key, value in candidate.items()
            if key not in {"candidate_sha256", "response"}
        }
        digest = _sha256(candidate.get("candidate_sha256"), "candidate hash")
        if not hmac.compare_digest(digest, _canonical_sha256(body)):
            raise ContractError("candidate hash mismatch")
        processed = state.setdefault("processed_candidate_sha256", [])
        current = state.get("accepted") or state["run"].get("accepted") or {
            "accepted_commit": state["run"]["base_commit"]
        }
        if digest in processed:
            return {
                "status": "duplicate",
                "reason": "candidate_already_processed",
                "candidate_sha256": digest,
                "accepted_commit": current["accepted_commit"],
            }
        processed.append(digest)

        def reject(reason: str, *, requeue: bool = False) -> dict[str, Any]:
            status = "requeue" if requeue else "rejected"
            receipt = {
                "candidate_sha256": digest,
                "node": candidate.get("node"),
                "status": status,
                "reason": reason,
                "accepted_commit": current["accepted_commit"],
            }
            state.setdefault("candidate_receipts", []).append(receipt)
            state["run"]["events"].append(
                f"candidate_{status}:{candidate.get('request_id')}"
            )
            state.pop("inflight_transition", None)
            _checkpoint_if_enabled(
                state, f"candidate:{candidate.get('request_id')}:{status}"
            )
            return receipt

        if not isinstance(response, dict) or response.get("kind") != "patch":
            return reject("candidate_result_invalid")
        local_gate = candidate.get("local_gate_receipt")
        if (
            not isinstance(local_gate, dict)
            or local_gate.get("status") != "passed"
            or candidate.get("local_gate_receipt_sha256")
            != _canonical_sha256(local_gate)
            or local_gate.get("request_id") != candidate.get("request_id")
            or local_gate.get("assigned_path") != candidate.get("assigned_path")
            or local_gate.get("source_base_commit") != candidate.get("base_commit")
            or local_gate.get("checked_base_commit")
            != candidate.get("checked_base_commit")
            or local_gate.get("native_decide_policy_sha256")
            != candidate.get("native_decide_policy_sha256")
        ):
            return reject("candidate_local_gate_mismatch")
        payload = response.get("payload", {})
        path = candidate.get("assigned_path")
        patch = payload.get("patch")
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or not isinstance(patch, str)
            or response.get("request_id") != candidate.get("request_id")
            or response.get("assigned_path") != path
            or payload.get("assigned_path") != path
            or response.get("base_commit") != candidate.get("base_commit")
            or payload.get("base_commit") != candidate.get("base_commit")
            or candidate.get("patch_sha256") != payload.get("patch_sha256")
            or not patch.startswith(f"diff --git a/{path} b/{path}\n")
            or patch.count("diff --git ") != 1
        ):
            return reject("candidate_scope_mismatch")
        if not hmac.compare_digest(
            candidate.get("result_sha256", ""), _canonical_sha256(response)
        ):
            return reject("candidate_result_mismatch")
        frozen = state["contracts"]["frozen_fingerprints"]
        if not _candidate_binding_is_current(
            candidate.get("statement_fingerprints"),
            candidate.get("native_decide_policy_sha256", ""),
            frozen,
            state["run"]["native_decide_policy_sha256"],
        ):
            reason = (
                "candidate_policy_mismatch"
                if candidate.get("native_decide_policy_sha256")
                != state["run"]["native_decide_policy_sha256"]
                else "candidate_fingerprint_mismatch"
            )
            return reject(reason)
        if not isinstance(candidate.get("native_decide_inventory_delta"), list):
            return reject("candidate_native_decide_inventory_invalid")

        stale = candidate["base_commit"] != current["accepted_commit"]
        state["inflight_transition"] = {
            "kind": "candidate_accept",
            "candidate_sha256": digest,
            "request_id": candidate["request_id"],
            "node": candidate["node"],
            "base_commit": candidate["base_commit"],
            "previous_accepted_commit": current["accepted_commit"],
        }
        try:
            accepted = _external_call(
                state,
                f"candidate:{candidate['request_id']}:apply-build",
                lambda: worker.accept_candidate(state["run"], response, manifest),
            )
        except worker.WorkerError as exc:
            return reject(str(exc)[:1000], requeue=stale)
        if accepted.get("accepted_commit") == current["accepted_commit"]:
            return reject("candidate_did_not_advance")

        status = "accepted_reverified" if stale else "accepted"
        transition = {
            "sequence": len(state.setdefault("accepted_sequence", [])) + 1,
            "candidate_sha256": digest,
            "node": candidate["node"],
            "status": status,
            "base_commit": candidate["base_commit"],
            "previous_accepted_commit": current["accepted_commit"],
            "accepted_commit": accepted["accepted_commit"],
        }
        transition["transition_sha256"] = _canonical_sha256(transition)
        state["accepted_sequence"].append(transition)
        state["accepted"] = accepted
        state["working"] = dict(accepted)
        state["run"]["accepted"] = accepted
        accepted_nodes = state.setdefault("accepted_nodes", [])
        if candidate["node"] not in accepted_nodes:
            accepted_nodes.append(candidate["node"])
        receipt = {
            "candidate_sha256": digest,
            "node": candidate["node"],
            "status": status,
            "reason": None,
            "local_gate_receipt_sha256": candidate[
                "local_gate_receipt_sha256"
            ],
            "accepted_commit": accepted["accepted_commit"],
        }
        state.setdefault("candidate_receipts", []).append(receipt)
        state["run"]["events"].append(
            f"candidate_{status}:{candidate['request_id']}"
        )
        state.pop("inflight_transition", None)
        _checkpoint_if_enabled(
            state, f"candidate:{candidate['request_id']}:accepted"
        )
        return receipt


def _repair_contracts(
    state: _RunState,
    dependency: dict[str, Any],
    top_fingerprint: str,
) -> dict[str, Any]:
    """Run the bounded weak-draft, consumer-check, review, and freeze sequence."""
    run = state["run"]
    previous = state.get("contracts")
    if isinstance(previous, dict) and previous.get("frozen_fingerprints"):
        return previous
    policy_sha256 = run["native_decide_policy_sha256"]
    contracts = {
        "attempts": [],
        "provisional": {},
        "frozen": {},
        "frozen_fingerprints": [],
        "invalidated_fingerprints": [],
        "feasibility": [],
    }
    state["contracts"] = contracts

    weak_left, _ = _model_request(
        state,
        request_id="contract-left-001",
        role="contract-author",
        input_hashes=[dependency["payload_sha256"], top_fingerprint],
    )
    right, _ = _model_request(
        state,
        request_id="contract-right-001",
        role="contract-author",
        input_hashes=[dependency["payload_sha256"], top_fingerprint],
    )
    weak_record = _statement_record(weak_left, policy_sha256)
    right_record = _statement_record(right, policy_sha256)
    contracts["attempts"].extend((weak_record, right_record))
    contracts["provisional"] = {
        weak_record["declaration"]: weak_record,
        right_record["declaration"]: right_record,
    }
    for event in (
        f"contract_draft:{weak_record['declaration']}",
        f"contract_draft:{right_record['declaration']}",
        "provisional_contracts_applied",
    ):
        _event_once(run, event)

    feasibility = _external_call(
        state,
        "build:provisional-consumer-weak",
        lambda: worker.check_contract_feasibility(
            run, [weak_record["canon"], right_record["canon"]]
        ),
    )
    contracts["feasibility"].append(feasibility)
    _event_once(run, f"provisional_consumer:{feasibility['status']}")
    if feasibility["status"] != "failed":
        raise ContractError("fixture weak contract unexpectedly passed consumer proof")

    strong_left, _ = _model_request(
        state,
        request_id="contract-left-review-002",
        role="contract-reviewer",
        input_hashes=[weak_record["model_fingerprint"], top_fingerprint],
    )
    strong_record = _statement_record(strong_left, policy_sha256)
    if (
        strong_record["declaration"] != weak_record["declaration"]
        or strong_record["model_fingerprint"] == weak_record["model_fingerprint"]
    ):
        raise ContractError("contract review did not replace the weak statement")
    contracts["attempts"].append(strong_record)
    contracts["invalidated_fingerprints"].append(weak_record["model_fingerprint"])
    contracts["provisional"][strong_record["declaration"]] = strong_record
    for event in (
        f"contract_review:{strong_record['declaration']}",
        f"statement_invalidated:{weak_record['model_fingerprint']}",
    ):
        _event_once(run, event)

    feasibility = _external_call(
        state,
        "build:provisional-consumer-strong",
        lambda: worker.check_contract_feasibility(
            run, [strong_record["canon"], right_record["canon"]]
        ),
    )
    contracts["feasibility"].append(feasibility)
    _event_once(run, f"provisional_consumer:{feasibility['status']}")
    if feasibility["status"] != "passed":
        _event_once(run, "contract_inconclusive")
        raise ContractInconclusive(feasibility["diagnostic"])

    contracts["frozen"] = {
        record["declaration"]: {**record, "status": "frozen"}
        for record in (strong_record, right_record)
    }
    contracts["provisional"] = {}
    contracts["frozen_fingerprints"] = sorted(
        [
            top_fingerprint,
            strong_record["model_fingerprint"],
            right_record["model_fingerprint"],
        ]
    )
    _event_once(run, "statements_frozen")
    _checkpoint_if_enabled(state, "contracts:frozen")
    return contracts


def _freeze(state: _RunState) -> dict[str, Any]:
    if state.get("graph"):
        return _node_update(state, graph=state["graph"])
    rust_raw, aeneas_raw = _external_call(
        state, "probe", lambda: worker.run_probes(state["run"])
    )
    graph = probes.parse_probe_bytes(state["manifest"], rust_raw, aeneas_raw)
    state["graph"] = graph
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        state["run"][name] = graph[name]
    _event_once(state["run"], "targets_frozen")
    _checkpoint_if_enabled(state, "probe:parsed")
    return _node_update(state, graph=graph)


def _agent_loop(state: _RunState) -> dict[str, Any]:
    graph, run, manifest = state["graph"], state["run"], state["manifest"]
    if len(graph["frozen_targets"]) != 1 or len(graph["proof_batches"]) != 2:
        raise ContractError("the V1 tracer requires one acyclic diamond target")
    top_fingerprint = _external_call(
        state,
        "source:read-top-statement",
        lambda: _statement_fingerprint(run, graph),
    )
    probe_hash = graph["graph_sha256"]

    scout, _ = _model_request(
        state,
        request_id="scout-001",
        role="scout",
        input_hashes=[probe_hash],
    )
    dependency, _ = _model_request(
        state,
        request_id="dependency-plan-001",
        role="dependency-planner",
        input_hashes=[scout["payload_sha256"], probe_hash],
    )
    contracts = _repair_contracts(state, dependency, top_fingerprint)
    leaf_nodes = graph["proof_batches"][0]
    if _proof_ready_nodes(graph, set()) != leaf_nodes:
        raise ContractError("the V1 leaf proof frontier is inconsistent")
    lanes = state.setdefault("lanes", [])
    existing_lane_ids = {lane["lane_id"] for lane in lanes}
    new_lanes = [
        {**lane, "status": "preparing"}
        for lane in _lane_descriptors(run, graph, leaf_nodes)
        if lane["lane_id"] not in existing_lane_ids
    ]
    if new_lanes:
        lanes.extend(new_lanes)
        _external_call(
            state,
            "lanes:prepare-leaves",
            lambda: worker.prepare_lanes(
                run,
                [_worker_lane(lane) for lane in new_lanes],
            ),
        )
        for lane in new_lanes:
            lane["status"] = "running"
    leaf_lanes = [lane for lane in lanes if lane["node"] in leaf_nodes]
    for key in (
        "lane_intervals",
        "candidate_receipts",
        "processed_candidate_sha256",
        "accepted_sequence",
        "accepted_nodes",
    ):
        value = state.setdefault(key, {} if key == "lane_intervals" else [])
        run[key] = value
    run["lanes"] = lanes
    exchanges = _parallel_model_requests(
        state,
        [
            {
                "request_id": lane["request_id"],
                "role": "proof-author",
                "batch_id": "proof-leaves-001",
                "input_hashes": [
                    contracts["frozen"][
                        f"{lane['node'].removeprefix('probe:')}_spec"
                    ]["model_fingerprint"],
                    probe_hash,
                ],
            }
            for lane in leaf_lanes
        ],
    )
    leaf_patches = []
    for lane, (response, _) in zip(leaf_lanes, exchanges, strict=True):
        candidate = _candidate_record(
            response, lane, run["native_decide_policy_sha256"]
        )
        if candidate["candidate_sha256"] not in state["processed_candidate_sha256"]:
            _external_call(
                state,
                f"lane:{lane['lane_id']}:persist",
                lambda candidate=candidate, lane=lane: worker.persist_lane_result(
                    run,
                    lane,
                    {
                        key: value
                        for key, value in candidate.items()
                        if key != "response"
                    },
                ),
            )
        transition = _checkpoint_candidate(state, candidate, manifest)
        if transition["status"].startswith("accepted") or (
            transition["status"] == "duplicate"
            and lane["node"] in state["accepted_nodes"]
        ):
            lane["status"] = "accepted"
            lane["requeueable"] = False
        else:
            raise ContractError(
                f"leaf candidate {lane['request_id']} was {transition['status']}: "
                f"{transition['reason']}"
            )
        leaf_patches.append(response["payload"]["patch_sha256"])

    top_batch = graph["proof_batches"][1]
    if set(top_batch) <= set(state["accepted_nodes"]):
        return _node_update(state, **{
            "accepted": state["accepted"],
            "contracts": contracts,
            "receipts": state["receipts"],
            "cost": state["cost"],
            "lanes": lanes,
            "lane_intervals": state["lane_intervals"],
            "candidate_receipts": state["candidate_receipts"],
            "processed_candidate_sha256": state["processed_candidate_sha256"],
            "accepted_sequence": state["accepted_sequence"],
            "accepted_nodes": state["accepted_nodes"],
        })
    ready = _proof_ready_nodes(graph, set(state["accepted_nodes"]))
    if ready != top_batch:
        raise ContractError("top proof became ready before both leaves were accepted")
    left_fingerprint = contracts["frozen"]["Diamond.left_spec"]["model_fingerprint"]
    right_fingerprint = contracts["frozen"]["Diamond.right_spec"]["model_fingerprint"]
    proof_top, _ = _model_request(
        state,
        request_id="proof-top-001",
        role="proof-author",
        input_hashes=[
            left_fingerprint,
            right_fingerprint,
            top_fingerprint,
            *leaf_patches,
        ],
    )
    desired_top = _lane_descriptors(run, graph, ready)[0]
    top_lane = next(
        (lane for lane in lanes if lane["lane_id"] == desired_top["lane_id"]), None
    )
    if top_lane is None:
        top_lane = {**desired_top, "status": "preparing"}
        lanes.append(top_lane)
        _external_call(
            state,
            "lanes:prepare-top",
            lambda: worker.prepare_lanes(run, [_worker_lane(top_lane)]),
        )
        top_lane["status"] = "running"
    top_candidate = _candidate_record(
        proof_top, top_lane, run["native_decide_policy_sha256"]
    )
    if top_candidate["candidate_sha256"] not in state["processed_candidate_sha256"]:
        _external_call(
            state,
            f"lane:{top_lane['lane_id']}:persist",
            lambda: worker.persist_lane_result(
                run,
                top_lane,
                {
                    key: value
                    for key, value in top_candidate.items()
                    if key != "response"
                },
            ),
        )
    transition = _checkpoint_candidate(state, top_candidate, manifest)
    if transition["status"].startswith("accepted") or (
        transition["status"] == "duplicate"
        and top_lane["node"] in state["accepted_nodes"]
    ):
        top_lane["status"] = "accepted"
        top_lane["requeueable"] = False
    else:
        raise ContractError(
            f"top candidate was {transition['status']}: {transition['reason']}"
        )
    accepted = state["accepted"]
    return _node_update(state, **{
        "accepted": accepted,
        "contracts": contracts,
        "receipts": state["receipts"],
        "cost": state["cost"],
        "lanes": lanes,
        "lane_intervals": state["lane_intervals"],
        "candidate_receipts": state["candidate_receipts"],
        "processed_candidate_sha256": state["processed_candidate_sha256"],
        "accepted_sequence": state["accepted_sequence"],
        "accepted_nodes": state["accepted_nodes"],
    })
