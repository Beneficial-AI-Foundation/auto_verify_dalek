"""The bounded diamond scheduler and sole candidate-acceptance path."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path, PurePosixPath
from typing import Any

from . import probes, worker
from .contracts import BudgetExhausted, ContractError, ContractInconclusive, _sha256
from .model import (
    _accept_model_exchange,
    _invoke_model,
    _model_envelope,
    _model_request,
)
from .run_state import (
    _RunState,
    _canonical_sha256,
    _checkpoint_if_enabled,
    _event_once,
    _external_call,
    _check_budget,
    _node_update,
)

MAX_PARALLEL_LANES = 4


def _record_preparation_defect(
    state: _RunState, kind: str, **details: Any
) -> dict[str, Any]:
    defect = {"kind": kind, **details}
    defects = state.setdefault("preparation_defects", [])
    if defect not in defects:
        defects.append(defect)
    _event_once(state["run"], f"preparation_defect:{kind}")
    return defect


def _validate_scheduling_graph(state: _RunState) -> str:
    """Freeze one valid declaration DAG before any model or worker call."""
    graph = state.get("graph")
    if not isinstance(graph, dict):
        raise ContractError("scheduling graph is missing")
    nodes = graph.get("selected_nodes")
    targets = graph.get("frozen_targets")
    edges = graph.get("term_dependencies")
    type_edges = graph.get("type_dependencies", [])
    paths = graph.get("source_paths")
    supplied_specs = graph.get("supplied_specs", {})
    if (
        not isinstance(nodes, list)
        or not nodes
        or any(not isinstance(node, str) or not node for node in nodes)
        or len(nodes) != len(set(nodes))
        or not isinstance(targets, list)
        or not targets
        or any(target not in nodes for target in targets)
        or not isinstance(edges, list)
        or not isinstance(type_edges, list)
        or not isinstance(paths, dict)
        or not isinstance(supplied_specs, dict)
        or any(
            target not in targets or not isinstance(spec, str) or not spec
            for target, spec in supplied_specs.items()
        )
    ):
        _record_preparation_defect(state, "invalid_graph_shape")
        raise ContractError("invalid scheduling graph shape")

    node_set = set(nodes)
    normalized_type_edges: list[list[str]] = []
    for edge in type_edges:
        if (
            not isinstance(edge, list)
            or len(edge) != 2
            or any(not isinstance(item, str) or not item for item in edge)
        ):
            _record_preparation_defect(state, "invalid_type_edge", edge=edge)
            raise ContractError(f"invalid scheduling type edge: {edge!r}")
        normalized_type_edges.append(edge)
    if len({tuple(edge) for edge in normalized_type_edges}) != len(
        normalized_type_edges
    ):
        _record_preparation_defect(state, "duplicate_type_edge")
        raise ContractError("duplicate scheduling type edge")
    type_declarations = {item for edge in normalized_type_edges for item in edge}
    declared_paths = node_set | set(supplied_specs.values()) | type_declarations
    if set(paths) != declared_paths:
        _record_preparation_defect(state, "invalid_graph_shape")
        raise ContractError("invalid scheduling graph shape")
    normalized_edges: list[list[str]] = []
    for edge in edges:
        if (
            not isinstance(edge, list)
            or len(edge) != 2
            or any(not isinstance(item, str) for item in edge)
            or edge[0] not in node_set
            or edge[1] not in node_set
        ):
            _record_preparation_defect(state, "undeclared_edge", edge=edge)
            raise ContractError(f"undeclared scheduling edge: {edge!r}")
        normalized_edges.append(edge)
    if len({tuple(edge) for edge in normalized_edges}) != len(normalized_edges):
        _record_preparation_defect(state, "duplicate_edge")
        raise ContractError("duplicate scheduling edge")
    for declaration, path in paths.items():
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.suffix != ".lean"
        ):
            _record_preparation_defect(
                state, "invalid_source_path", declaration=declaration
            )
            raise ContractError(f"invalid scheduling source path: {declaration}")

    dependents = {node: [] for node in nodes}
    indegree = {node: 0 for node in nodes}
    for consumer, dependency in normalized_edges:
        dependents[dependency].append(consumer)
        indegree[consumer] += 1
    ready = sorted(node for node, count in indegree.items() if count == 0)
    visited: list[str] = []
    while ready:
        node = ready.pop(0)
        visited.append(node)
        for consumer in sorted(dependents[node]):
            indegree[consumer] -= 1
            if indegree[consumer] == 0:
                ready.append(consumer)
                ready.sort()
    if len(visited) != len(nodes):
        members = sorted(node for node, count in indegree.items() if count)
        sources = {node: paths[node] for node in members}
        _record_preparation_defect(
            state,
            "cycle",
            nodes=members,
            declarations=members,
            source_paths=sources,
            edges=[edge for edge in normalized_edges if set(edge) <= set(members)],
        )
        raise ContractError(
            f"unsupported_dependency_cycle: nodes={members!r}; sources={sources!r}"
        )

    immutable = {
        "frozen_targets": targets,
        "selected_nodes": nodes,
        "term_dependencies": normalized_edges,
        "type_dependencies": normalized_type_edges,
        "source_paths": paths,
        "supplied_specs": supplied_specs,
    }
    digest = _canonical_sha256(immutable)
    previous = state.get("immutable_graph_sha256")
    if previous is not None and not hmac.compare_digest(previous, digest):
        _record_preparation_defect(state, "graph_mutated")
        raise ContractError("immutable scheduling graph changed")
    state["immutable_graph_sha256"] = digest
    target_states = state.setdefault("target_states", {})
    for node in nodes:
        target = target_states.setdefault(node, {})
        for key, value in {
            "phase": "contract",
            "status": "pending",
            "attempt_count": 0,
            "immediate_consumer_requirements": _immediate_consumers(graph, node),
            "contract_revision": 0,
            "contract_fingerprint": None,
            "file": paths[node],
            "block_chain": None,
        }.items():
            target.setdefault(key, value)
    state.setdefault("file_owners", {})
    state.setdefault("release_events", [])
    state.setdefault("invalidated_consumers", [])
    state.setdefault("block_chains", {})
    return digest


def _transitive_consumers(graph: dict[str, Any], node: str) -> list[str]:
    found: set[str] = set()
    frontier = [node]
    while frontier:
        dependency = frontier.pop(0)
        for consumer in _immediate_consumers(graph, dependency):
            if consumer not in found:
                found.add(consumer)
                frontier.append(consumer)
    return sorted(found)


def _validate_dependency_plan(
    state: _RunState, dependency: dict[str, Any]
) -> None:
    """Reject model-proposed declarations and edges outside the frozen graph."""
    graph = state["graph"]
    payload = dependency.get("payload")
    root = graph["frozen_targets"][0]
    expected_dependencies = {node: [] for node in graph["selected_nodes"]}
    for consumer, required in graph["term_dependencies"]:
        expected_dependencies[consumer].append(required)
    lanes = payload.get("lanes") if isinstance(payload, dict) else None
    join = payload.get("join") if isinstance(payload, dict) else None
    valid = (
        payload.get("root") == root
        if isinstance(payload, dict)
        else False
    )
    seen: set[str] = set()
    if not isinstance(lanes, list):
        valid = False
        lanes = []
    for lane in lanes:
        declaration = lane.get("declaration") if isinstance(lane, dict) else None
        if declaration in seen or declaration not in graph["selected_nodes"]:
            valid = False
            continue
        seen.add(declaration)
        depends_on = lane.get("depends_on")
        if (
            lane.get("source_path") != graph["source_paths"][declaration]
            or not isinstance(depends_on, list)
            or any(not isinstance(item, str) for item in depends_on)
            or sorted(depends_on)
            != sorted(expected_dependencies[declaration])
        ):
            valid = False
    expected_lanes = set(graph["selected_nodes"]) - {root}
    if seen != expected_lanes or not isinstance(join, dict):
        valid = False
    else:
        requires = join.get("requires")
        if (
            join.get("consumer") != root
            or not isinstance(requires, list)
            or any(not isinstance(item, str) for item in requires)
            or sorted(requires) != sorted(expected_dependencies[root])
        ):
            valid = False
    if not valid:
        _record_preparation_defect(
            state,
            "dependency_plan_outside_graph",
            root=payload.get("root") if isinstance(payload, dict) else None,
            declarations=sorted(seen),
        )
        raise ContractError("dependency plan contains an undeclared node or edge")


def _revise_contract_fingerprint(
    state: _RunState,
    node: str,
    new_fingerprint: str,
    *,
    graph: dict[str, Any] | None = None,
) -> list[str]:
    """Invalidate exactly the changed node's proof and transitive consumers."""
    if graph is None:
        _validate_scheduling_graph(state)
        graph = state["graph"]
    contracts = state["contracts"]
    fingerprints = contracts["node_fingerprints"]
    if node not in fingerprints or not isinstance(new_fingerprint, str):
        raise ContractError("contract revision references an undeclared node")
    old_fingerprint = fingerprints[node]
    if hmac.compare_digest(old_fingerprint, new_fingerprint):
        raise ContractError("contract revision did not change its fingerprint")
    consumers = _transitive_consumers(graph, node)
    fingerprints[node] = new_fingerprint
    contracts.setdefault("invalidated_fingerprints", []).append(old_fingerprint)
    frozen = contracts.get("frozen_fingerprints")
    if isinstance(frozen, list):
        contracts["frozen_fingerprints"] = sorted(
            new_fingerprint if item == old_fingerprint else item for item in frozen
        )
    revision = 1 + sum(
        item.get("node") == node for item in contracts.setdefault("revision_lineage", [])
    )
    contracts["revision_lineage"].append(
        {
            "node": node,
            "revision": revision,
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
        }
    )
    affected = {node, *consumers}
    state["accepted_nodes"] = [
        accepted for accepted in state.get("accepted_nodes", []) if accepted not in affected
    ]
    target_states = state.get("target_states", {})
    for affected_node in affected:
        state.setdefault("proof_patch_sha256", {}).pop(affected_node, None)
        target = target_states.get(affected_node)
        if target is not None:
            target["phase"] = "contract" if affected_node == node else "proof"
            target["status"] = "revised" if affected_node == node else "invalidated"
            target["block_chain"] = None
    if node in target_states:
        target_states[node]["contract_revision"] = revision
        target_states[node]["contract_fingerprint"] = new_fingerprint
    invalidated = state.setdefault("invalidated_consumers", [])
    invalidated.extend(item for item in consumers if item not in invalidated)
    _event_once(state["run"], f"contract_revised:{node}")
    return consumers


def _block_dependents(state: _RunState, node: str, reason: str) -> list[str]:
    """Retain deterministic consumer-to-failed-leaf diagnostic chains."""
    _validate_scheduling_graph(state)
    graph = state["graph"]
    chains = {node: [node]}
    frontier = [node]
    while frontier:
        dependency = frontier.pop(0)
        for consumer in _immediate_consumers(graph, dependency):
            if consumer not in chains:
                chains[consumer] = [consumer, *chains[dependency]]
                frontier.append(consumer)
    blocked = sorted(set(chains) - {node})
    target_states = state["target_states"]
    target_states[node].update(
        {"phase": "proof", "status": "failed", "reason": reason, "block_chain": [node]}
    )
    block_chains = state.setdefault("block_chains", {})
    for consumer in blocked:
        block_chains[consumer] = chains[consumer]
        target_states[consumer].update(
            {"phase": "proof", "status": "blocked", "block_chain": chains[consumer]}
        )
    affected = {node, *blocked}
    state["accepted_nodes"] = [
        accepted for accepted in state.get("accepted_nodes", []) if accepted not in affected
    ]
    for affected_node in affected:
        state.setdefault("proof_patch_sha256", {}).pop(affected_node, None)
    _event_once(state["run"], f"proof_blocked:{node}")
    return blocked

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
    lane_ids = set()
    for node in nodes:
        leaf = re.sub(r"[^a-z0-9]+", "-", node.rsplit(".", 1)[-1].lower()).strip("-")
        if not leaf:
            raise ContractError("proof node cannot form a safe lane identity")
        path = graph["source_paths"].get(node)
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.suffix != ".lean"
        ):
            raise ContractError("proof lane must own one safe Lean path")
        request_id = f"proof-{leaf}-001"
        if request_id in lane_ids:
            request_id = f"proof-{leaf}-{hashlib.sha256(node.encode()).hexdigest()[:8]}-001"
        lane_ids.add(request_id)
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


def _immediate_consumers(graph: dict[str, Any], node: str) -> list[str]:
    return sorted(
        consumer
        for consumer, dependency in graph["term_dependencies"]
        if dependency == node
    )


def _contract_frontier(graph: dict[str, Any], completed_nodes: set[str]) -> list[str]:
    return sorted(
        node
        for node in graph["selected_nodes"]
        if node not in completed_nodes
        and set(_immediate_consumers(graph, node)) <= completed_nodes
    )


def _schedule_proofs(
    graph,
    run_job,
    accept_job,
    *,
    prepare_job=None,
    accepted_nodes=(),
    max_workers=MAX_PARALLEL_LANES,
) -> set[str]:
    """Run ready declaration jobs concurrently, with one owner per Lean file."""
    accepted = set(accepted_nodes)
    submitted: set[str] = set()
    busy_files: set[str] = set()
    file_locks: dict[str, threading.Lock] = {}
    futures = {}
    submission = 0
    if type(max_workers) is not int or max_workers <= 0:
        raise ContractError("proof lane bound must be a positive integer")

    def run_locked(node: str, job):
        path = graph["source_paths"][node]
        with file_locks.setdefault(path, threading.Lock()):
            return run_job(job)

    def priority(node: str) -> tuple[int, str]:
        remaining = [
            len(
                {
                    dependency
                    for consumer, dependency in graph["term_dependencies"]
                    if consumer == parent
                }
                - accepted
            )
            for parent in _immediate_consumers(graph, node)
        ]
        return (min(remaining, default=0), node)

    with ThreadPoolExecutor(
        max_workers=min(max_workers, max(1, len(graph["selected_nodes"]))),
        thread_name_prefix="autofv-proof",
    ) as pool:
        while len(accepted) < len(graph["selected_nodes"]):
            available = max_workers - len(futures)
            for node in sorted(_proof_ready_nodes(graph, accepted), key=priority):
                if available <= 0:
                    break
                path = graph["source_paths"][node]
                if node in submitted or path in busy_files:
                    continue
                submitted.add(node)
                busy_files.add(path)
                job = prepare_job(node) if prepare_job else node
                futures[pool.submit(run_locked, node, job)] = (
                    submission,
                    node,
                    path,
                )
                submission += 1
                available -= 1
            if len(accepted) == len(graph["selected_nodes"]):
                break
            if not futures:
                break
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in sorted(done, key=lambda item: futures[item][0]):
                _, node, path = futures.pop(future)
                busy_files.remove(path)
                accept_job(node, future.result())
                accepted.add(node)
    return accepted


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

        graph = state.get("graph")
        if graph is not None:
            _validate_scheduling_graph(state)
            node = candidate.get("node")
            if node not in graph["selected_nodes"]:
                _record_preparation_defect(
                    state,
                    "undeclared_node",
                    node=node,
                    request_id=candidate.get("request_id"),
                )
                return reject("preparation_defect_undeclared_node")
            if candidate.get("assigned_path") != graph["source_paths"][node]:
                _record_preparation_defect(
                    state,
                    "source_path_mismatch",
                    node=node,
                    assigned_path=candidate.get("assigned_path"),
                )
                return reject("preparation_defect_source_path_mismatch")

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
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Draft consumer-first contracts, then run the bounded freeze gate."""
    run = state["run"]
    previous = state.get("contracts")
    if isinstance(previous, dict) and previous.get("frozen_fingerprints"):
        return previous
    policy_sha256 = run["native_decide_policy_sha256"]
    if graph is None:
        graph = {
            "frozen_targets": ["probe:Diamond.top"],
            "selected_nodes": [
                "probe:Diamond.left",
                "probe:Diamond.right",
                "probe:Diamond.top",
            ],
            "term_dependencies": [
                ["probe:Diamond.top", "probe:Diamond.left"],
                ["probe:Diamond.top", "probe:Diamond.right"],
            ],
        }
    targets = set(graph["frozen_targets"])
    if len(targets) != 1:
        raise ContractError("the bounded contract pass requires one selected root")
    contract_candidates = [
        node for node in graph["selected_nodes"] if node not in targets
    ]
    leaf_counts: dict[str, int] = {}
    for node in contract_candidates:
        leaf = re.sub(r"[^a-z0-9]+", "-", node.rsplit(".", 1)[-1].lower()).strip("-")
        if not leaf:
            raise ContractError("contract node cannot form a safe request identity")
        leaf_counts[leaf] = leaf_counts.get(leaf, 0) + 1
    contract_stems = {}
    for node in contract_candidates:
        leaf = re.sub(r"[^a-z0-9]+", "-", node.rsplit(".", 1)[-1].lower()).strip("-")
        contract_stems[node] = (
            leaf
            if leaf_counts[leaf] == 1
            else f"{leaf}-{hashlib.sha256(node.encode()).hexdigest()[:12]}"
        )
    if len(set(contract_stems.values())) != len(contract_stems):
        raise ContractError("contract request identities collided")
    contracts = {
        "attempts": [],
        "provisional": {},
        "frozen": {},
        "frozen_fingerprints": [],
        "invalidated_fingerprints": [],
        "feasibility": [],
        "immediate_consumer_requirements": {},
        "node_fingerprints": {next(iter(targets)): top_fingerprint},
        "revision_lineage": [],
        "max_revisions": min(
            2, max(0, int(state.get("config", {}).get("max_contract_revisions", 1)))
        ),
        "proof_barrier": "drafting",
    }
    state["contracts"] = contracts
    completed = set(targets)
    contract_nodes = []
    while len(completed) < len(graph["selected_nodes"]):
        frontier = _contract_frontier(graph, completed)
        if not frontier:
            raise ContractError("contract graph has no consumer-first frontier")
        for node in frontier:
            requirements = [
                {
                    "consumer": consumer,
                    "fingerprint": contracts["node_fingerprints"][consumer],
                }
                for consumer in _immediate_consumers(graph, node)
            ]
            response, _ = _model_request(
                state,
                request_id=f"contract-{contract_stems[node]}-001",
                role="contract-author",
                input_hashes=[
                    dependency["payload_sha256"],
                    *(item["fingerprint"] for item in requirements),
                ],
            )
            record = _statement_record(response, policy_sha256)
            expected = f"{node.removeprefix('probe:')}_spec"
            if record["declaration"] != expected:
                raise ContractError("contract response declaration mismatch")
            contracts["attempts"].append(record)
            contracts["provisional"][record["declaration"]] = record
            contracts["immediate_consumer_requirements"][node] = requirements
            contracts["node_fingerprints"][node] = record["model_fingerprint"]
            contract_nodes.append(node)
            _event_once(run, f"contract_draft:{record['declaration']}")
        completed.update(frontier)
    _event_once(run, "provisional_contracts_applied")

    def check_feasibility(label: str) -> dict[str, Any]:
        result = _external_call(
            state,
            label,
            lambda: worker.check_contract_feasibility(
                run,
                [
                    contracts["provisional"][f"{node.removeprefix('probe:')}_spec"][
                        "canon"
                    ]
                    for node in contract_nodes
                ],
            ),
        )
        contracts["feasibility"].append(result)
        _event_once(run, f"provisional_consumer:{result['status']}")
        return result

    feasibility = check_feasibility("build:provisional-consumer-weak")
    revision_counts = {node: 0 for node in contract_nodes}
    while feasibility["status"] != "passed":
        failed_declaration = feasibility.get("declaration")
        matching_nodes = [
            node
            for node in contract_nodes
            if f"{node.removeprefix('probe:')}_spec" == failed_declaration
        ]
        if failed_declaration is not None and not matching_nodes:
            raise ContractError("contract diagnostic references an undeclared helper")
        failed_node = matching_nodes[0] if matching_nodes else contract_nodes[0]
        if revision_counts[failed_node] >= contracts["max_revisions"]:
            break
        revision_counts[failed_node] += 1
        revision = revision_counts[failed_node]
        declaration = f"{failed_node.removeprefix('probe:')}_spec"
        previous_record = contracts["provisional"][declaration]
        requirements = contracts["immediate_consumer_requirements"][failed_node]
        response, _ = _model_request(
            state,
            request_id=(
                f"contract-{contract_stems[failed_node]}-review-"
                f"{revision + 1:03d}"
            ),
            role="contract-reviewer",
            input_hashes=[
                previous_record["model_fingerprint"],
                *(item["fingerprint"] for item in requirements),
            ],
        )
        record = _statement_record(response, policy_sha256)
        if (
            record["declaration"] != declaration
            or record["model_fingerprint"] == previous_record["model_fingerprint"]
        ):
            raise ContractError("contract review did not replace the weak statement")
        contracts["attempts"].append(record)
        contracts["provisional"][declaration] = record
        _revise_contract_fingerprint(
            state,
            failed_node,
            record["model_fingerprint"],
            graph=graph,
        )
        _event_once(run, f"contract_review:{record['declaration']}")
        _event_once(
            run,
            f"statement_invalidated:{previous_record['model_fingerprint']}",
        )
        feasibility = check_feasibility("build:provisional-consumer-strong")
    if feasibility["status"] != "passed":
        contracts["proof_barrier"] = "inconclusive"
        _event_once(run, "contract_inconclusive")
        raise ContractInconclusive(feasibility["diagnostic"])

    contracts["frozen"] = {
        declaration: {**record, "status": "frozen"}
        for declaration, record in contracts["provisional"].items()
    }
    contracts["provisional"] = {}
    contracts["frozen_fingerprints"] = sorted(
        contracts["node_fingerprints"].values()
    )
    contracts["proof_barrier"] = "frozen"
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
    _validate_scheduling_graph(state)
    if len(graph["frozen_targets"]) != 1:
        raise ContractError("the bounded scheduler requires one selected root")
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
    _validate_dependency_plan(state, dependency)
    contracts = _repair_contracts(state, dependency, top_fingerprint, graph)
    for node, target in state["target_states"].items():
        target.update(
            {
                "phase": "proof",
                "status": "pending",
                "immediate_consumer_requirements": contracts[
                    "immediate_consumer_requirements"
                ].get(node, []),
                "contract_fingerprint": contracts["node_fingerprints"][node],
            }
        )
    lanes = state.setdefault("lanes", [])
    existing_lane_ids = {lane["lane_id"] for lane in lanes}
    new_lanes = [
        {**lane, "status": "preparing"}
        for lane in _lane_descriptors(
            run,
            graph,
            graph["selected_nodes"],
            base_commit=run["base_commit"],
        )
        if lane["lane_id"] not in existing_lane_ids
    ]
    if new_lanes:
        lanes.extend(new_lanes)
        _external_call(
            state,
            "lanes:prepare-proofs",
            lambda: worker.prepare_lanes(
                run,
                [_worker_lane(lane) for lane in new_lanes],
            ),
        )
        for lane in new_lanes:
            lane["status"] = "running"
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
    lanes_by_node = {lane["node"]: lane for lane in lanes}
    proof_patches = state.setdefault("proof_patch_sha256", {})
    run["proof_patch_sha256"] = proof_patches
    dependencies = {node: [] for node in graph["selected_nodes"]}
    for consumer, dependency_node in graph["term_dependencies"]:
        dependencies[consumer].append(dependency_node)
    first_frontier = _proof_ready_nodes(graph, set())
    stored = {
        **state.setdefault("model_exchanges", {}),
        **state.setdefault("pending_model_exchanges", {}),
    }
    used_sequences = [
        exchange["request"]["sequence"]
        for exchange in stored.values()
        if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict)
    ] + [receipt["sequence"] for receipt in state["receipts"]]
    next_sequence = max(used_sequences, default=0) + 1

    def prepare_job(node: str) -> dict[str, Any]:
        nonlocal next_sequence
        lane = lanes_by_node[node]
        previous = stored.get(lane["request_id"])
        if previous is None:
            _check_budget(state)
            state["target_states"][node]["attempt_count"] += 1
        target = state["target_states"][node]
        target["phase"] = "proof"
        target["status"] = "running"
        state["file_owners"][lane["assigned_path"]] = node
        sequence = (
            previous["request"]["sequence"] if previous is not None else next_sequence
        )
        if previous is None:
            next_sequence += 1
        required = sorted(dependencies[node])
        input_hashes = [contracts["node_fingerprints"][node]]
        input_hashes.extend(
            contracts["node_fingerprints"][dependency_node]
            for dependency_node in required
        )
        input_hashes.extend(proof_patches[dependency_node] for dependency_node in required)
        if not required:
            input_hashes.append(probe_hash)
        request = _model_envelope(
            state,
            request_id=lane["request_id"],
            role="proof-author",
            batch_id=(
                "proof-leaves-001"
                if len(first_frontier) > 1 and node in first_frontier
                else None
            ),
            input_hashes=input_hashes,
            sequence=sequence,
        )
        if previous is not None and previous.get("request") != request:
            raise ContractError(f"resumed model request changed: {lane['request_id']}")
        return {"lane": lane, "previous": previous, "request": request}

    def run_job(job: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic_ns()
        previous = job["previous"]
        if previous is None:
            response, receipt = _invoke_model(state, job["request"], checkpoint=False)
        else:
            response, receipt = previous["response"], previous["receipt"]
        return {
            **job,
            "response": response,
            "receipt": receipt,
            "started_monotonic_ns": started,
            "finished_monotonic_ns": time.monotonic_ns(),
        }

    def accept_job(node: str, job: dict[str, Any]) -> None:
        lane = job["lane"]
        if lane["request_id"] not in state["model_exchanges"]:
            response, _ = _accept_model_exchange(
                state,
                job["request"],
                job["response"],
                job["receipt"],
                allow_out_of_order=True,
            )
        else:
            response = job["response"]
        state["lane_intervals"][lane["request_id"]] = {
            "started_monotonic_ns": job["started_monotonic_ns"],
            "finished_monotonic_ns": job["finished_monotonic_ns"],
        }
        candidate = _candidate_record(
            response, lane, run["native_decide_policy_sha256"]
        )
        if candidate["candidate_sha256"] not in state["processed_candidate_sha256"]:
            _external_call(
                state,
                f"lane:{lane['lane_id']}:persist",
                lambda: worker.persist_lane_result(
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
            and node in state["accepted_nodes"]
        ):
            lane["status"] = "accepted"
            lane["requeueable"] = False
            proof_patches[node] = response["payload"]["patch_sha256"]
            target = state["target_states"][node]
            target["status"] = "accepted"
            target["accepted_commit"] = transition["accepted_commit"]
            if state["file_owners"].get(lane["assigned_path"]) == node:
                state["file_owners"].pop(lane["assigned_path"])
            release = {
                "sequence": len(state["release_events"]) + 1,
                "node": node,
                "accepted_commit": transition["accepted_commit"],
            }
            state["release_events"].append(release)
            return
        if state["file_owners"].get(lane["assigned_path"]) == node:
            state["file_owners"].pop(lane["assigned_path"])
        _block_dependents(state, node, transition["reason"])
        raise ContractError(
            f"proof candidate {lane['request_id']} was {transition['status']}: "
            f"{transition['reason']}"
        )

    scheduled = _external_call(
        state,
        "proofs:schedule",
        lambda: _schedule_proofs(
            graph,
            run_job,
            accept_job,
            prepare_job=prepare_job,
            accepted_nodes=state["accepted_nodes"],
        ),
    )
    if scheduled != set(graph["selected_nodes"]):
        raise ContractError("proof scheduler stopped before the selected graph completed")
    if state["cost"] > state["config"]["max_cost_usd"]:
        raise BudgetExhausted(
            "cost_usd", state["config"]["max_cost_usd"], state["cost"]
        )
    initial_intervals = [
        state["lane_intervals"][lanes_by_node[node]["request_id"]]
        for node in first_frontier
        if lanes_by_node[node]["request_id"] in state["lane_intervals"]
    ]
    if len(initial_intervals) > 1:
        if max(item["started_monotonic_ns"] for item in initial_intervals) >= min(
            item["finished_monotonic_ns"] for item in initial_intervals
        ):
            raise ContractError("ready proof lanes did not overlap")
        _event_once(run, "proof_lanes:overlapped")
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
        "proof_patch_sha256": proof_patches,
    })
