"""Concrete generic role-lane orchestration behind the diamond controller seam."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any

from . import agent_lane, worker
from .contracts import ContractError, ContractInconclusive
from .diamond import (
    _candidate_record,
    _checkpoint_candidate,
    _lane_descriptors,
    _statement_fingerprint,
    _worker_lane,
)
from .graph_scheduler import (
    _contract_frontier,
    _immediate_consumers,
    _proof_ready_nodes,
    _revise_contract_fingerprint,
)
from .run_state import (
    _RunState,
    _canonical_sha256,
    _event_once,
    _external_call,
    _node_update,
)


def _role_job(
    state: _RunState,
    graph: dict[str, Any],
    lane: dict[str, Any],
    role: str,
    *,
    statement_sha256: str,
    contract_fingerprint: str,
    input_hashes: list[str],
) -> dict[str, Any]:
    current = state.get("accepted") or {"accepted_commit": state["run"]["base_commit"]}
    return {
        "schema": "autofv-role-job/v1",
        "run_id": state["run"]["run_id"],
        "declaration": lane["node"],
        "role": role,
        "assigned_path": lane["assigned_path"],
        "allowed_read_paths": sorted(set(graph["source_paths"].values())),
        "graph_sha256": graph["graph_sha256"],
        "statement_sha256": statement_sha256,
        "contract_fingerprint": contract_fingerprint,
        "input_hashes": sorted(set(input_hashes)),
        "accepted_commit": current["accepted_commit"],
    }


def _run_role_lane(
    state: _RunState,
    graph: dict[str, Any],
    lane: dict[str, Any],
    role: str,
    *,
    statement_sha256: str,
    contract_fingerprint: str,
    input_hashes: list[str],
) -> dict[str, Any]:
    """Run one receipted role with exactly the candidate-only lane tools."""
    job = _role_job(
        state,
        graph,
        lane,
        role,
        statement_sha256=statement_sha256,
        contract_fingerprint=contract_fingerprint,
        input_hashes=input_hashes,
    )
    lane_root = Path(lane["worktree_path"])

    def read_file(relative: str) -> str:
        return (lane_root / relative).read_text(encoding="utf-8")

    def search_files(query: str) -> str:
        matches = []
        for relative in job["allowed_read_paths"]:
            for number, line in enumerate(
                (lane_root / relative).read_text(encoding="utf-8").splitlines(), 1
            ):
                if query in line:
                    matches.append(f"{relative}:{number}:{line}")
        return "\n".join(matches)

    tools = agent_lane.build_lane_tools(
        job,
        lane_root=lane_root,
        read_file=read_file,
        search_files=search_files,
        edit_assigned=lambda patch: hashlib.sha256(patch.encode()).hexdigest(),
        check_lean=lambda: "candidate diagnostic requested; controller gate is authoritative",
    )
    return asyncio.run(agent_lane.run_role_conversation(state, job, tools))


def _lane_candidate_response(
    candidate: dict[str, Any],
    lane: dict[str, Any],
    statement_fingerprints: list[str],
) -> dict[str, Any]:
    """Adapt an authenticated lane candidate to the existing acceptance record."""
    patch = candidate["patch"]
    payload = {
        "schema": "autofv-candidate-patch/v1",
        "assigned_path": lane["assigned_path"],
        "base_commit": lane["base_commit"],
        "format": "unified_diff",
        "patch": patch,
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        "statement_fingerprints": statement_fingerprints,
    }
    response = {
        "schema": "autofv-controller-candidate-adapter/v1",
        "request_id": lane["request_id"],
        "role": candidate["role"],
        "lane_candidate_sha256": _canonical_sha256(candidate),
        "kind": "patch",
        "assigned_path": lane["assigned_path"],
        "base_commit": lane["base_commit"],
        "statement_fingerprints": statement_fingerprints,
        "payload": payload,
    }
    return response


def _contract_text(candidate: dict[str, Any], declaration: str) -> str:
    evidence = candidate.get("evidence")
    if (
        candidate.get("claimed_status") != "candidate"
        or not isinstance(evidence, list)
        or len(evidence) != 1
        or not evidence[0].startswith("statement:theorem ")
    ):
        raise ContractError("specifier candidate has no canonical theorem statement")
    statement = evidence[0].removeprefix("statement:")
    if not statement.startswith(f"theorem {declaration} "):
        raise ContractError("specifier candidate declaration mismatch")
    return statement


def _contract_record(
    candidate: dict[str, Any],
    declaration: str,
    policy_sha256: str,
    consumer_fingerprints: list[str],
) -> dict[str, Any]:
    text = _contract_text(candidate, declaration)
    return {
        "declaration": declaration,
        "kind": "theorem",
        "canon": text,
        "canonical_sha256": _canonical_sha256({"kind": "theorem", "canon": text}),
        "model_fingerprint": _canonical_sha256(candidate),
        "consumer_fingerprints": consumer_fingerprints,
        "native_decide_policy_sha256": policy_sha256,
        "status": "provisional",
    }


def run_generic_role_path(state: _RunState) -> dict[str, Any]:
    """Execute the generic role sequence while retaining one acceptance writer."""
    graph, run, manifest = state["graph"], state["run"], state["manifest"]
    if len(graph["frozen_targets"]) != 1:
        raise ContractError("the bounded scheduler requires one selected root")
    root = graph["frozen_targets"][0]
    top_fingerprint = _external_call(
        state,
        "source:read-top-statement",
        lambda: _statement_fingerprint(run, graph),
    )
    lanes = _lane_descriptors(
        run, graph, graph["selected_nodes"], base_commit=run["base_commit"]
    )
    _external_call(
        state,
        "lanes:prepare-role-lanes",
        lambda: worker.prepare_lanes(run, [_worker_lane(lane) for lane in lanes]),
    )
    for lane in lanes:
        lane["status"] = "running"
    lanes_by_node = {lane["node"]: lane for lane in lanes}
    run["lanes"] = state["lanes"] = lanes

    scout = _run_role_lane(
        state,
        graph,
        lanes_by_node[root],
        "scout",
        statement_sha256=top_fingerprint,
        contract_fingerprint=top_fingerprint,
        input_hashes=[graph["graph_sha256"]],
    )
    dependency = _run_role_lane(
        state,
        graph,
        lanes_by_node[root],
        "dependency_planner",
        statement_sha256=top_fingerprint,
        contract_fingerprint=top_fingerprint,
        input_hashes=[graph["graph_sha256"], _canonical_sha256(scout)],
    )

    policy_sha256 = run["native_decide_policy_sha256"]
    contracts = {
        "attempts": [],
        "provisional": {},
        "frozen": {},
        "frozen_fingerprints": [],
        "invalidated_fingerprints": [],
        "feasibility": [],
        "immediate_consumer_requirements": {},
        "node_fingerprints": {root: top_fingerprint},
        "revision_lineage": [],
        "max_revisions": 1,
        "proof_barrier": "drafting",
    }
    state["contracts"] = contracts
    contract_nodes: list[str] = []
    completed_contracts = {root}
    while len(completed_contracts) < len(graph["selected_nodes"]):
        frontier = _contract_frontier(graph, completed_contracts)
        if not frontier:
            raise ContractError("contract graph has no consumer-first frontier")
        contract_nodes.extend(frontier)
        completed_contracts.update(frontier)
    for node in contract_nodes:
        consumers = _immediate_consumers(graph, node)
        consumer_fingerprints = [
            contracts["node_fingerprints"][consumer] for consumer in consumers
        ]
        candidate = _run_role_lane(
            state,
            graph,
            lanes_by_node[node],
            "specifier",
            statement_sha256=top_fingerprint,
            contract_fingerprint=top_fingerprint,
            input_hashes=[_canonical_sha256(dependency), *consumer_fingerprints],
        )
        declaration = f"{node.removeprefix('probe:')}_spec"
        record = _contract_record(
            candidate, declaration, policy_sha256, consumer_fingerprints
        )
        contracts["attempts"].append(record)
        contracts["provisional"][declaration] = record
        contracts["node_fingerprints"][node] = record["model_fingerprint"]
        contracts["immediate_consumer_requirements"][node] = [
            {"consumer": consumer, "fingerprint": contracts["node_fingerprints"][consumer]}
            for consumer in consumers
        ]

    def feasibility(label: str) -> dict[str, Any]:
        outcome = _external_call(
            state,
            label,
            lambda: worker.check_contract_feasibility(
                run,
                [
                    contracts["provisional"][
                        f"{node.removeprefix('probe:')}_spec"
                    ]["canon"]
                    for node in contract_nodes
                ],
            ),
        )
        contracts["feasibility"].append(outcome)
        return outcome

    outcome = feasibility("build:generic-provisional-consumer")
    if outcome["status"] != "passed" and contract_nodes:
        node = contract_nodes[0]
        declaration = f"{node.removeprefix('probe:')}_spec"
        prior = contracts["provisional"][declaration]
        reviewed = _run_role_lane(
            state,
            graph,
            lanes_by_node[node],
            "spec_reviewer",
            statement_sha256=top_fingerprint,
            contract_fingerprint=prior["model_fingerprint"],
            input_hashes=[prior["model_fingerprint"]],
        )
        record = _contract_record(
            reviewed,
            declaration,
            policy_sha256,
            prior["consumer_fingerprints"],
        )
        contracts["attempts"].append(record)
        contracts["provisional"][declaration] = record
        _revise_contract_fingerprint(
            state,
            node,
            record["model_fingerprint"],
            graph=graph,
        )
        outcome = feasibility("build:generic-reviewed-consumer")
    if outcome["status"] != "passed":
        raise ContractInconclusive(outcome["diagnostic"])

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

    for node, target in state["target_states"].items():
        target.update(
            {
                "phase": "proof",
                "status": "pending",
                "contract_fingerprint": contracts["node_fingerprints"][node],
            }
        )
    for key in (
        "candidate_receipts",
        "processed_candidate_sha256",
        "accepted_sequence",
        "accepted_nodes",
    ):
        value = state.setdefault(key, [])
        run[key] = value
    state.setdefault("lane_intervals", {})
    state.setdefault("proof_patch_sha256", {})

    accepted_nodes: set[str] = set(state["accepted_nodes"])
    while len(accepted_nodes) < len(graph["selected_nodes"]):
        ready = _proof_ready_nodes(graph, accepted_nodes)
        if not ready:
            raise ContractError("proof scheduler stopped before the selected graph completed")
        for node in ready:
            lane = lanes_by_node[node]
            dependencies = sorted(
                dependency_node
                for consumer, dependency_node in graph["term_dependencies"]
                if consumer == node
            )
            fingerprints = sorted(
                {
                    contracts["node_fingerprints"][node],
                    *(contracts["node_fingerprints"][item] for item in dependencies),
                }
            )
            proposed = _run_role_lane(
                state,
                graph,
                lane,
                "prover",
                statement_sha256=top_fingerprint,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[
                    *fingerprints,
                    *(state["proof_patch_sha256"][item] for item in dependencies),
                    graph["graph_sha256"],
                ],
            )
            reviewed = _run_role_lane(
                state,
                graph,
                lane,
                "proof_reviewer",
                statement_sha256=top_fingerprint,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[*fingerprints, _canonical_sha256(proposed)],
            )
            response = _lane_candidate_response(reviewed, lane, fingerprints)
            candidate = _candidate_record(response, lane, policy_sha256)
            _external_call(
                state,
                f"lane:{lane['lane_id']}:persist",
                lambda: worker.persist_lane_result(
                    run,
                    lane,
                    {key: value for key, value in candidate.items() if key != "response"},
                ),
            )
            transition = _checkpoint_candidate(state, candidate, manifest)
            if not transition["status"].startswith("accepted"):
                raise ContractError(f"candidate rejected: {transition['reason']}")
            lane["status"] = "accepted"
            state["proof_patch_sha256"][node] = response["payload"]["patch_sha256"]
            accepted_nodes.add(node)
            target = state["target_states"][node]
            target["status"] = "accepted"
            target["accepted_commit"] = transition["accepted_commit"]
            state["release_events"].append(
                {
                    "sequence": len(state["release_events"]) + 1,
                    "node": node,
                    "accepted_commit": transition["accepted_commit"],
                }
            )

    _run_role_lane(
        state,
        graph,
        lanes_by_node[root],
        "verification_adviser",
        statement_sha256=top_fingerprint,
        contract_fingerprint=contracts["node_fingerprints"][root],
        input_hashes=[
            contracts["node_fingerprints"][root],
            hashlib.sha256(state["accepted"]["accepted_commit"].encode()).hexdigest(),
        ],
    )
    return _node_update(
        state,
        accepted=state["accepted"],
        contracts=contracts,
        receipts=state["receipts"],
        cost=state["cost"],
        lanes=lanes,
        lane_intervals=state["lane_intervals"],
        candidate_receipts=state["candidate_receipts"],
        processed_candidate_sha256=state["processed_candidate_sha256"],
        accepted_sequence=state["accepted_sequence"],
        accepted_nodes=state["accepted_nodes"],
        proof_patch_sha256=state["proof_patch_sha256"],
    )
