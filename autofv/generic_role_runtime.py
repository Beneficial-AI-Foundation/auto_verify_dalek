"""Concrete generic role-lane orchestration behind the diamond controller seam."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from . import agent_lane, worker
from .contracts import ContractError, ContractInconclusive
from .diamond import (
    _candidate_record,
    _checkpoint_candidate,
    _lane_descriptors,
    _supplied_statement,
    _worker_lane,
)
from .graph_scheduler import (
    _block_dependents,
    _contract_frontier,
    _immediate_consumers,
    _revise_contract_fingerprint,
    _schedule_proofs,
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
    role_context: dict[str, Any],
) -> dict[str, Any]:
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
        # The role identity is tied to its immutable lane snapshot. Canonical-tree
        # acceptance may advance while this job is running and must not fork replay.
        "accepted_commit": lane["base_commit"],
        "role_context": role_context,
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
    role_context: dict[str, Any],
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
        role_context=role_context,
    )
    tools = agent_lane.build_lane_tools(
        job,
        read_file=lambda relative: worker.read_lane_file(
            state["run"], lane, relative, job["allowed_read_paths"]
        ),
        search_files=lambda query: worker.search_lane_files(
            state["run"], lane, query, job["allowed_read_paths"]
        ),
        edit_assigned=lambda patch: worker.edit_lane_file(state["run"], lane, patch),
        check_lean=lambda: worker.check_lane(
            state["run"], lane, state["manifest"]
        ),
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
        # The terminal verifier independently requires SHA256(canon).
        "model_fingerprint": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "candidate_sha256": _canonical_sha256(candidate),
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
    supplied_statement = _external_call(
        state,
        "source:read-top-statement",
        lambda: _supplied_statement(run, graph),
    )
    top_fingerprint = supplied_statement["model_fingerprint"]
    supplied_spec = graph["supplied_specs"][root]
    supplied_source = supplied_statement["canon"]
    expected_lanes = _lane_descriptors(
        run, graph, graph["selected_nodes"], base_commit=run["base_commit"]
    )
    previous_lanes = state.get("lanes")
    if isinstance(previous_lanes, list) and previous_lanes:
        expected_by_node = {lane["node"]: lane for lane in expected_lanes}
        if {lane.get("node") for lane in previous_lanes} != set(expected_by_node):
            raise ContractError("resumed role lanes changed")
        for lane in previous_lanes:
            expected = expected_by_node[lane["node"]]
            if any(lane.get(key) != expected[key] for key in expected):
                raise ContractError("resumed role lane identity changed")
        lanes = previous_lanes
        _event_once(run, "proof_lanes:reused")
    else:
        lanes = expected_lanes
        _external_call(
            state,
            "lanes:prepare-role-lanes",
            lambda: worker.prepare_lanes(run, [_worker_lane(lane) for lane in lanes]),
        )
    for lane in lanes:
        if lane.get("status") != "accepted":
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
        role_context={
            "target": root,
            "supplied_spec": supplied_spec,
            "supplied_source": supplied_source,
            "selected_nodes": graph["selected_nodes"],
            "term_dependencies": graph["term_dependencies"],
        },
    )
    dependency = _run_role_lane(
        state,
        graph,
        lanes_by_node[root],
        "dependency_planner",
        statement_sha256=top_fingerprint,
        contract_fingerprint=top_fingerprint,
        input_hashes=[graph["graph_sha256"], _canonical_sha256(scout)],
        role_context={
            "target": root,
            "scout_candidate": scout,
            "selected_nodes": graph["selected_nodes"],
            "term_dependencies": graph["term_dependencies"],
        },
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
            role_context={
                "node": node,
                "dependency_plan": dependency,
                "immediate_consumer_contracts": [
                    contracts["frozen"].get(
                        f"{consumer.removeprefix('probe:')}_spec",
                        contracts["provisional"].get(
                            f"{consumer.removeprefix('probe:')}_spec"
                        ),
                    )
                    for consumer in consumers
                    if consumer != root
                ]
                + ([{"declaration": supplied_spec, "canon": supplied_source}] if root in consumers else []),
            },
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
        reviewed = _run_role_lane(
            state,
            graph,
            lanes_by_node[node],
            "spec_reviewer",
            statement_sha256=top_fingerprint,
            contract_fingerprint=record["model_fingerprint"],
            input_hashes=[record["model_fingerprint"], *consumer_fingerprints],
            role_context={
                "node": node,
                "provisional_contract": record,
                "diagnostic": {"status": "review_required_before_freeze"},
                "immediate_consumers": contracts[
                    "immediate_consumer_requirements"
                ][node],
            },
        )
        reviewed_record = _contract_record(
            reviewed, declaration, policy_sha256, consumer_fingerprints
        )
        contracts["attempts"].append(reviewed_record)
        contracts["provisional"][declaration] = reviewed_record
        contracts["node_fingerprints"][node] = reviewed_record["model_fingerprint"]

    def feasibility(label: str) -> dict[str, Any]:
        records_by_node = {
            root: {
                **supplied_statement,
                "status": "supplied",
            },
            **{
                node: contracts["provisional"][
                    f"{node.removeprefix('probe:')}_spec"
                ]
                for node in contract_nodes
            },
        }
        outcome = _external_call(
            state,
            label,
            lambda: worker.check_contract_feasibility(
                run,
                worker.contract_feasibility_request(graph, records_by_node),
            ),
        )
        contracts["feasibility"].append(outcome)
        return outcome

    outcome = feasibility("build:generic-provisional-consumer")
    if outcome["status"] != "passed" and contract_nodes:
        failed_declaration = outcome.get("declaration")
        targets = [
            node
            for node in contract_nodes
            if failed_declaration is None
            or f"{node.removeprefix('probe:')}_spec" == failed_declaration
        ]
        if failed_declaration is not None and not targets:
            raise ContractError("contract diagnostic references an undeclared helper")
        for node in targets:
            declaration = f"{node.removeprefix('probe:')}_spec"
            prior = contracts["provisional"][declaration]
            reviewed = _run_role_lane(
                state,
                graph,
                lanes_by_node[node],
                "spec_reviewer",
                statement_sha256=top_fingerprint,
                contract_fingerprint=prior["model_fingerprint"],
                input_hashes=[prior["model_fingerprint"], outcome["diagnostic_sha256"]],
                role_context={
                    "node": node,
                    "provisional_contract": prior,
                    "diagnostic": outcome,
                    "immediate_consumers": contracts[
                        "immediate_consumer_requirements"
                    ][node],
                },
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

    def prepare_proof(node: str) -> dict[str, Any]:
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
        return {
            "node": node,
            "lane": lanes_by_node[node],
            "dependencies": dependencies,
            "fingerprints": fingerprints,
        }

    def run_proof(job: dict[str, Any]) -> dict[str, Any]:
        node, lane = job["node"], job["lane"]
        proposed = _run_role_lane(
            state,
            graph,
            lane,
            "prover",
            statement_sha256=top_fingerprint,
            contract_fingerprint=contracts["node_fingerprints"][node],
            input_hashes=[
                *job["fingerprints"],
                *(state["proof_patch_sha256"][item] for item in job["dependencies"]),
                graph["graph_sha256"],
            ],
            role_context={
                "node": node,
                "contract": contracts["frozen"].get(
                    f"{node.removeprefix('probe:')}_spec",
                    {"declaration": supplied_spec, "canon": supplied_source},
                ),
                "dependency_contracts": [
                    contracts["frozen"].get(
                        f"{item.removeprefix('probe:')}_spec"
                    )
                    for item in job["dependencies"]
                ],
            },
        )
        reviewed = _run_role_lane(
            state,
            graph,
            lane,
            "proof_reviewer",
            statement_sha256=top_fingerprint,
            contract_fingerprint=contracts["node_fingerprints"][node],
            input_hashes=[*job["fingerprints"], _canonical_sha256(proposed)],
            role_context={
                "node": node,
                "proposed_candidate": proposed,
                "contract_fingerprints": job["fingerprints"],
            },
        )
        if reviewed["claimed_status"] != "candidate":
            reviewed = _run_role_lane(
                state,
                graph,
                lane,
                "repair",
                statement_sha256=top_fingerprint,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[*job["fingerprints"], _canonical_sha256(reviewed)],
                role_context={
                    "node": node,
                    "proposed_candidate": proposed,
                    "review_rejection": reviewed,
                },
            )
        return {**job, "proposed": proposed, "reviewed": reviewed}

    def persist_and_accept(job: dict[str, Any], selected: dict[str, Any]) -> dict[str, Any]:
        response = _lane_candidate_response(
            selected, job["lane"], job["fingerprints"]
        )
        candidate = _candidate_record(response, job["lane"], policy_sha256)
        _external_call(
            state,
            f"lane:{job['lane']['lane_id']}:persist:{selected['role']}",
            lambda: worker.persist_lane_result(
                run,
                job["lane"],
                {key: value for key, value in candidate.items() if key != "response"},
            ),
        )
        return _checkpoint_candidate(state, candidate, manifest)

    def accept_proof(node: str, job: dict[str, Any]) -> bool:
        selected = job["reviewed"]
        if selected["claimed_status"] != "candidate":
            job["lane"]["status"] = "blocked"
            _block_dependents(
                state,
                node,
                "proof_repair_exhausted:" + selected["claimed_status"],
            )
            return False
        transition = persist_and_accept(job, selected)
        if not transition["status"].startswith("accepted"):
            repaired = _run_role_lane(
                state,
                graph,
                job["lane"],
                "repair",
                statement_sha256=top_fingerprint,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[
                    *job["fingerprints"],
                    _canonical_sha256(selected),
                    _canonical_sha256(transition),
                ],
                role_context={
                    "node": node,
                    "rejected_candidate": selected,
                    "controller_rejection": transition,
                },
            )
            selected = repaired
            if repaired["claimed_status"] == "candidate":
                transition = persist_and_accept(job, repaired)
            else:
                transition = {
                    "status": "rejected",
                    "reason": "repair_" + repaired["claimed_status"],
                }
        if not transition["status"].startswith("accepted"):
            job["lane"]["status"] = "blocked"
            _block_dependents(
                state,
                node,
                "proof_repair_exhausted:" + str(transition.get("reason")),
            )
            return False
        job["lane"]["status"] = "accepted"
        state["proof_patch_sha256"][node] = hashlib.sha256(
            selected["patch"].encode()
        ).hexdigest()
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
        return True

    accepted_nodes = _schedule_proofs(
        graph,
        run_proof,
        accept_proof,
        prepare_job=prepare_proof,
        accepted_nodes=state["accepted_nodes"],
    )
    state["accepted_nodes"][:] = sorted(accepted_nodes)

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
        role_context={
            "target": root,
            "frozen_contracts": contracts["frozen"],
            "accepted": state["accepted"],
            "accepted_nodes": state["accepted_nodes"],
        },
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
