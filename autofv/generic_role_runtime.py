"""Concrete generic role-lane orchestration behind the diamond controller seam."""

from __future__ import annotations

import asyncio
import hashlib
from copy import deepcopy
from typing import Any

from . import agent_lane, fvs_packet, fvs_profile, role_journal, terminal_run, worker
from .contracts import ContractError, ContractInconclusive
from .diamond import (
    _candidate_record,
    _checkpoint_candidate,
    _lane_descriptors,
    _supplied_statement,
    _worker_lane,
)
from .graph_scheduler import (
    MAX_PARALLEL_LANES,
    _block_dependents,
    _contract_frontier,
    _immediate_consumers,
    _revise_contract_fingerprint,
    _schedule_progressive,
    _schedule_proofs,
)
from .run_state import (
    _RunState,
    _canonical_sha256,
    _charge_wall,
    _event_once,
    _external_call,
    _node_update,
    _state_lock,
    _checkpoint_if_enabled,
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
    fvs = fvs_profile.enabled(state.get("config", {}))
    if fvs and "source_packet" not in role_context:
        generation = state.get("fvs_lane_generations", {}).get(lane["node"])
        packet = generation["packet"] if "generation_sha256" in lane else state["config"]["source_packet"]
        role_context = {**role_context, "source_packet": packet}
    return {
        "schema": "autofv-role-job/v2" if fvs else "autofv-role-job/v1",
        **({"methodology": agent_lane._FVS_METHODOLOGY} if fvs else {}),
        "run_id": state["run"]["run_id"],
        "declaration": lane["node"],
        "role": role,
        "assigned_path": lane["assigned_path"],
        "allowed_read_paths": sorted({s["path"] for s in state["config"]["source_packet"]["sources"]})
        if fvs else sorted(set(graph["source_paths"].values())),
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
    def durable_mutation(invoke):
        result = invoke()
        # Snapshot is durable before the journal declares a non-idempotent tool
        # completed. A crash between those writes stays ambiguous/fail-closed.
        receipt = worker.save_lane_snapshot(state["run"], _worker_lane(lane))
        with _state_lock(state):
            state.setdefault("lane_snapshots", {})[lane["node"]] = receipt
        return result

    tools = agent_lane.build_lane_tools(
        job,
        read_file=lambda relative: worker.read_lane_file(
            state["run"], lane, relative, job["allowed_read_paths"]
        ),
        search_files=lambda query: worker.search_lane_files(
            state["run"], lane, query, job["allowed_read_paths"]
        ),
        edit_assigned=lambda patch: durable_mutation(
            lambda: worker.edit_lane_file(state["run"], lane, patch)
        ),
        check_lean=lambda: durable_mutation(
            lambda: worker.check_lane(state["run"], lane, state["manifest"])
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
        **({"generation_sha256": lane["generation_sha256"], "generation_node": lane["node"]}
           if "generation_sha256" in lane else {}),
        "role": candidate["role"],
        "lane_candidate_sha256": _canonical_sha256(candidate),
        "kind": "patch",
        "assigned_path": lane["assigned_path"],
        "base_commit": lane["base_commit"],
        "statement_fingerprints": statement_fingerprints,
        "payload": payload,
    }
    return response


def _contract_text(candidate: dict[str, Any], declaration: str, *, supplied_statement: str | None = None) -> str:
    evidence = candidate.get("evidence")
    if (
        candidate.get("claimed_status") != "candidate"
        or not isinstance(evidence, list)
        or len(evidence) != 1
        or not evidence[0].startswith("statement:theorem ")
    ):
        raise ContractError("specifier candidate has no canonical theorem statement")
    statement = evidence[0].removeprefix("statement:")
    if supplied_statement is not None:
        if statement != supplied_statement:
            raise ContractError("specifier changed immutable supplied statement")
    elif not statement.startswith(f"theorem {declaration} "):
        raise ContractError("specifier candidate declaration mismatch")
    return statement


def _contract_record(
    candidate: dict[str, Any],
    declaration: str,
    policy_sha256: str,
    consumer_fingerprints: list[str],
    *, supplied_statement: str | None = None,
) -> dict[str, Any]:
    text = _contract_text(candidate, declaration, supplied_statement=supplied_statement)
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


def _dependency_ready_lane(state: _RunState, lane: dict[str, Any]) -> dict[str, Any]:
    """Freeze a fresh lane from the exact independently verified canonical tree.

    Planning lanes remain on the original base. No active author lane is rebased;
    interrupted generation is ambiguous and requires explicit reconciliation.
    """
    run, graph, node = state["run"], state["graph"], lane["node"]
    generations = state.setdefault("fvs_lane_generations", {})
    run["fvs_lane_generations"] = generations
    dependencies = sorted(required for consumer, required in graph["term_dependencies"] if consumer == node)
    prior = generations.get(node)
    if prior is not None and prior.get("phase") != "ready":
        raise ContractError("ambiguous dependency lane generation requires reconciliation")
    if prior is None:
        if not set(dependencies) <= set(state.get("accepted_nodes", [])):
            raise ContractError("FVS dependency is not canonically accepted")
        if not state.get("accepted_nodes"):
            return lane
        if any(key.startswith(node + ":") for key in state.get("fvs_evidence", {})):
            raise ContractError("FVS cannot change an already journaled author baseline")
        accepted = deepcopy(state["accepted"])
        accepted_nodes = sorted(state["accepted_nodes"])
        frozen = deepcopy(state["contracts"]["frozen"])
    else:
        accepted = {"accepted_commit": prior["binding"]["accepted_commit"],
                    "accepted_tree_sha256": prior["binding"]["accepted_tree_sha256"]}
        accepted_nodes = prior["binding"]["accepted_nodes"]
        frozen = prior["frozen_contracts"]
        if not set(accepted_nodes) <= set(state.get("accepted_nodes", [])):
            raise ContractError("FVS generation accepted dependency state changed")
        if any(state["contracts"]["frozen"].get(name) != value for name, value in frozen.items()):
            raise ContractError("FVS generation frozen dependency contract changed")
    commit = accepted["accepted_commit"]
    if worker.committed_source(run, "rev-parse", commit).decode().strip() != commit:
        raise ContractError("FVS generation accepted commit drift")
    archive = worker.committed_source(run, "archive", "--format=tar", commit)
    if hashlib.sha256(archive).hexdigest() != accepted["accepted_tree_sha256"]:
        raise ContractError("FVS generation accepted tree drift")
    if prior is None and (
        worker.committed_source(run, "rev-parse", "HEAD").decode().strip() != commit
        or worker.committed_source(run, "status", "--porcelain", "--untracked-files=all").strip()
    ):
        raise ContractError("FVS generation canonical acceptance drift")
    if not set(dependencies) <= set(accepted_nodes) or set(accepted_nodes) & set(graph["frozen_targets"]):
        raise ContractError("FVS generation dependency scope changed")
    state.setdefault("partial_verifier_reports", {})
    verification_state = state if prior is None else {
        **state, "accepted": accepted, "accepted_nodes": accepted_nodes,
        "contracts": {"frozen": frozen}}
    report_hashes = {}
    for helper in accepted_nodes:
        if state["target_states"][helper]["status"] != "accepted":
            raise ContractError("FVS generation contains a local-only helper")
        key = f"{helper}@{commit}"
        if prior is not None and key not in state.get("partial_verifier_reports", {}):
            raise ContractError("FVS generation dependency verifier receipt missing")
        report = terminal_run.clean_verify_partial(verification_state, helper,
            checkpoint=_checkpoint_if_enabled, charge_wall=_charge_wall)
        if report["verdict"] != "SCOPED_PASS":
            raise ContractError("FVS dependency lacks independent verification")
        report_hashes[helper] = _canonical_sha256(report)
    original = fvs_packet.validate_packet(state["config"]["source_packet"])
    sources = fvs_packet.validate_view(original)
    permitted = {graph["source_paths"][helper] for helper in accepted_nodes}
    changed = worker.committed_source(run, "diff", "--name-only", "-z", run["base_commit"], commit).decode().split("\0")
    if not set(filter(None, changed)) <= permitted or not permitted <= set(sources):
        raise ContractError("FVS accepted tree changed unowned/missing packet source")
    overlays = []
    hashes = {}
    for path, item in sorted(sources.items()):
        if item["surface"] == "rust":
            continue
        content = worker.committed_source(run, "show", f"{commit}:{path}").decode("utf-8")
        updated = fvs_packet.source(path, item["surface"], content)
        hashes[path] = updated["sha256"]
        if updated != item:
            if path not in permitted:
                raise ContractError("FVS generation source lineage drift")
            overlays.append(updated)
    body = {"schema": "autofv-fvs-lane-generation/v1", "run_id": run["run_id"],
            "node": node, "graph_sha256": graph["graph_sha256"], "original_base_commit": run["base_commit"],
            "original_packet_sha256": original["packet_sha256"], "dependencies": dependencies,
            "accepted_nodes": accepted_nodes, "accepted_commit": commit,
            "accepted_tree_sha256": accepted["accepted_tree_sha256"],
            "frozen_contracts_sha256": _canonical_sha256(frozen),
            "dependency_report_hashes": report_hashes, "source_hashes": hashes}
    binding = {**body, "generation_sha256": _canonical_sha256(body)}
    packet = fvs_packet.dependency_snapshot(original, binding, overlays)
    generated = deepcopy(lane)
    suffix = "-g-" + binding["generation_sha256"][:24]
    generated["lane_id"] = generated["request_id"] = lane["lane_id"] + suffix
    for field in ("worktree_path", "cache_path", "result_path"):
        generated[field] = lane[field].replace("/" + lane["lane_id"] + "/", "/" + generated["lane_id"] + "/")
    generated.update(schema="autofv-proof-lane/v2", base_commit=commit,
                     generation_sha256=binding["generation_sha256"])
    entry = {"phase": "preparing", "binding": binding, "packet": packet,
             "lane": _worker_lane(generated), "frozen_contracts": frozen}
    if prior is not None:
        if {k: v for k, v in prior.items() if k != "phase"} != {k: v for k, v in entry.items() if k != "phase"}:
            raise ContractError("FVS dependency generation/replay identity drift")
        receipt = state.get("lane_snapshots", {}).get(node)
        if receipt is None or receipt["lane"] != entry["lane"]:
            raise ContractError("FVS dependency generation snapshot mismatch")
        worker.restore_lane_snapshot(run, entry["lane"], expected_receipt=receipt)
        return generated
    generations[node] = entry
    _checkpoint_if_enabled(state, f"fvs-generation:{node}:before")
    worker.prepare_lanes(run, [entry["lane"]])
    receipt = worker.save_lane_snapshot(run, entry["lane"], initial=True)
    state.setdefault("lane_snapshots", {})[node] = receipt
    entry["phase"] = "ready"
    _checkpoint_if_enabled(state, f"fvs-generation:{node}:ready")
    return generated


def _run_prepared_progressive(
    state: _RunState,
    lanes_by_node: dict[str, dict[str, Any]],
    root: str,
    supplied: dict[str, Any],
    dependency: dict[str, Any],
    *,
    proof_only: bool,
) -> dict[str, Any]:
    """Bundle each ready contract and proof before releasing its consumers."""
    graph, run, manifest = state["graph"], state["run"], state["manifest"]
    top = supplied["model_fingerprint"]
    previous = state.get("contracts")
    if previous is None:
        contracts = {
            "attempts": [], "provisional": {}, "frozen": {},
            "frozen_fingerprints": [top], "invalidated_fingerprints": [],
            "feasibility": [], "immediate_consumer_requirements": {},
            "node_fingerprints": {root: top}, "revision_lineage": [],
            "max_revisions": 1, "proof_barrier": "progressive",
        }
        state["contracts"] = contracts
    elif (
        not isinstance(previous, dict)
        or previous.get("proof_barrier") != "progressive"
        or previous.get("node_fingerprints", {}).get(root) != top
    ):
        raise ContractError("progressive contract replay identity changed")
    else:
        contracts = previous
    policy = run["native_decide_policy_sha256"]
    supplied_spec = graph["supplied_specs"][root]
    for key in ("candidate_receipts", "processed_candidate_sha256", "accepted_sequence", "accepted_nodes"):
        run[key] = state.setdefault(key, [])
    state.setdefault("lane_intervals", {})
    state.setdefault("proof_patch_sha256", {})
    state.setdefault("partial_verifier_reports", {})

    def confirm_helper(node: str) -> None:
        state["target_states"][node]["status"] = "unverified"
        report = terminal_run.clean_verify_partial(
            state, node, checkpoint=_checkpoint_if_enabled, charge_wall=_charge_wall
        )
        if report["verdict"] != "SCOPED_PASS":
            raise ContractError("helper lacks independent scoped verification")
        state["target_states"][node]["status"] = "accepted"
        if fvs_profile.enabled(state["config"]):
            from .fvs_adapter import Stages
            generation = state.get("fvs_lane_generations", {}).get(node)
            helper_lane = generation["lane"] if generation is not None else lanes_by_node[node]
            stages = Stages(state, graph, helper_lane, _run_role_lane, _checkpoint_if_enabled)
            key = "distinct-helper-verifier"
            previous_report = state.get("fvs_evidence", {}).get(node + ":" + key, {}).get("report")
            if previous_report is not None and previous_report != report:
                key += ":" + report["accepted_commit"]
            stages.record(key, {"report": report, "root_status": "unverified"})

    # An interrupted local acceptance is not a verified helper. Replay its
    # clean check (or fail closed if the earlier invocation is unresolved).
    for node in sorted(state["accepted_nodes"]):
        if node != root and root not in state["accepted_nodes"]:
            confirm_helper(node)

    def run_bundle(node: str) -> dict[str, Any]:
        lane = lanes_by_node[node]
        if fvs_profile.enabled(state["config"]):
            lane = _dependency_ready_lane(state, lane)
        dependencies = sorted(
            required for consumer, required in graph["term_dependencies"] if consumer == node
        )
        fvs = fvs_profile.enabled(state["config"])
        if fvs:
            from .fvs_adapter import Stages, statement
            stages = Stages(state, graph, lane, _run_role_lane, _checkpoint_if_enabled)
            requirements = [{"consumer": consumer, "fingerprint": contracts["node_fingerprints"].get(consumer),
                             "source_path": graph["source_paths"][consumer]}
                            for consumer in _immediate_consumers(graph, node)]
            contracts["immediate_consumer_requirements"][node] = requirements
            candidate = stages.specification(top, {
                "node": node, "dependency_plan": dependency,
                "immediate_consumer_requirements": requirements,
                "accepted_dependency_contracts": [contracts["frozen"][f"{item.removeprefix('probe:')}_spec"] for item in dependencies],
            })
            if node == root and statement(candidate) != supplied["canon"]:
                raise ContractError("FVS author changed immutable supplied root statement")
            declaration = supplied_spec.removeprefix("probe:") if node == root else f"{node.removeprefix('probe:')}_spec"
            normalized = {**candidate, "evidence": ["statement:" + statement(candidate)]}
            record = _contract_record(normalized, declaration, policy, [],
                                      supplied_statement=supplied["canon"] if node == root else None)
            prior = contracts["frozen"].get(declaration)
            if prior is not None and prior != {**record, "status": "frozen"}:
                raise ContractError("FVS frozen statement replay drift")
            if prior is None:
                contracts["attempts"].append(record)
            contracts["frozen"][declaration] = {**record, "status": "frozen"}
            contracts["node_fingerprints"][node] = record["model_fingerprint"]
            contracts["frozen_fingerprints"] = sorted(set(contracts["node_fingerprints"].values()))
            state["target_states"][node].update(phase="proof", contract_fingerprint=record["model_fingerprint"])
            selected = stages.proof(candidate, record["model_fingerprint"], {
                "dependency_contracts": [contracts["frozen"][f"{item.removeprefix('probe:')}_spec"] for item in dependencies],
            })
            from .fvs_packet import review_snapshot
            expected = review_snapshot(stages.baseline, path=lane["assigned_path"], patch=selected["patch"])["overlay"]["content"]
            if worker.read_lane_file(run, lane, lane["assigned_path"], [lane["assigned_path"]]) != expected:
                raise ContractError("FVS source drift after immutable proof review")
            fingerprints = sorted({record["model_fingerprint"], *(contracts["node_fingerprints"][item] for item in dependencies)})
            return {"node": node, "lane": lane, "fingerprints": fingerprints, "reviewed": selected}
        if node != root:
            declaration = f"{node.removeprefix('probe:')}_spec"
            consumers = _immediate_consumers(graph, node)
            known = [
                contracts["node_fingerprints"][consumer]
                for consumer in consumers if consumer in contracts["node_fingerprints"]
            ]
            requirements = [
                {"consumer": consumer, "fingerprint": contracts["node_fingerprints"].get(consumer),
                 "source_path": graph["source_paths"][consumer]}
                for consumer in consumers
            ]
            contracts["immediate_consumer_requirements"][node] = requirements
            candidate = _run_role_lane(
                state, graph, lane, "specifier", statement_sha256=top,
                contract_fingerprint=top,
                input_hashes=[graph["graph_sha256"], _canonical_sha256(dependency), *known],
                role_context={
                    "node": node, "dependency_plan": dependency,
                    "immediate_consumer_requirements": requirements,
                    "supplied_target_contract": {"declaration": supplied_spec, "canon": supplied["canon"]},
                    "accepted_dependency_contracts": [
                        contracts["frozen"][f"{item.removeprefix('probe:')}_spec"]
                        for item in dependencies
                    ],
                },
            )
            provisional = _contract_record(candidate, declaration, policy, known)
            contracts["attempts"].append(provisional)
            contracts["provisional"][declaration] = provisional
            reviewed = _run_role_lane(
                state, graph, lane, "spec_reviewer", statement_sha256=top,
                contract_fingerprint=provisional["model_fingerprint"],
                input_hashes=[provisional["model_fingerprint"], *known],
                role_context={
                    "node": node, "provisional_contract": provisional,
                    "immediate_consumers": requirements,
                    "diagnostic": {"status": "review_required_before_freeze"},
                },
            )
            record = _contract_record(reviewed, declaration, policy, known)
            prior = contracts["frozen"].get(declaration)
            if prior is not None and prior["model_fingerprint"] != record["model_fingerprint"]:
                raise ContractError("reviewed progressive contract changed on restart")
            contracts["attempts"].append(record)
            contracts["provisional"].pop(declaration, None)
            contracts["frozen"][declaration] = {**record, "status": "frozen"}
            contracts["node_fingerprints"][node] = record["model_fingerprint"]
            contracts["frozen_fingerprints"] = sorted(set(contracts["node_fingerprints"].values()))
            _checkpoint_if_enabled(state, f"contracts:progressive:{node}:frozen")
        fingerprints = sorted({
            contracts["node_fingerprints"][node],
            *(contracts["node_fingerprints"][item] for item in dependencies),
        })
        state["target_states"][node].update(
            phase="proof", contract_fingerprint=contracts["node_fingerprints"][node]
        )
        proposed = _run_role_lane(
            state, graph, lane, "prover", statement_sha256=top,
            contract_fingerprint=contracts["node_fingerprints"][node],
            input_hashes=[
                *fingerprints,
                *(state["proof_patch_sha256"][item] for item in dependencies),
                graph["graph_sha256"],
            ],
            role_context={
                "node": node,
                "contract": contracts["frozen"].get(
                    f"{node.removeprefix('probe:')}_spec",
                    {"declaration": supplied_spec, "canon": supplied["canon"]},
                ),
                "dependency_contracts": [
                    contracts["frozen"][f"{item.removeprefix('probe:')}_spec"]
                    for item in dependencies
                ],
            },
        )
        reviewed = _run_role_lane(
            state, graph, lane, "proof_reviewer", statement_sha256=top,
            contract_fingerprint=contracts["node_fingerprints"][node],
            input_hashes=[*fingerprints, _canonical_sha256(proposed)],
            role_context={
                "node": node, "proposed_candidate": proposed,
                "contract_fingerprints": fingerprints,
            },
        )
        if reviewed["claimed_status"] != "candidate":
            reviewed = _run_role_lane(
                state, graph, lane, "repair", statement_sha256=top,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[*fingerprints, _canonical_sha256(reviewed)],
                role_context={
                    "node": node, "proposed_candidate": proposed,
                    "review_rejection": reviewed,
                },
            )
        return {"node": node, "lane": lane, "fingerprints": fingerprints,
                "reviewed": reviewed}

    def accept_bundle(node: str, job: dict[str, Any]) -> bool:
        selected = job["reviewed"]
        if selected["claimed_status"] != "candidate":
            _block_dependents(state, node, "proof_repair_exhausted:" + selected["claimed_status"])
            return False
        lane = job["lane"]
        for attempt in range(1 if fvs_profile.enabled(state["config"]) else 2):
            response = _lane_candidate_response(selected, lane, job["fingerprints"])
            candidate = _candidate_record(response, lane, policy)
            _external_call(
                state, f"lane:{lane['lane_id']}:persist:{selected['role']}",
                lambda: worker.persist_lane_result(
                    run, lane, {key: value for key, value in candidate.items() if key != "response"}
                ),
            )
            transition = _checkpoint_candidate(state, candidate, manifest)
            if fvs_profile.enabled(state["config"]):
                from .fvs_adapter import Stages
                Stages(state, graph, lane, _run_role_lane, _checkpoint_if_enabled).record(
                    "serial-acceptance", {"transition": transition, "candidate_sha256": _canonical_sha256(selected)})
            if transition["status"].startswith("accepted"):
                break
            if attempt or fvs_profile.enabled(state["config"]):
                break
            selected = _run_role_lane(
                state, graph, lane, "repair", statement_sha256=top,
                contract_fingerprint=contracts["node_fingerprints"][node],
                input_hashes=[*job["fingerprints"], _canonical_sha256(selected),
                              _canonical_sha256(transition)],
                role_context={
                    "node": node, "rejected_candidate": selected,
                    "controller_rejection": transition,
                },
            )
            if selected["claimed_status"] != "candidate":
                break
        if not transition["status"].startswith("accepted"):
            _block_dependents(state, node, "proof_repair_exhausted:" + str(transition.get("reason")))
            return False
        if node != root:
            confirm_helper(node)
        return True

    preferred = "probe:curve25519_dalek.backend.serial.u64.scalar.m"
    if preferred not in graph["selected_nodes"]:
        preferred = None
    if proof_only and state["accepted_nodes"]:
        if len(state["accepted_nodes"]) != 1 or root in state["accepted_nodes"]:
            raise ContractError("resumed smoke accepted nodes changed")
        accepted_nodes = set(state["accepted_nodes"])
    else:
        accepted_nodes = _schedule_progressive(
            graph, run_bundle, accept_bundle, accepted_nodes=state["accepted_nodes"],
            preferred_leaf=preferred if proof_only else None,
            stop_after_accept=proof_only,
        )
    state["accepted_nodes"][:] = sorted(accepted_nodes)
    return _node_update(
        state, accepted=state["accepted"], contracts=contracts,
        receipts=state["receipts"], cost=state["cost"], lanes=state["lanes"],
        lane_intervals=state["lane_intervals"],
        candidate_receipts=state["candidate_receipts"],
        processed_candidate_sha256=state["processed_candidate_sha256"],
        accepted_sequence=state["accepted_sequence"],
        accepted_nodes=state["accepted_nodes"],
        proof_patch_sha256=state["proof_patch_sha256"],
    )


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
    proof_only = run.get("execution_mode") == "proof_only"
    prepared = isinstance(run.get("preparation_manifest"), dict)
    expected_lanes = _lane_descriptors(
        run,
        graph,
        [root] if proof_only and not prepared else graph["selected_nodes"],
        base_commit=run["base_commit"],
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
    else:
        lanes = expected_lanes
        # Persist deterministic identities before any mkdir/worktree side effect.
        run["lanes"] = state["lanes"] = lanes
        state["lane_initialization"] = {
            "descriptor_sha256": _canonical_sha256(expected_lanes), "phase": "preparing",
        }
        _checkpoint_if_enabled(state, "lanes:initialize:before")
    initialization = state.get("lane_initialization")
    if initialization is not None and (
        initialization.get("descriptor_sha256") != _canonical_sha256(expected_lanes)
        or initialization.get("phase") not in {"preparing", "ready"}
    ):
        raise ContractError("lane initialization identity changed")
    if initialization is not None and initialization["phase"] == "preparing":
        _external_call(
            state,
            "lanes:prepare-role-lanes",
            lambda: worker.prepare_lanes(run, [_worker_lane(lane) for lane in lanes]),
        )
        for lane in lanes:
            receipt = worker.save_lane_snapshot(run, _worker_lane(lane), initial=True)
            prior = state.setdefault("lane_snapshots", {}).get(lane["node"])
            if prior is not None and prior != receipt:
                raise worker.WorkerError("initial lane snapshot receipt changed")
            state["lane_snapshots"][lane["node"]] = receipt
            _checkpoint_if_enabled(state, f"lanes:initialize:{lane['lane_id']}:snapshot")
        initialization["phase"] = "ready"
        _checkpoint_if_enabled(state, "lanes:initialize:ready")
    elif previous_lanes:
        role_journal.reconcile_lane_snapshots(state)
        for lane in lanes:
            if lane["node"] in state.get("fvs_lane_generations", {}):
                continue  # Author generations are authenticated/restored at their own replay seam.
            receipt = state.get("lane_snapshots", {}).get(lane["node"])
            if receipt is None:
                raise worker.WorkerError("lane snapshot checkpoint is missing")
            worker.restore_lane_snapshot(run, _worker_lane(lane), expected_receipt=receipt)
        _event_once(run, "proof_lanes:reused")
    for lane in lanes:
        if lane.get("status") != "accepted":
            lane["status"] = "running"
    lanes_by_node = {lane["node"]: lane for lane in lanes}
    run["lanes"] = state["lanes"] = lanes

    dependency = None
    if prepared and proof_only and fvs_profile.enabled(state["config"]):
        # Helper smoke uses graph-derived DATA, not a fabricated model plan.
        dependency = {
            "schema": "autofv-frozen-helper-plan/v1", "source": "frozen_graph",
            "graph_sha256": graph["graph_sha256"], "root": root,
            "selected_nodes": deepcopy(graph["selected_nodes"]),
            "term_dependencies": deepcopy(graph["term_dependencies"]),
        }
        _event_once(run, "helper_smoke:planning_from_frozen_graph")
    elif not proof_only or prepared:
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

    if prepared:
        return _run_prepared_progressive(
            state, lanes_by_node, root, supplied_statement, dependency,
            proof_only=proof_only,
        )

    policy_sha256 = run["native_decide_policy_sha256"]
    previous_contracts = state.get("contracts")
    previous_frozen = state.get("frozen_contract_baseline")
    if previous_frozen is not None and (
        not isinstance(previous_frozen, dict)
        or previous_frozen.get("proof_barrier") != "frozen"
    ):
        raise ContractError("invalid frozen contract replay baseline")
    if (
        previous_frozen is None
        and isinstance(previous_contracts, dict)
        and previous_contracts.get("proof_barrier") == "frozen"
    ):
        # Replay itself checkpoints. Retain the authenticated frozen identity
        # independently of the draft so another interruption cannot turn an
        # already completed repair into a fresh revision of accepted proofs.
        previous_frozen = deepcopy(previous_contracts)
        state["frozen_contract_baseline"] = previous_frozen
        _checkpoint_if_enabled(state, "contracts:replay:before")
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
    completed_contracts = set(graph["selected_nodes"]) if proof_only else {root}
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

    outcome = (
        {"status": "passed"}
        if proof_only
        else feasibility("build:generic-provisional-consumer")
    )
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
            if previous_frozen is not None:
                # Replaying an authenticated completed review reconstructs the
                # same contract, not a new revision of already accepted proofs.
                if previous_frozen["node_fingerprints"].get(node) != record["model_fingerprint"]:
                    raise ContractError("resumed frozen contract revision changed")
                contracts["node_fingerprints"][node] = record["model_fingerprint"]
                contracts["revision_lineage"] = list(previous_frozen["revision_lineage"])
                contracts["invalidated_fingerprints"] = list(previous_frozen["invalidated_fingerprints"])
            else:
                _revise_contract_fingerprint(
                    state, node, record["model_fingerprint"], graph=graph,
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
    if previous_frozen is not None and any(
        contracts[key] != previous_frozen[key]
        for key in ("frozen", "frozen_fingerprints", "node_fingerprints")
    ):
        raise ContractError("resumed frozen contracts changed")
    # Clear explicitly for graph state propagation, only once the exact frozen
    # identity is restored. Until then every durable replay checkpoint retains it.
    state["frozen_contract_baseline"] = None
    _event_once(run, "statements_frozen")

    for node, target in state["target_states"].items():
        target.update(
            {
                "phase": "proof" if not proof_only or node == root else target["phase"],
                "status": "accepted" if node in state.get("accepted_nodes", []) else "pending",
                "contract_fingerprint": contracts["node_fingerprints"].get(node),
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
        dependencies = [] if proof_only else sorted(
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
        return True

    if proof_only:
        accepted_nodes = set(state["accepted_nodes"])
        if root not in accepted_nodes:
            job = run_proof(prepare_proof(root))
            if accept_proof(root, job):
                accepted_nodes.add(root)
    else:
        accepted_nodes = _schedule_proofs(
            graph,
            run_proof,
            accept_proof,
            prepare_job=prepare_proof,
            accepted_nodes=state["accepted_nodes"],
            max_workers=1 if isinstance(run.get("preparation_manifest"), dict) else MAX_PARALLEL_LANES,
        )
    state["accepted_nodes"][:] = sorted(accepted_nodes)

    if not proof_only:
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
