"""Immutable graph validation and bounded declaration scheduling."""

from __future__ import annotations

import hmac
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import PurePosixPath
from typing import Any

from .contracts import ContractError
from .run_state import _RunState, _canonical_sha256, _event_once


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
    valid = payload.get("root") == root if isinstance(payload, dict) else False
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
            or sorted(depends_on) != sorted(expected_dependencies[declaration])
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
        item.get("node") == node
        for item in contracts.setdefault("revision_lineage", [])
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
        accepted
        for accepted in state.get("accepted_nodes", [])
        if accepted not in affected
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
        {
            "phase": "proof",
            "status": "failed",
            "reason": reason,
            "block_chain": [node],
        }
    )
    block_chains = state.setdefault("block_chains", {})
    for consumer in blocked:
        block_chains[consumer] = chains[consumer]
        target_states[consumer].update(
            {"phase": "proof", "status": "blocked", "block_chain": chains[consumer]}
        )
    affected = {node, *blocked}
    state["accepted_nodes"] = [
        accepted
        for accepted in state.get("accepted_nodes", [])
        if accepted not in affected
    ]
    for affected_node in affected:
        state.setdefault("proof_patch_sha256", {}).pop(affected_node, None)
    _event_once(state["run"], f"proof_blocked:{node}")
    return blocked


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
                if accept_job(node, future.result()) is not False:
                    accepted.add(node)
    return accepted
