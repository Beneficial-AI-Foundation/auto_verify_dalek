"""Canonical proof inventories, native provenance, and retained-report policy."""

from __future__ import annotations

import re
from typing import Any

from . import contracts


COMPILER_AXIOMS = frozenset({"Lean.ofReduceBool", "Lean.trustCompiler"})
_RECORD_FIELDS = frozenset(
    {
        "declaration",
        "origin",
        "type_sha256",
        "semantic_dependencies",
        "dependencies",
        "axioms",
        "native_decide_uses",
    }
)


def _sha(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def _reference_uses(
    proof: str, *, index: int, spec: str, declaration: str
) -> list[dict[str, str]]:
    source_path = f"reference/hidden-{index}.lean"
    source_sha256 = _sha(proof.encode())
    uses = []
    for line in proof.splitlines():
        code = line.split("--", 1)[0]
        for _ in re.finditer(r"\bnative_decide\b", code):
            uses.append(
                {
                    "spec": spec,
                    "declaration": declaration,
                    "source_path": source_path,
                    "source_sha256": source_sha256,
                    "expression_sha256": _sha(code.strip().encode()),
                    "origin": "baseline",
                }
            )
    return uses


def _use_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        item["spec"],
        item["declaration"],
        item["source_path"],
        item["expression_sha256"],
    )


def canonical_native_uses(*inventories: list[Any]) -> list[dict[str, Any]]:
    """Deduplicate then order the exact policy identity tuple."""
    selected: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in (item for inventory in inventories for item in inventory):
        if not isinstance(item, dict):
            raise contracts.ContractError("native_decide inventory is malformed")
        try:
            key = _use_key(item)
        except KeyError as exc:
            raise contracts.ContractError(
                "native_decide inventory is malformed"
            ) from exc
        previous = selected.get(key)
        if previous is not None and previous != item:
            raise contracts.ContractError("native_decide inventory is ambiguous")
        selected[key] = item
    return [selected[key] for key in sorted(selected)]


def _native_uses(
    claimed: list[Any], dependencies: set[str]
) -> list[dict[str, Any]]:
    """Select and canonically order every use attributed to this closure."""
    return canonical_native_uses(
        [
            item
            for item in claimed
            if isinstance(item, dict)
            and item.get("declaration") in dependencies
        ]
    )


def _contract_nodes(
    state: dict[str, Any], reference: dict[str, Any]
) -> dict[str, str]:
    graph = state.get("graph", {})
    selected = graph.get("selected_nodes", [])
    graph_nodes = set(graph.get("source_paths", {}))
    paths = graph.get("source_paths", {})
    leaves = {
        leaf.get("spec"): leaf
        for leaf in reference.get("leaves", [])
        if isinstance(leaf, dict)
    }
    result: dict[str, str] = {}
    for declaration in state.get("frozen_contracts", {}):
        leaf = leaves.get(declaration, {})
        stem = declaration.removesuffix("_spec")
        exact = f"probe:{declaration}"
        candidates = [exact] if exact in graph_nodes else [
            node for node in selected if node.removeprefix("probe:") == stem
        ]
        if not candidates and leaf.get("source"):
            candidates = [
                node
                for node in selected
                if paths.get(node) == leaf["source"]
                and node.removeprefix("probe:") == leaf.get("declaration")
            ]
        if len(candidates) != 1:
            raise contracts.ContractError("kernel audit contract node mismatch")
        result[declaration] = candidates[0]
    return result


def accepted_declaration_for_target(
    state: dict[str, Any], reference: dict[str, Any], target: str
) -> str | None:
    """Resolve one controller-bound graph target to its accepted theorem."""
    matches = [
        declaration
        for declaration, node in _contract_nodes(state, reference).items()
        if node == target
    ]
    if len(matches) > 1:
        raise contracts.ContractError("kernel audit contract node mismatch")
    return matches[0] if matches else None


def _dependency_closure(
    graph: dict[str, Any], node: str
) -> set[str]:
    edges = [
        *graph.get("term_dependencies", []),
        *graph.get("type_dependencies", []),
    ]
    closure = {node}
    changed = True
    while changed:
        changed = False
        for consumer, dependency in edges:
            if consumer in closure and dependency not in closure:
                closure.add(dependency)
                changed = True
    return closure


def _contract_dependency_nodes(
    declaration: str,
    *,
    state: dict[str, Any],
    nodes: dict[str, str],
) -> set[str]:
    return _dependency_closure(state["graph"], nodes[declaration])


def expected_inventory(
    state: dict[str, Any],
    reference: dict[str, Any],
    *,
    observed_closures: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Recompute the exact declaration universe and native-decide evidence."""
    claimed_uses = state.get("native_decide_uses", [])
    nodes = _contract_nodes(state, reference)
    closures_by_spec = {
        declaration: _contract_dependency_nodes(
            declaration, state=state, nodes=nodes
        )
        for declaration in state.get("frozen_contracts", {})
    }
    dependencies_by_spec = {
        declaration: sorted(
            node.removeprefix("probe:")
            for node in closure
            if node.startswith("probe:")
            and node != f"probe:{declaration}"
        )
        for declaration, closure in closures_by_spec.items()
    }
    attribution_by_spec = {
        declaration: set(dependencies_by_spec[declaration])
        | {
            name
            for name, node in nodes.items()
            if node in closures_by_spec[declaration]
        }
        for declaration in closures_by_spec
    }
    if observed_closures is not None:
        roots = set(state.get("frozen_contracts", {})) | {
            f"AutoFVVerifier.{kind}_{index}"
            for index, _leaf in enumerate(reference.get("leaves", []))
            for kind in ("hidden", "meaning")
        }
        if (
            set(observed_closures) != roots
            or any(
                not isinstance(closure, list)
                or root not in closure
                or closure != sorted(set(closure))
                or any(not isinstance(name, str) or not name for name in closure)
                for root, closure in observed_closures.items()
            )
        ):
            raise contracts.ContractError("kernel dependency closure is incomplete")
        attribution_by_spec = {
            declaration: set(observed_closures[declaration])
            for declaration in state.get("frozen_contracts", {})
        }
    records = []
    for declaration, contract in sorted(state.get("frozen_contracts", {}).items()):
        semantic_dependencies = dependencies_by_spec[declaration]
        dependencies = (
            [
                name
                for name in observed_closures[declaration]
                if name != declaration
            ]
            if observed_closures is not None
            else semantic_dependencies
        )
        uses = _native_uses(claimed_uses, attribution_by_spec[declaration])
        records.append(
            {
                "declaration": declaration,
                "origin": "accepted_spec",
                "type_sha256": _sha(contract["canon"].encode()),
                "semantic_dependencies": semantic_dependencies,
                "dependencies": dependencies,
                "axioms": [],
                "native_decide_uses": uses,
            }
        )
    for index, leaf in enumerate(reference.get("leaves", [])):
        if not isinstance(leaf, dict):
            continue
        declaration = f"AutoFVVerifier.hidden_{index}"
        spec = leaf.get("spec", "")
        semantic_dependencies = dependencies_by_spec.get(spec, [])
        dependencies = (
            [name for name in observed_closures[declaration] if name != declaration]
            if observed_closures is not None
            else semantic_dependencies
        )
        attribution = (
            set(observed_closures[declaration])
            if observed_closures is not None
            else attribution_by_spec[spec]
        )
        records.append(
            {
                "declaration": declaration,
                "origin": "hidden_reference",
                "type_sha256": _sha(
                    f"theorem {declaration} : {leaf.get('statement', '')}".encode()
                ),
                "semantic_dependencies": semantic_dependencies,
                "dependencies": dependencies,
                "axioms": [],
                "native_decide_uses": canonical_native_uses(
                    _native_uses(claimed_uses, attribution),
                    _reference_uses(
                        leaf.get("proof", ""),
                        index=index,
                        spec=spec,
                        declaration=declaration,
                    ),
                ),
            }
        )
        meaning = f"AutoFVVerifier.meaning_{index}"
        meaning_dependencies = (
            [name for name in observed_closures[meaning] if name != meaning]
            if observed_closures is not None
            else semantic_dependencies
        )
        meaning_attribution = (
            set(observed_closures[meaning])
            if observed_closures is not None
            else attribution_by_spec[spec]
        )
        records.append(
            {
                "declaration": meaning,
                "origin": "meaning_check",
                "type_sha256": _sha(
                    f"theorem {meaning} : {leaf.get('statement', '')}".encode()
                ),
                "semantic_dependencies": semantic_dependencies,
                "dependencies": meaning_dependencies,
                "axioms": [],
                "native_decide_uses": _native_uses(
                    claimed_uses, meaning_attribution
                ),
            }
        )
    return sorted(records, key=lambda item: (item["declaration"], item["origin"]))


def parse_inventory(
    stdout: bytes, stderr: bytes, expected: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    text = (stdout + b"\n" + stderr).decode("utf-8", "strict")
    parsed = []
    for skeleton in expected:
        declaration = skeleton["declaration"]
        empty = f"'{declaration}' does not depend on any axioms"
        matches = re.findall(
            rf"'{re.escape(declaration)}' depends on axioms: \[(.*?)\]$",
            text,
            flags=re.MULTILINE,
        )
        if empty in text:
            matches.append("")
        if len(matches) != 1:
            raise contracts.ContractError("kernel axiom inventory is incomplete")
        axioms = sorted(
            {item.strip() for item in matches[0].split(",") if item.strip()}
        )
        parsed.append({**skeleton, "axioms": axioms})
    return parsed


def validate_inventory(
    inventory: Any,
    expected: list[dict[str, Any]],
    *,
    lock: dict[str, Any],
    compiler_assumptions: list[dict[str, str]],
    allow_untrusted_axioms: bool = False,
    permitted_untrusted_declarations: frozenset[str] = frozenset(),
) -> None:
    """Reject incomplete declarations and every unaudited transitive axiom."""
    if not isinstance(inventory, list) or len(inventory) != len(expected):
        raise contracts.ContractError("kernel axiom inventory mismatch")
    all_uses: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for actual, skeleton in zip(inventory, expected, strict=True):
        if (
            not isinstance(actual, dict)
            or set(actual) != _RECORD_FIELDS
            or {key: actual.get(key) for key in _RECORD_FIELDS - {"axioms"}}
            != {key: skeleton.get(key) for key in _RECORD_FIELDS - {"axioms"}}
            or not isinstance(actual.get("axioms"), list)
            or actual["axioms"] != sorted(set(actual["axioms"]))
            or any(not isinstance(item, str) or not item for item in actual["axioms"])
        ):
            raise contracts.ContractError("kernel axiom inventory mismatch")
        axioms = set(actual["axioms"])
        uses = actual["native_decide_uses"]
        if (
            axioms - COMPILER_AXIOMS
            and (
                not allow_untrusted_axioms
                or actual["origin"] != "accepted_spec"
                or actual["declaration"] not in permitted_untrusted_declarations
            )
        ) or bool(axioms & COMPILER_AXIOMS) != bool(uses):
            raise contracts.ContractError("kernel axiom inventory is unauthorized")
        for use in uses:
            key = _use_key(use)
            previous = all_uses.get(key)
            if previous is not None and previous != use:
                raise contracts.ContractError("native_decide inventory is ambiguous")
            all_uses[key] = use
    contracts.evaluate_native_decide_policy(
        lock,
        native_decide_uses=[all_uses[key] for key in sorted(all_uses)],
        compiler_assumptions=compiler_assumptions,
    )


def inventory_scope_sha256(inventory: Any) -> str:
    """Bind the exact state/reference-derived declaration contract."""
    if not isinstance(inventory, list) or any(
        not isinstance(item, dict)
        or not {
            "declaration",
            "origin",
            "type_sha256",
            "semantic_dependencies",
        } <= set(item)
        for item in inventory
    ):
        raise contracts.ContractError("kernel axiom inventory mismatch")
    identity = [
        {
            key: item[key]
            for key in (
                "declaration",
                "origin",
                "type_sha256",
                "semantic_dependencies",
            )
        }
        for item in inventory
    ]
    return _sha(contracts.canonical_json_bytes(identity))


def inventory_identity_sha256(inventory: Any) -> str:
    """Bind every retained field of the observed kernel inventory."""
    if not isinstance(inventory, list) or any(
        not isinstance(item, dict) or set(item) != _RECORD_FIELDS
        for item in inventory
    ):
        raise contracts.ContractError("kernel axiom inventory mismatch")
    return _sha(contracts.canonical_json_bytes(inventory))


def native_use_provenance(
    inventory: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Separate accepted-source uses from direct hidden-reference uses."""
    if not isinstance(inventory, list):
        raise contracts.ContractError("kernel axiom inventory mismatch")
    accepted = []
    hidden = []
    for record in inventory:
        if not isinstance(record, dict):
            raise contracts.ContractError("kernel axiom inventory mismatch")
        declaration = record.get("declaration")
        match = (
            re.fullmatch(r"AutoFVVerifier\.hidden_(\d+)", declaration)
            if isinstance(declaration, str)
            else None
        )
        hidden_path = f"reference/hidden-{match.group(1)}.lean" if match else None
        for use in record.get("native_decide_uses", []):
            direct_hidden = (
                record.get("origin") == "hidden_reference"
                and hidden_path is not None
                and isinstance(use, dict)
                and use.get("declaration") == declaration
                and use.get("source_path") == hidden_path
            )
            if isinstance(use, dict) and str(use.get("source_path", "")).startswith(
                "reference/"
            ) and not direct_hidden:
                raise contracts.ContractError(
                    "native_decide reference provenance is invalid"
                )
            (hidden if direct_hidden else accepted).append(use)
    accepted_uses = canonical_native_uses(accepted)
    hidden_uses = canonical_native_uses(hidden)
    return (
        accepted_uses,
        hidden_uses,
        canonical_native_uses(accepted_uses, hidden_uses),
    )


def validate_report_inventory(
    inventory: Any,
    *,
    lock: dict[str, Any],
    compiler_assumptions: list[dict[str, str]],
    require_complete: bool,
    expected_scope_sha256: str | None = None,
    expected_identity_sha256: str | None = None,
    accepted_native_decide_uses: list[dict[str, Any]] | None = None,
    hidden_native_decide_uses: list[dict[str, Any]] | None = None,
    required_native_uses: list[dict[str, Any]] | None = None,
    allow_untrusted_axioms: bool = False,
    permitted_untrusted_declarations: frozenset[str] = frozenset(),
) -> None:
    """Reauthorize retained inventory without trusting its verdict/check bits."""
    if not isinstance(inventory, list):
        raise contracts.ContractError("kernel axiom inventory mismatch")
    if (
        not isinstance(expected_scope_sha256, str)
        or not isinstance(expected_identity_sha256, str)
        or inventory_scope_sha256(inventory) != expected_scope_sha256
        or inventory_identity_sha256(inventory) != expected_identity_sha256
    ):
        raise contracts.ContractError("kernel axiom inventory identity mismatch")
    if require_complete:
        origins = [item.get("origin") for item in inventory if isinstance(item, dict)]
        identities = [
            (item.get("declaration"), item.get("origin"))
            for item in inventory
            if isinstance(item, dict)
        ]
        hidden = {
            match.group(1)
            for item in inventory
            if isinstance(item, dict)
            and (match := re.fullmatch(
                r"AutoFVVerifier\.hidden_(\d+)", item.get("declaration", "")
            ))
        }
        meanings = {
            match.group(1)
            for item in inventory
            if isinstance(item, dict)
            and (match := re.fullmatch(
                r"AutoFVVerifier\.meaning_(\d+)", item.get("declaration", "")
            ))
        }
        if (
            not inventory
            or set(origins)
            != {"accepted_spec", "hidden_reference", "meaning_check"}
            or len(set(identities)) != len(inventory)
            or hidden != meanings
            or any(
                not isinstance(item.get("declaration"), str)
                or not item["declaration"]
                or not isinstance(item.get("type_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["type_sha256"])
                or any(
                    not isinstance(item.get(field), list)
                    or item[field] != sorted(set(item[field]))
                    for field in ("semantic_dependencies", "dependencies")
                )
                or any(
                    not isinstance(dependency, str) or not dependency
                    for field in ("semantic_dependencies", "dependencies")
                    for dependency in item[field]
                )
                for item in inventory
                if isinstance(item, dict)
            )
        ):
            raise contracts.ContractError("kernel axiom inventory is incomplete")
    universe = canonical_native_uses(
        *[
            item.get("native_decide_uses", [])
            for item in inventory
            if isinstance(item, dict)
        ]
    )
    accepted_uses, hidden_uses, provenance_union = native_use_provenance(inventory)
    if accepted_native_decide_uses is not None and (
        canonical_native_uses(accepted_native_decide_uses) != accepted_uses
    ):
        raise contracts.ContractError("native_decide accepted provenance mismatch")
    if hidden_native_decide_uses is not None and (
        canonical_native_uses(hidden_native_decide_uses) != hidden_uses
    ):
        raise contracts.ContractError("native_decide hidden provenance mismatch")
    if provenance_union != universe:
        raise contracts.ContractError("native_decide inventory is incomplete")
    if required_native_uses is not None:
        required = canonical_native_uses(required_native_uses)
        if required != universe:
            raise contracts.ContractError("native_decide inventory is incomplete")
    expected = []
    for item in inventory:
        if not isinstance(item, dict):
            expected.append(item)
            continue
        closure = set(item.get("dependencies", [])) | {
            item.get("declaration")
        }
        expected.append(
            {
                **item,
                "axioms": [],
                "native_decide_uses": _native_uses(universe, closure),
            }
        )
    validate_inventory(
        inventory,
        expected,
        lock=lock,
        compiler_assumptions=compiler_assumptions,
        allow_untrusted_axioms=allow_untrusted_axioms,
        permitted_untrusted_declarations=permitted_untrusted_declarations,
    )
