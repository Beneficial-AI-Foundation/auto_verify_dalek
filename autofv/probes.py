"""Strict adapters for the pinned Rust and Aeneas probe outputs."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


MAX_PROBE_BYTES = 16 * 1024 * 1024
MAX_NODES = 10_000
MAX_EDGES = 100_000


class ProbeError(ValueError):
    """Probe evidence is malformed, incomplete, or unsupported."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > MAX_PROBE_BYTES:
        raise ProbeError(f"{label}_too_large")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_float=lambda _: (_ for _ in ()).throw(
                ValueError("floating point values are forbidden")
            ),
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite value {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProbeError(f"invalid_{label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProbeError(f"invalid_{label}: root must be an object")
    return value


def _tool_envelope(
    value: dict[str, Any], *, schema: str, name: str, version: str, label: str
) -> dict[str, Any]:
    if value.get("schema") != schema or value.get("schema-version") != "3.0":
        raise ProbeError(f"{label}_schema_mismatch")
    if value.get("tool") != {"name": name, "version": version, "command": "extract"}:
        raise ProbeError(f"{label}_tool_mismatch")
    atoms = value.get("data")
    if not isinstance(atoms, dict) or not atoms or len(atoms) > MAX_NODES:
        raise ProbeError(f"{label}_data_invalid")
    return atoms


def _text(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ProbeError(reason)
    return value


def _string_list(value: Any, reason: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ProbeError(reason)
    return value


def _source_path(value: Any, reason: str) -> str:
    source = _text(value, reason)
    path = PurePosixPath(source)
    if (
        path.is_absolute()
        or "\\" in source
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != source
    ):
        raise ProbeError(reason)
    return source


def _selected_lean_atom(name: str, atom: Any) -> dict[str, Any]:
    if not isinstance(atom, dict) or atom.get("language") != "lean":
        raise ProbeError("selected_lean_atom_missing")
    required = {
        "code-path",
        "code-text",
        "dependencies",
        "display-name",
        "is-extraction-artifact",
        "is-hidden",
        "is-ignored",
        "is-in-package",
        "is-relevant",
        "term-dependencies",
        "type-dependencies",
        "verification-status",
    }
    if not required <= atom.keys():
        raise ProbeError("selected_lean_fields_missing")
    if (
        atom["is-extraction-artifact"] is not False
        or atom["is-hidden"] is not False
        or atom["is-ignored"] is not False
        or atom["is-in-package"] is not True
        or atom["is-relevant"] is not True
    ):
        raise ProbeError("selected_lean_atom_not_schedulable")
    if atom["verification-status"] == "failed":
        raise ProbeError("selected_dependency_failed")
    if atom["verification-status"] not in {
        "verified",
        "transitively-verified",
        "unverified",
    }:
        raise ProbeError("selected_lean_status_invalid")
    _source_path(atom["code-path"], "selected_lean_source_invalid")
    _text(atom["display-name"], "selected_lean_display_name_missing")
    lines = atom["code-text"]
    if (
        not isinstance(lines, dict)
        or type(lines.get("lines-start")) is not int
        or type(lines.get("lines-end")) is not int
        or lines["lines-start"] <= 0
        or lines["lines-end"] < lines["lines-start"]
    ):
        raise ProbeError("selected_lean_code_range_invalid")
    _string_list(atom["dependencies"], "selected_dependencies_invalid")
    _string_list(atom["term-dependencies"], "selected_term_dependencies_invalid")
    _string_list(atom["type-dependencies"], "selected_type_dependencies_invalid")
    return atom


def _validate_dependency_partition(
    atom: dict[str, Any], merged_atoms: dict[str, Any]
) -> None:
    classified = set(atom["term-dependencies"]) | set(atom["type-dependencies"])
    for dependency in atom["dependencies"]:
        candidate = merged_atoms.get(dependency)
        if (
            isinstance(candidate, dict)
            and candidate.get("language") == "lean"
            and candidate.get("is-in-package") is True
            and candidate.get("is-relevant") is True
            and dependency not in classified
        ):
            raise ProbeError("selected_dependency_edge_missing")


def _topological_orders(
    nodes: set[str], edges: list[tuple[str, str]], roots: list[str]
) -> tuple[list[str], list[list[str]]]:
    dependencies = {node: set() for node in nodes}
    consumers = {node: set() for node in nodes}
    for consumer, dependency in edges:
        dependencies[consumer].add(dependency)
        consumers[dependency].add(consumer)

    # The contract walk starts at T and follows consumer -> dependency.
    contract_order: list[str] = []
    seen: set[str] = set()

    def visit(node: str) -> None:
        if node in seen:
            return
        seen.add(node)
        contract_order.append(node)
        for dependency in sorted(dependencies[node]):
            visit(dependency)

    for root in sorted(roots):
        visit(root)

    remaining = {node: set(values) for node, values in dependencies.items()}
    proof_batches: list[list[str]] = []
    while remaining:
        ready = sorted(node for node, values in remaining.items() if not values)
        if not ready:
            raise ProbeError("unsupported_dependency_cycle")
        proof_batches.append(ready)
        for node in ready:
            del remaining[node]
        for values in remaining.values():
            values.difference_update(ready)
    return contract_order, proof_batches


def parse_probe_bytes(
    manifest: dict[str, Any], rust_raw: bytes, aeneas_raw: bytes
) -> dict[str, Any]:
    """Reduce exact probe bytes to the selected deterministic scheduling graph."""
    rust = _strict_json(rust_raw, "probe_rust")
    aeneas = _strict_json(aeneas_raw, "probe_aeneas")
    rust_atoms = _tool_envelope(
        rust,
        schema="probe-rust/extract",
        name="probe-rust",
        version="0.10.0",
        label="probe_rust",
    )
    merged_atoms = _tool_envelope(
        aeneas,
        schema="probe-aeneas/extract",
        name="probe-aeneas",
        version="0.19.0",
        label="probe_aeneas",
    )

    frozen_targets: list[str] = []
    supplied_specs: dict[str, str] = {}
    for target in manifest.get("targets", []):
        rust_name = target["function"]
        rust_atom = rust_atoms.get(rust_name)
        merged_rust = merged_atoms.get(rust_name)
        if not isinstance(rust_atom, dict) or not isinstance(merged_rust, dict):
            raise ProbeError("manifest_target_missing")
        lean_name = merged_rust.get("translation-name")
        if not isinstance(lean_name, str) or not lean_name:
            raise ProbeError("manifest_target_translation_missing")
        lean_atom = _selected_lean_atom(lean_name, merged_atoms.get(lean_name))
        _validate_dependency_partition(lean_atom, merged_atoms)
        primary_spec = lean_atom.get("primary-spec")
        expected_spec = f"probe:{target['spec']}"
        if primary_spec != expected_spec:
            raise ProbeError("manifest_primary_spec_mismatch")
        _selected_lean_atom(primary_spec, merged_atoms.get(primary_spec))
        frozen_targets.append(lean_name)
        supplied_specs[lean_name] = primary_spec

    nodes: set[str] = set(frozen_targets)
    pending = list(frozen_targets)
    edges: set[tuple[str, str]] = set()
    type_edges: set[tuple[str, str]] = set()
    sources: dict[str, str] = {}
    while pending:
        name = pending.pop()
        atom = _selected_lean_atom(name, merged_atoms.get(name))
        _validate_dependency_partition(atom, merged_atoms)
        sources[name] = atom["code-path"]
        for dependency in atom["term-dependencies"]:
            candidate = merged_atoms.get(dependency)
            if not isinstance(candidate, dict) or candidate.get("language") != "lean":
                raise ProbeError("selected_term_dependency_missing")
            _selected_lean_atom(dependency, candidate)
            edges.add((name, dependency))
            if dependency not in nodes:
                nodes.add(dependency)
                pending.append(dependency)
        for dependency in atom["type-dependencies"]:
            candidate = merged_atoms.get(dependency)
            if not isinstance(candidate, dict) or candidate.get("language") != "lean":
                raise ProbeError("selected_type_dependency_missing")
            dependency_atom = _selected_lean_atom(dependency, candidate)
            sources[dependency] = dependency_atom["code-path"]
            type_edges.add((name, dependency))

    primary_specs = sorted(set(supplied_specs.values()))
    for spec in primary_specs:
        atom = _selected_lean_atom(spec, merged_atoms.get(spec))
        _validate_dependency_partition(atom, merged_atoms)
        sources[spec] = atom["code-path"]
        for dependency in atom["type-dependencies"]:
            candidate = merged_atoms.get(dependency)
            if not isinstance(candidate, dict) or candidate.get("language") != "lean":
                raise ProbeError("selected_type_dependency_missing")
            dependency_atom = _selected_lean_atom(dependency, candidate)
            sources[dependency] = dependency_atom["code-path"]
            type_edges.add((spec, dependency))

    if len(edges) > MAX_EDGES:
        raise ProbeError("probe_graph_too_large")
    contract_order, proof_batches = _topological_orders(nodes, sorted(edges), frozen_targets)
    graph_body = {
        "frozen_targets": sorted(frozen_targets),
        "supplied_specs": supplied_specs,
        "selected_nodes": sorted(nodes),
        "term_dependencies": [list(edge) for edge in sorted(edges)],
        "type_dependencies": [list(edge) for edge in sorted(type_edges)],
        "contract_order": contract_order,
        "proof_batches": proof_batches,
        "source_paths": {key: sources[key] for key in sorted(sources)},
    }
    return {
        **graph_body,
        "probe_rust_sha256": _sha256(rust_raw),
        "probe_aeneas_sha256": _sha256(aeneas_raw),
        "graph_sha256": _sha256(_canonical_bytes(graph_body)),
    }


def run_probes(project_dir: str | Path, evidence_dir: str | Path) -> dict[str, Any]:
    """Run the two pinned argv contracts, retain bytes, and return their graph."""
    project = Path(project_dir)
    evidence = Path(evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    rust_path = evidence / "probe-rust.json"
    aeneas_path = evidence / "probe-aeneas.json"
    subprocess.run(
        (
            "probe-rust",
            "extract",
            str(project),
            "--with-locations",
            "--with-public-api",
            "-o",
            str(rust_path),
        ),
        check=True,
        cwd=project,
    )
    subprocess.run(
        (
            "probe-aeneas",
            "extract",
            str(project),
            "--with-public-api",
            "-o",
            str(aeneas_path),
        ),
        check=True,
        cwd=project,
    )
    rust_raw = rust_path.read_bytes()
    aeneas_raw = aeneas_path.read_bytes()
    manifest = json.loads((project / "autofv.json").read_text(encoding="utf-8"))
    return parse_probe_bytes(manifest, rust_raw, aeneas_raw)
