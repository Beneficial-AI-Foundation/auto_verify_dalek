"""Deterministic, Dalek-specific preparation of spoiler-free Lean inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


SMALL_DECLARATION = "probe:curve25519_dalek.scalar.Scalar.from_canonical_bytes"
REPORT_SCHEMA = "target-report/v1"
IDENTITIES_SCHEMA = "autofv-dalek-probe-identities/v1"
MANIFEST_SCHEMA = "preparation-manifest/v1"
PUBLICATION_SCHEMA = "autofv-publication-receipt/v1"
HEX = frozenset("0123456789abcdef")
SECRET_PATTERN = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-z0-9_-]{8,}"
)
SPOILER_MARKERS = (
    b"diamond-reference",
    b"hidden reference",
    b"reference.json",
    b"secretlemma",
    b"solutiononly",
)
GENERATED_CORE_FILES = frozenset(
    {
        "Curve25519Dalek/Funs.lean",
        "Curve25519Dalek/FunsExternal.lean",
        "Curve25519Dalek/Types.lean",
        "Curve25519Dalek/TypesExternal.lean",
    }
)
PUBLICATION_LICENSES = (
    ("LICENSE", "LICENSE"),
    ("curve25519-dalek/LICENSE", "LICENSES/curve25519-dalek-BSD-3-Clause.txt"),
)


class PreparationError(RuntimeError):
    """The solved input cannot be reduced to a trusted prepared tree."""


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


def _read_json(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PreparationError(f"invalid {label}") from exc
    if not isinstance(value, dict):
        raise PreparationError(f"invalid {label}")
    return raw, value


def _is_hash(value: Any, lengths: frozenset[int] = frozenset({64})) -> bool:
    return (
        isinstance(value, str)
        and len(value) in lengths
        and all(char in HEX for char in value)
    )


def _identity(value: Any, *, probe: bool) -> dict[str, Any]:
    fields = {"repository", "revision", "tree_sha256"}
    if probe:
        fields.add("version")
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not isinstance(value["repository"], str)
        or not value["repository"]
        or not _is_hash(value["revision"], frozenset({40, 64}))
        or not _is_hash(value["tree_sha256"])
        or (probe and (not isinstance(value["version"], str) or not value["version"]))
    ):
        raise PreparationError("provenance identity mismatch")
    return value


def _safe_path(name: Any) -> str:
    if not isinstance(name, str):
        raise PreparationError("unsafe source path")
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or "\\" in name
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PreparationError(f"unsafe source path: {name!r}")
    return name


def _source_file(source: Path, name: str) -> Path:
    path = source / _safe_path(name)
    if path.is_symlink() or not path.is_file():
        raise PreparationError(f"source is not a regular file: {name}")
    if not path.resolve().is_relative_to(source):
        raise PreparationError(f"source path escapes repository: {name}")
    return path


def _validate_inputs(
    report: dict[str, Any], identities: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if set(report) != {
        "schema",
        "inputs",
        "tools",
        "graph_tops",
        "declarations",
        "diagnostics",
    } or report.get("schema") != REPORT_SCHEMA:
        raise PreparationError("target report schema mismatch")
    tops = report.get("graph_tops")
    targets = report.get("declarations")
    diagnostics = report.get("diagnostics")
    if (
        not isinstance(tops, list)
        or not tops
        or tops != sorted(set(tops))
        or not isinstance(targets, dict)
        or set(targets) != set(tops)
        or not isinstance(diagnostics, list)
    ):
        raise PreparationError("target report graph tops mismatch")
    for diagnostic in diagnostics:
        if (
            not isinstance(diagnostic, dict)
            or set(diagnostic)
            != {"kind", "rust_function", "declaration"}
            or diagnostic.get("kind") != "graph_top_primary_spec_missing"
            or not isinstance(diagnostic.get("rust_function"), str)
            or not diagnostic["rust_function"]
            or not isinstance(diagnostic.get("declaration"), str)
            or not diagnostic["declaration"]
            or diagnostic["rust_function"] in targets
        ):
            raise PreparationError("target report diagnostic mismatch")
    if diagnostics != sorted(
        diagnostics,
        key=lambda item: (item["rust_function"], item["declaration"]),
    ):
        raise PreparationError("target report diagnostic order mismatch")
    inputs = report.get("inputs")
    tools = report.get("tools")
    if (
        not isinstance(inputs, dict)
        or set(inputs) != {"probe_aeneas_sha256", "probe_rust_sha256"}
        or not all(_is_hash(value) for value in inputs.values())
        or not isinstance(tools, dict)
        or set(tools) != {"probe_aeneas", "probe_rust"}
    ):
        raise PreparationError("target report input identity mismatch")
    for name in tops:
        target = targets[name]
        if not isinstance(target, dict) or set(target) != {
            "public_api",
            "declaration",
            "primary_spec",
            "directed_closure",
            "source",
        }:
            raise PreparationError(f"target metadata mismatch: {name}")

    if set(identities) != {
        "schema",
        "source",
        "probes",
        "files",
        "declarations",
    } or identities.get("schema") != IDENTITIES_SCHEMA:
        raise PreparationError("probe identities schema mismatch")
    declarations = identities.get("declarations")
    files = identities.get("files")
    probes = identities.get("probes")
    _identity(identities.get("source"), probe=False)
    if (
        not isinstance(probes, dict)
        or set(probes) != {"probe-aeneas", "probe-rust", "probe-lean"}
    ):
        raise PreparationError("provenance probe identities mismatch")
    for name, value in probes.items():
        _identity(value, probe=True)
        report_tool = tools.get(name.replace("-", "_"))
        if report_tool is not None and report_tool != {
            "name": name,
            "version": value["version"],
            "command": "extract",
        }:
            raise PreparationError("provenance probe tool mismatch")
    if not isinstance(declarations, dict) or not declarations or not isinstance(files, dict):
        raise PreparationError("probe identities declaration index missing")
    for name, record in declarations.items():
        if not isinstance(name, str) or not isinstance(record, dict) or set(record) != {
            "path",
            "lines",
            "kind",
            "dependencies",
            "proof_dependencies",
        }:
            raise PreparationError(f"declaration evidence mismatch: {name}")
        if record["kind"] not in {
            "implementation",
            "statement",
            "type",
            "trusted_math",
            "proof_only",
        }:
            raise PreparationError(f"declaration kind invalid: {name}")
    for name, record in files.items():
        _safe_path(name)
        if not isinstance(record, dict) or record != {"role": "build"}:
            raise PreparationError(f"support file evidence mismatch: {name}")
    return targets, declarations, files


def _selected_roots(
    tops: list[str], targets: dict[str, Any], mode: str
) -> list[str]:
    if mode == "full":
        return tops
    matches = [
        name
        for name in tops
        if isinstance(targets.get(name), dict)
        and targets[name].get("declaration") == SMALL_DECLARATION
    ]
    if len(matches) != 1:
        raise PreparationError("small-mode Scalar.from_canonical_bytes root mismatch")
    return matches


def _selected_declarations(
    roots: list[str],
    targets: dict[str, Any],
    declarations: dict[str, Any],
) -> tuple[set[str], set[str]]:
    selected: set[str] = set()
    root_specs: set[str] = set()
    for root in roots:
        target = targets.get(root)
        if not isinstance(target, dict):
            raise PreparationError(f"target metadata missing: {root}")
        closure = target.get("directed_closure")
        spec = target.get("primary_spec")
        if (
            not isinstance(closure, list)
            or not closure
            or any(not isinstance(item, str) or not item for item in closure)
            or not isinstance(spec, str)
            or not spec
        ):
            raise PreparationError(f"target closure invalid: {root}")
        selected.update(closure)
        selected.add(spec)
        root_specs.add(spec)

    pending = list(selected)
    while pending:
        name = pending.pop()
        record = declarations.get(name)
        if not isinstance(record, dict):
            raise PreparationError(f"declaration evidence missing: {name}")
        dependencies = record.get("dependencies")
        proof_dependencies = record.get("proof_dependencies")
        if (
            not isinstance(dependencies, list)
            or not isinstance(proof_dependencies, list)
            or any(not isinstance(item, str) or not item for item in dependencies)
            or any(not isinstance(item, str) or not item for item in proof_dependencies)
        ):
            raise PreparationError(f"declaration edges invalid: {name}")
        for dependency in dependencies:
            if dependency not in selected:
                selected.add(dependency)
                pending.append(dependency)
    forbidden = [
        name
        for name in selected
        if declarations[name]["kind"] == "proof_only"
        or (declarations[name]["kind"] == "statement" and name not in root_specs)
    ]
    if forbidden:
        raise PreparationError(
            "proof-only or lower specification selected: " + ",".join(sorted(forbidden))
        )
    return selected, root_specs


def _record_path(record: Any, name: str) -> str:
    if not isinstance(record, dict):
        raise PreparationError(f"declaration evidence missing: {name}")
    path = _safe_path(record.get("path"))
    lines = record.get("lines")
    if (
        not isinstance(lines, list)
        or len(lines) != 2
        or any(type(value) is not int for value in lines)
        or lines[0] <= 0
        or lines[1] < lines[0]
    ):
        raise PreparationError(f"declaration source span invalid: {name}")
    return path


def _redact_proof(lines: list[str], name: str) -> list[str]:
    text = "".join(lines)
    marker = ":= by"
    boundary = text.find(marker)
    if boundary < 0:
        raise PreparationError(f"root statement proof boundary missing: {name}")
    return (text[:boundary] + marker + "\n  sorry\n").splitlines(keepends=True)


def _attribute_start(lines: list[str], start: int) -> int:
    cursor = start
    while cursor > 0:
        previous = lines[cursor - 1].strip()
        if (
            previous.startswith("@[")
            or previous.startswith("--")
            or (
                previous.startswith("set_option ")
                and previous.endswith(" in")
            )
        ):
            cursor -= 1
            continue
        break
    return cursor


def _generated_core_source(
    lines: list[str],
    units: list[tuple[int, int, list[tuple[int, int, str]]]],
    selected: set[str],
    path: str,
) -> list[str]:
    namespace_indexes = [
        index
        for index, line in enumerate(lines)
        if line.startswith("namespace ")
    ]
    if not namespace_indexes:
        raise PreparationError(f"generated core namespace mismatch: {path}")
    namespace_index = namespace_indexes[0]
    namespace = lines[namespace_index].strip().removeprefix("namespace ")
    rendered = [*lines[: namespace_index + 1], "\n"]
    current_nested: list[str] = []
    for start, end, members in units:
        if {name for _, _, name in members} & selected:
            active: list[str] = []
            for line in lines[:start]:
                if line.startswith("namespace "):
                    active.append(line.strip().removeprefix("namespace "))
                elif line.startswith("end "):
                    ended = line.strip().removeprefix("end ")
                    if active and active[-1] == ended:
                        active.pop()
            nested = active[1:] if active and active[0] == namespace else active
            shared = 0
            while (
                shared < len(current_nested)
                and shared < len(nested)
                and current_nested[shared] == nested[shared]
            ):
                shared += 1
            for opened in reversed(current_nested[shared:]):
                rendered.append(f"end {opened}\n")
            for opened in nested[shared:]:
                rendered.append(f"namespace {opened}\n")
            current_nested = nested
            block_start = _attribute_start(lines, start)
            rendered.extend(lines[block_start:end])
            if rendered and rendered[-1].strip():
                rendered.append("\n")
    for opened in reversed(current_nested):
        rendered.append(f"end {opened}\n")
    rendered.append(f"end {namespace}\n")
    return rendered


def _render_source(
    source: Path,
    path: str,
    records: list[tuple[str, dict[str, Any]]],
    selected: set[str],
    root_specs: set[str],
    retained_modules: set[str],
    indexed_modules: set[str],
    required_imports: set[str],
) -> bytes:
    lines = _source_file(source, path).read_text(encoding="utf-8").splitlines(
        keepends=True
    )
    spans: list[tuple[int, int, str]] = []
    for name, record in records:
        _record_path(record, name)
        start, end = record["lines"]
        if end > len(lines):
            raise PreparationError(f"declaration source span invalid: {name}")
        spans.append((start - 1, end, name))
    spans.sort(key=lambda item: (item[0], -item[1], item[2]))

    # Lean reports generated projections, structure fields, and local proof
    # declarations inside the owning top-level declaration. Treat every
    # maximal source span as one materialization unit while preserving all
    # declaration identities for dependency selection and provenance.
    units: list[tuple[int, int, list[tuple[int, int, str]]]] = []
    for start, end, name in spans:
        if units and start < units[-1][1]:
            unit_start, unit_end, members = units[-1]
            if start < unit_start or end > unit_end:
                raise PreparationError(f"crossing declaration spans: {path}")
            members.append((start, end, name))
            continue
        units.append((start, end, [(start, end, name)]))

    if path in GENERATED_CORE_FILES:
        lines = _generated_core_source(lines, units, selected, path)
    else:
        for start, end, members in reversed(units):
            names = {name for _, _, name in members}
            retained_roots = sorted(names & root_specs)
            if not names & selected:
                lines[_attribute_start(lines, start):end] = []
            elif retained_roots:
                if len(retained_roots) != 1:
                    raise PreparationError(f"overlapping root statements: {path}")
                root = retained_roots[0]
                root_spans = {
                    (member_start, member_end)
                    for member_start, member_end, name in members
                    if name == root
                }
                if root_spans != {(start, end)}:
                    raise PreparationError(f"nested root statement span: {root}")
                lines[start:end] = _redact_proof(lines[start:end], root)

    local_names: dict[str, set[str]] = {}
    for name, _ in records:
        leaf = name.removeprefix("probe:").rsplit(".", 1)[-1]
        local_names.setdefault(leaf, set()).add(name)

    filtered: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import "):
            imported = stripped.removeprefix("import ").strip()
            if imported in indexed_modules and imported not in retained_modules:
                continue
        if stripped.startswith("attribute ") and "]" in stripped:
            targets = stripped.split("]", 1)[1].removesuffix(" in").split()
            referenced = {
                name
                for target in targets
                for leaf, names in local_names.items()
                if target == leaf or target.endswith(f".{leaf}")
                for name in names
            }
            if referenced and not referenced & selected:
                continue
        filtered.append(line)
    existing_imports = {
        line.strip().removeprefix("import ").strip()
        for line in filtered
        if line.strip().startswith("import ")
    }
    missing_imports = sorted(required_imports - existing_imports)
    if missing_imports:
        insertion = next(
            (
                index
                for index, line in enumerate(filtered)
                if line.strip().startswith("import ")
            ),
            0,
        )
        filtered[insertion:insertion] = [
            f"import {module}\n" for module in missing_imports
        ]
    return "".join(filtered).encode("utf-8")


def _run_build(project: Path) -> None:
    packages = os.environ.get("AUTOFV_LAKE_PACKAGES_DIR")
    if packages:
        packages_path = Path(packages).resolve(strict=True)
        if not packages_path.is_dir():
            raise PreparationError("Lake packages cache is not a directory")
        lake_dir = project / ".lake"
        lake_dir.mkdir()
        (lake_dir / "packages").symlink_to(packages_path, target_is_directory=True)
    build_log = os.environ.get("AUTOFV_BUILD_LOG")
    try:
        completed = subprocess.run(
            ("lake", "build"),
            cwd=project,
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise PreparationError(f"prepared project build failed: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        output = (exc.stdout or b"") + (exc.stderr or b"")
        if build_log:
            Path(build_log).write_bytes(output)
        detail = output.decode("utf-8", errors="replace")[-8_000:].strip()
        suffix = f"\n{detail}" if detail else ""
        raise PreparationError(f"prepared project build failed{suffix}") from exc
    if build_log:
        Path(build_log).write_bytes(
            (completed.stdout or b"") + (completed.stderr or b"")
        )


def _tree_entries(root: Path, *, ignore_git: bool = False) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ignore_git and ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise PreparationError(f"symlink rejected: {relative.as_posix()}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PreparationError(f"unsafe file kind: {relative.as_posix()}")
        raw = path.read_bytes()
        entries.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256(raw),
                "size": len(raw),
            }
        )
    return entries


def source_tree_sha256(source: str | Path) -> str:
    """Hash regular source bytes canonically, excluding only Git metadata."""
    root = Path(source).resolve(strict=True)
    if not root.is_dir():
        raise PreparationError("source must be a directory")
    return _sha256(_canonical_bytes(_tree_entries(root, ignore_git=True)))


def _scan_prepared(root: Path) -> None:
    for entry in _tree_entries(root):
        raw = (root / entry["path"]).read_bytes()
        if SECRET_PATTERN.search(raw):
            raise PreparationError(f"secret-like content rejected: {entry['path']}")
        lowered = raw.lower()
        if any(marker in lowered for marker in SPOILER_MARKERS):
            raise PreparationError(f"spoiler content rejected: {entry['path']}")


def _publication_readme(
    mode: str, source_identity: dict[str, Any], target_count: int
) -> str:
    return f"""# AutoFV Dalek prepared baseline

This repository is a reproducible Lean experiment input prepared from the pinned
`curve25519-dalek-lean-verify` source. Target proof bodies are intentionally
replaced with `sorry`; exact targets are listed in `autofv.json`.

- Shape: `{mode}`
- Targets: {target_count}
- Source revision: `{source_identity["revision"]}`
- Source tree SHA-256: `{source_identity["tree_sha256"]}`
- Verification command: `lake build`

This artifact supports scoped functional-correctness experiments. It is not a
cryptographic-security, side-channel, memory-safety, or implementation audit.
Builds may report disclosed warnings from trusted mathematics or pinned
external dependencies; those warnings are not target solutions.

## Licensing

The prepared Lean project is distributed under `LICENSE`. Translated
`curve25519-dalek` material retains its upstream notice in
`LICENSES/curve25519-dalek-BSD-3-Clause.txt`.
"""


def _materialize(
    stage: Path,
    source: Path,
    support_paths: set[str],
    selected_paths: set[str],
    records_by_path: dict[str, list[tuple[str, dict[str, Any]]]],
    selected: set[str],
    root_specs: set[str],
    retained_modules: set[str],
    indexed_modules: set[str],
    required_imports_by_path: dict[str, set[str]],
    targets_manifest: list[dict[str, str]],
    mode: str,
    source_identity: dict[str, Any],
) -> None:
    for path in sorted(support_paths):
        destination = stage / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_source_file(source, path).read_bytes())
    for source_name, destination_name in PUBLICATION_LICENSES:
        destination = stage / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(_source_file(source, source_name).read_bytes())
    for path in sorted(selected_paths):
        destination = stage / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            _render_source(
                source,
                path,
                records_by_path[path],
                selected,
                root_specs,
                retained_modules,
                indexed_modules,
                required_imports_by_path.get(path, set()),
            )
        )
    root_modules = sorted(
        module
        for path, module in (
            (
                path,
                ".".join(PurePosixPath(path).with_suffix("").parts),
            )
            for path in selected_paths
            if path.endswith(".lean")
        )
        if path != "Curve25519Dalek.lean"
    )
    (stage / "Curve25519Dalek.lean").write_text(
        "".join(f"import {module}\n" for module in root_modules),
        encoding="utf-8",
    )
    (stage / "autofv.json").write_bytes(
        _canonical_bytes(
            {
                "schema": "autofv/v1",
                "targets": targets_manifest,
                "verify": ["lake", "build"],
            }
        )
    )
    (stage / "README.md").write_text(
        _publication_readme(mode, source_identity, len(targets_manifest)),
        encoding="utf-8",
    )


def _same_tree(path: Path, expected: list[dict[str, Any]]) -> bool:
    return path.is_dir() and not path.is_symlink() and _tree_entries(path) == expected


def _write_once(path: Path, raw: bytes) -> None:
    if path.is_symlink():
        raise PreparationError(f"different-byte replacement refused: {path}")
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
            raise PreparationError(f"different-byte replacement refused: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(raw)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _destination_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path.parent.resolve(strict=False) / path.name


def prepare_dalek(
    source: str | Path,
    target_report: str | Path,
    probe_identities: str | Path,
    mode: str,
    output: str | Path,
    manifest: str | Path,
) -> dict[str, Any]:
    """Prepare one explicit pinned Dalek source tree in ``full`` or ``small`` mode."""
    if mode not in {"full", "small"}:
        raise PreparationError("preparation mode must be full or small")
    source_path = Path(source).resolve(strict=True)
    if not source_path.is_dir():
        raise PreparationError("source must be a directory")
    report_path = Path(target_report).resolve(strict=True)
    identities_path = Path(probe_identities).resolve(strict=True)
    output_path = _destination_path(output)
    manifest_path = _destination_path(manifest)
    if output_path.is_relative_to(source_path) or manifest_path.is_relative_to(source_path):
        raise PreparationError("preparation output cannot modify solved source")
    if manifest_path == output_path or manifest_path.is_relative_to(output_path):
        raise PreparationError("manifest must be outside prepared output")

    report_raw, report = _read_json(report_path, "target report")
    identities_raw, identities = _read_json(identities_path, "probe identities")
    targets, declarations, files = _validate_inputs(report, identities)
    if source_tree_sha256(source_path) != identities["source"]["tree_sha256"]:
        raise PreparationError("provenance source tree mismatch")
    roots = _selected_roots(report["graph_tops"], targets, mode)
    selected, root_specs = _selected_declarations(roots, targets, declarations)

    records_by_path: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for name, record in declarations.items():
        path = _record_path(record, name)
        records_by_path.setdefault(path, []).append((name, record))
    selected_paths = {_record_path(declarations[name], name) for name in selected}
    support_paths = {_safe_path(name) for name in files}
    modules_by_path = {
        path: ".".join(PurePosixPath(path).with_suffix("").parts)
        for path in records_by_path
        if path.endswith(".lean")
    }
    retained_modules = {
        modules_by_path[path]
        for path in selected_paths
        if path in modules_by_path
    }
    retained_modules.update(
        ".".join(PurePosixPath(path).with_suffix("").parts)
        for path in support_paths
        if path.endswith(".lean")
    )
    indexed_modules = set(modules_by_path.values())
    for path in source_path.rglob("*.lean"):
        if path.is_symlink() or not path.is_file():
            raise PreparationError("unsafe local Lean module")
        indexed_modules.add(
            ".".join(path.relative_to(source_path).with_suffix("").parts)
        )
    required_imports_by_path: dict[str, set[str]] = {}
    declaration_paths = {
        name: _record_path(record, name)
        for name, record in declarations.items()
    }
    for name in selected:
        record = declarations[name]
        path = declaration_paths[name]
        if not path.endswith(".lean"):
            continue
        for dependency in [
            *record["dependencies"],
            *record["proof_dependencies"],
        ]:
            if dependency not in selected:
                continue
            dependency_path = declaration_paths[dependency]
            if dependency_path == path or not dependency_path.endswith(".lean"):
                continue
            required_imports_by_path.setdefault(path, set()).add(
                ".".join(PurePosixPath(dependency_path).with_suffix("").parts)
            )
    targets_manifest = [
        {
            "function": root,
            "spec": targets[root]["primary_spec"].removeprefix("probe:"),
        }
        for root in roots
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    stages = [
        Path(tempfile.mkdtemp(prefix=".autofv-prep-", dir=output_path.parent))
        for _ in range(2)
    ]
    build_stage = Path(
        tempfile.mkdtemp(prefix=".autofv-build-", dir=output_path.parent)
    )
    created_output = False
    try:
        for stage in stages:
            _materialize(
                stage,
                source_path,
                support_paths,
                selected_paths,
                records_by_path,
                selected,
                root_specs,
                retained_modules,
                indexed_modules,
                required_imports_by_path,
                targets_manifest,
                mode,
                identities["source"],
            )
            _scan_prepared(stage)
        entries = _tree_entries(stages[0])
        if _tree_entries(stages[1]) != entries:
            raise PreparationError("reproducibility tree mismatch")
        shutil.copytree(stages[0], build_stage, dirs_exist_ok=True)
        _run_build(build_stage)
        body = {
            "schema": MANIFEST_SCHEMA,
            "mode": mode,
            "source": identities.get("source"),
            "probes": identities.get("probes"),
            "target_report_sha256": _sha256(report_raw),
            "probe_identities_sha256": _sha256(identities_raw),
            "roots": roots,
            "closures": {
                root: targets[root]["directed_closure"] for root in roots
            },
            "retained_declarations": sorted(selected),
            "files": entries,
            "tree_sha256": _sha256(_canonical_bytes(entries)),
            "gates": {
                "build": "passed",
                "provenance": "passed",
                "reproducibility": "passed",
                "secret_scan": "passed",
                "spoiler_scan": "passed",
                "symlink_scan": "passed",
            },
        }
        rendered = {**body, "manifest_sha256": _sha256(_canonical_bytes(body))}
        manifest_raw = _canonical_bytes(rendered)

        if output_path.is_symlink() or (
            output_path.exists() and not _same_tree(output_path, entries)
        ):
            raise PreparationError(f"different-byte replacement refused: {output_path}")
        if manifest_path.is_symlink() or (
            manifest_path.exists()
            and (not manifest_path.is_file() or manifest_path.read_bytes() != manifest_raw)
        ):
            raise PreparationError(f"different-byte replacement refused: {manifest_path}")
        if not output_path.exists():
            os.replace(stages[0], output_path)
            created_output = True
        _write_once(manifest_path, manifest_raw)
        return rendered
    except Exception:
        if created_output:
            shutil.rmtree(output_path, ignore_errors=True)
        raise
    finally:
        for stage in [*stages, build_stage]:
            shutil.rmtree(stage, ignore_errors=True)


def validate_publication_receipt(path: str | Path) -> dict[str, Any]:
    """Validate that both observed publications equal their approved identities."""
    _, receipt = _read_json(Path(path).resolve(strict=True), "publication receipt")
    if set(receipt) != {"schema", "approved", "observed"} or receipt.get(
        "schema"
    ) != PUBLICATION_SCHEMA:
        raise PreparationError("publication receipt schema mismatch")
    approved = receipt.get("approved")
    observed = receipt.get("observed")
    if (
        not isinstance(approved, dict)
        or not isinstance(observed, dict)
        or set(approved) != {"full", "small"}
        or set(observed) != {"full", "small"}
    ):
        raise PreparationError("publication receipt modes mismatch")

    for mode in ("full", "small"):
        expected = approved[mode]
        actual = observed[mode]
        identity_fields = {
            "repository",
            "tag",
            "manifest_sha256",
            "tree_sha256",
        }
        if (
            not isinstance(expected, dict)
            or set(expected) != identity_fields
            or not isinstance(actual, dict)
            or set(actual) != identity_fields | {"commit", "tag_object"}
            or not isinstance(expected["repository"], str)
            or not expected["repository"]
            or not isinstance(expected["tag"], str)
            or not expected["tag"]
            or not _is_hash(expected["manifest_sha256"])
            or not _is_hash(expected["tree_sha256"])
            or not _is_hash(actual["commit"], frozenset({40, 64}))
            or not _is_hash(actual["tag_object"], frozenset({40, 64}))
            or {key: actual[key] for key in identity_fields} != expected
        ):
            raise PreparationError(f"publication {mode} identity mismatch")
    if approved["full"]["repository"] == approved["small"]["repository"]:
        raise PreparationError("publication repositories must be distinct")
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m autofv.prepare_dalek")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target-report", required=True)
    parser.add_argument("--probe-identities", required=True)
    parser.add_argument("--mode", required=True, choices=("full", "small"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    prepare_dalek(
        args.source,
        args.target_report,
        args.probe_identities,
        args.mode,
        args.output,
        args.manifest,
    )


if __name__ == "__main__":
    main()
