"""Deterministic, Dalek-specific preparation of spoiler-free Lean inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


SMALL_ROOT_MARKER = "curve25519_dalek.scalar.Scalar.from_canonical_bytes"
REPORT_SCHEMA = "target-report/v1"
IDENTITIES_SCHEMA = "autofv-dalek-probe-identities/v1"
MANIFEST_SCHEMA = "preparation-manifest/v1"


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
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationError(f"invalid {label}") from exc
    if not isinstance(value, dict):
        raise PreparationError(f"invalid {label}")
    return raw, value


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
    if report.get("schema") != REPORT_SCHEMA:
        raise PreparationError("target report schema mismatch")
    tops = report.get("graph_tops")
    targets = report.get("declarations")
    if (
        not isinstance(tops, list)
        or not tops
        or tops != sorted(set(tops))
        or not isinstance(targets, dict)
        or set(targets) != set(tops)
    ):
        raise PreparationError("target report graph tops mismatch")
    if identities.get("schema") != IDENTITIES_SCHEMA:
        raise PreparationError("probe identities schema mismatch")
    declarations = identities.get("declarations")
    files = identities.get("files")
    if not isinstance(declarations, dict) or not isinstance(files, dict):
        raise PreparationError("probe identities declaration index missing")
    return targets, declarations, files


def _selected_roots(tops: list[str], mode: str) -> list[str]:
    if mode == "full":
        return tops
    matches = [name for name in tops if SMALL_ROOT_MARKER in name]
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
    boundary = text.rfind(marker)
    if boundary < 0:
        raise PreparationError(f"root statement proof boundary missing: {name}")
    return (text[:boundary] + marker + "\n  sorry\n").splitlines(keepends=True)


def _render_source(
    source: Path,
    path: str,
    records: list[tuple[str, dict[str, Any]]],
    selected: set[str],
    root_specs: set[str],
    retained_modules: set[str],
    indexed_modules: set[str],
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
    spans.sort()
    if any(right[0] < left[1] for left, right in zip(spans, spans[1:])):
        raise PreparationError(f"overlapping declaration spans: {path}")

    for start, end, name in reversed(spans):
        if name not in selected:
            lines[start:end] = []
        elif name in root_specs:
            lines[start:end] = _redact_proof(lines[start:end], name)

    filtered: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import "):
            imported = stripped.removeprefix("import ").strip()
            if imported in indexed_modules and imported not in retained_modules:
                continue
        filtered.append(line)
    return "".join(filtered).encode("utf-8")


def _run_build(project: Path) -> None:
    try:
        subprocess.run(
            ("lake", "build"),
            cwd=project,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PreparationError("prepared project build failed") from exc


def _tree_entries(root: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(path.read_bytes()),
            "size": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def _write_once(path: Path, raw: bytes) -> None:
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
    output_path = Path(output).resolve()
    manifest_path = Path(manifest).resolve()
    if output_path.is_relative_to(source_path) or manifest_path.is_relative_to(source_path):
        raise PreparationError("preparation output cannot modify solved source")
    if output_path.exists():
        raise PreparationError(f"different-byte replacement refused: {output_path}")

    report_raw, report = _read_json(report_path, "target report")
    identities_raw, identities = _read_json(identities_path, "probe identities")
    targets, declarations, files = _validate_inputs(report, identities)
    roots = _selected_roots(report["graph_tops"], mode)
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
    retained_modules = {modules_by_path[path] for path in selected_paths if path in modules_by_path}
    indexed_modules = set(modules_by_path.values())

    output_path.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".autofv-prep-", dir=output_path.parent))
    try:
        for path in sorted(support_paths):
            destination = stage / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(_source_file(source_path, path).read_bytes())
        for path in sorted(selected_paths):
            destination = stage / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(
                _render_source(
                    source_path,
                    path,
                    records_by_path[path],
                    selected,
                    root_specs,
                    retained_modules,
                    indexed_modules,
                )
            )
        targets_manifest = [
            {
                "function": root,
                "spec": targets[root]["primary_spec"].removeprefix("probe:"),
            }
            for root in roots
        ]
        (stage / "autofv.json").write_bytes(
            _canonical_bytes(
                {
                    "schema": "autofv/v1",
                    "targets": targets_manifest,
                    "verify": ["lake", "build"],
                }
            )
        )
        _run_build(stage)
        entries = _tree_entries(stage)
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
            "gates": {"build": "passed"},
        }
        rendered = {**body, "manifest_sha256": _sha256(_canonical_bytes(body))}
        manifest_raw = _canonical_bytes(rendered)
        os.replace(stage, output_path)
        _write_once(manifest_path, manifest_raw)
        return rendered
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


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
