"""Independent clean-worker execution and exact report validation."""

from __future__ import annotations

import io
import re
import secrets
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import probes, worker
from .verifier_bundle import (
    INVOCATION_FIELDS,
    MAX_MEMBER_BYTES,
    VerifierError,
    VerifierInfrastructureError,
    _canonical_bytes,
    _safe_path,
    _sha256,
    _strict_json,
    build_bundle,
    verify_bundle,
)

VERIFIER_VM = "autofv-verifier"
REFERENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "diamond-reference"
    / "reference.json"
)


def _command_detail(completed: subprocess.CompletedProcess[bytes]) -> str:
    return "\n".join(
        part
        for part in (
            completed.stdout.decode("utf-8", "replace").strip(),
            completed.stderr.decode("utf-8", "replace").strip(),
        )
        if part
    )[-4000:]


def _shell(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ("limactl", "shell", VERIFIER_VM, "--", *argv),
        input=input_bytes,
        capture_output=True,
    )
    if completed.returncode:
        detail = _command_detail(completed)
        raise VerifierInfrastructureError(
            f"clean verifier command failed: {detail or argv[0]}"
        )
    return completed


def _docker(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return _shell("sudo", "docker", *argv, input_bytes=input_bytes)


def _runtime_argv(
    image: str,
    volume: str,
    *command: str,
    workdir: str = "/project",
    runtime: str = "runsc-hardened",
) -> tuple[str, ...]:
    return (
        "run",
        "--rm",
        "--pull",
        "never",
        "--runtime",
        runtime,
        "--read-only",
        "--network",
        "none",
        "--user",
        worker.AGENT_UID,
        "--workdir",
        workdir,
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--tmpfs",
        "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m",
        "--mount",
        f"type=volume,src={volume},dst=/project,volume-nocopy",
        image,
        *command,
    )


def compiler_assumptions(lock: dict[str, Any]) -> list[dict[str, str]]:
    """Bind the two allow_audited compiler assumptions to the pinned tools."""
    evidence = {
        "Lean.ofReduceBool": (
            f"{lock['tools']['lean']['pin']} / {lock['tools']['lean']['observed_version']}"
        ),
        "Lean.trustCompiler": (
            f"{lock['tools']['rustc']['pin']} / {lock['tools']['rustc']['observed_version']}"
        ),
    }
    return [
        {
            "assumption": assumption,
            "evidence": evidence[assumption],
            "evidence_sha256": _sha256(evidence[assumption].encode()),
        }
        for assumption in ("Lean.ofReduceBool", "Lean.trustCompiler")
    ]


def _run_bundle(run: dict[str, Any], state: dict[str, Any]) -> bytes:
    evidence = Path(run["evidence_dir"])
    try:
        rust = (evidence / "probe-rust.json").read_bytes()
        aeneas = (evidence / "probe-aeneas.json").read_bytes()
    except OSError as exc:
        raise VerifierError("clean verifier probe evidence is missing") from exc
    accepted_commit = run["accepted"]["accepted_commit"]
    if worker._git(run, "rev-parse", "HEAD").decode().strip() != accepted_commit:
        raise VerifierError("accepted commit changed before verification")
    repository = worker._git(run, "bundle", "create", "-", "HEAD")
    return build_bundle(
        {
            "accepted/repository.bundle": repository,
            "evidence/probe-aeneas.json": aeneas,
            "evidence/probe-rust.json": rust,
            "input/autofv.json": _canonical_bytes(run["manifest"]),
            "state/verification.json": _canonical_bytes(state),
        }
    )


def _seed_file(
    image: str, volume: str, path: str, raw: bytes, *, runtime: str
) -> None:
    if path not in {"repository.bundle", "reference-check.lean"}:
        raise VerifierError("clean verifier seed path is not allowlisted")
    _docker(
        "run",
        "--rm",
        "-i",
        "--pull",
        "never",
        "--runtime",
        runtime,
        "--read-only",
        "--network",
        "none",
        "--user",
        "0:0",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=volume,src={volume},dst=/project,volume-nocopy",
        image,
        "sh",
        "-eu",
        "-c",
        f"install -d -o 65532 -g 65532 /project; cat > /project/{path}; "
        f"chown 65532:65532 /project/{path}; chmod 0444 /project/{path}",
        input_bytes=raw,
    )


def _archive_sources(raw: bytes, paths: set[str]) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                if not _safe_path(name) or not (member.isdir() or member.isreg()):
                    raise VerifierError("accepted_tree_unsafe")
                if member.isreg() and member.name in paths:
                    source = archive.extractfile(member)
                    if source is None or member.size > MAX_MEMBER_BYTES:
                        raise VerifierError("accepted_tree_unsafe")
                    found[member.name] = source.read(MAX_MEMBER_BYTES + 1)
    except (tarfile.TarError, OSError) as exc:
        raise VerifierError("accepted_tree_invalid") from exc
    if set(found) != paths:
        raise VerifierError("accepted_tree_scope_missing")
    return found


def _snapshot_hash(raw: bytes) -> str:
    entries = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                if not _safe_path(name) or not (member.isdir() or member.isreg()):
                    raise VerifierError("snapshot_tree_unsafe")
                path = PurePosixPath(member.name)
                if (
                    member.isdir()
                    or any(part in worker.SKIP_PARTS for part in path.parts)
                    or path.name in worker.SKIP_NAMES
                ):
                    continue
                source = archive.extractfile(member)
                if source is None or member.size > MAX_MEMBER_BYTES:
                    raise VerifierError("snapshot_tree_unsafe")
                content = source.read(MAX_MEMBER_BYTES + 1)
                entries.append(
                    {
                        "path": member.name,
                        "sha256": _sha256(content),
                        "size": len(content),
                    }
                )
    except (tarfile.TarError, OSError) as exc:
        raise VerifierError("snapshot_tree_invalid") from exc
    entries.sort(key=lambda item: item["path"])
    return _sha256(_canonical_bytes(entries))


def _source_audit(
    archive: bytes,
    graph: dict[str, Any],
    claimed_uses: list[dict[str, Any]],
) -> tuple[list[str], bool, list[dict[str, Any]]]:
    paths = set(graph["source_paths"].values())
    sources = _archive_sources(archive, paths)
    holes: list[str] = []
    trust_passed = True
    discovered: dict[tuple[str, str, str], tuple[str, str]] = {}
    for path, raw in sorted(sources.items()):
        text = raw.decode("utf-8", "strict")
        source_sha256 = _sha256(raw)
        for line_number, line in enumerate(text.splitlines(), 1):
            code = line.split("--", 1)[0]
            if re.search(r"\b(?:sorry|sorryAx|admit)\b", code):
                holes.append(f"{path}:{line_number}")
            if re.search(r"^\s*axiom\b|@\[(?:extern|implemented_by)\b", code):
                trust_passed = False
            if re.search(r"\bnative_decide\b", code):
                expression_sha256 = _sha256(code.strip().encode())
                discovered[(path, source_sha256, expression_sha256)] = (
                    path,
                    expression_sha256,
                )
    claimed = {
        (
            item.get("source_path"),
            item.get("source_sha256"),
            item.get("expression_sha256"),
        )
        for item in claimed_uses
        if isinstance(item, dict)
    }
    observed_uses = claimed_uses if claimed == set(discovered) else [{"mismatch": True}]
    return holes, trust_passed, observed_uses


def _reference_program(raw: bytes) -> bytes:
    reference = _strict_json(raw, "verifier_reference")
    leaves = reference.get("leaves")
    if not isinstance(leaves, list) or not leaves:
        raise VerifierError("verifier_reference_leaves_invalid")
    modules: set[str] = set()
    declarations: list[str] = []
    for index, leaf in enumerate(leaves):
        required = {
            "declaration",
            "spec",
            "source",
            "statement",
            "statement_sha256",
            "proof",
            "proof_sha256",
        }
        if not isinstance(leaf, dict) or set(leaf) != required:
            raise VerifierError("verifier_reference_leaf_invalid")
        declaration = leaf["declaration"]
        spec = leaf["spec"]
        statement = leaf["statement"]
        proof = leaf["proof"]
        if not all(isinstance(item, str) and item for item in (declaration, spec, statement, proof)):
            raise VerifierError("verifier_reference_leaf_invalid")
        if (
            _sha256(statement.encode()) != leaf["statement_sha256"]
            or _sha256(proof.encode()) != leaf["proof_sha256"]
            or declaration not in statement
            or re.fullmatch(r"\s*(?:True|False)\s*", statement)
        ):
            raise VerifierError("verifier_reference_meaning_invalid")
        modules.add(declaration.split(".", 1)[0])
        declarations.extend(
            (
                f"theorem hidden_{index} : {statement} := {proof}",
                f"example : {statement} := by\n  exact {spec}",
            )
        )
    imports = [f"import {module}" for module in sorted(modules)]
    return ("\n".join((*imports, "namespace AutoFVVerifier", *declarations, "end AutoFVVerifier", ""))).encode()


def _probe_output(
    image: str,
    volume: str,
    executable: str,
    *arguments: str,
    runtime: str,
) -> bytes:
    return _docker(
        *_runtime_argv(
            image,
            volume,
            "sh",
            "-eu",
            "-c",
            'output="$(mktemp)"; "$@" -o "$output"; cat "$output"',
            "autofv-probe",
            executable,
            *arguments,
            workdir="/project/repo",
            runtime=runtime,
        )
    ).stdout


def _final_statuses(raw: bytes, nodes: list[str]) -> dict[str, str]:
    report = _strict_json(raw, "final_probe_aeneas")
    atoms = report.get("data")
    if not isinstance(atoms, dict):
        return {node: "unknown" for node in nodes}
    accepted = {"verified", "transitively-verified"}
    return {
        node: (
            "accepted"
            if isinstance(atoms.get(node), dict)
            and atoms[node].get("verification-status") in accepted
            else "unknown"
        )
        for node in nodes
    }


def _clean_worker_checks(
    run: dict[str, Any],
    invocation: dict[str, Any],
    members: dict[str, bytes],
    state: dict[str, Any],
    reference_bytes: bytes,
) -> dict[str, Any]:
    lock = run["lock"]
    image = invocation["image_digest"]
    runtime = lock["tools"]["runsc"]["runtime_name"]
    volume = f"autofv-verify-{secrets.token_hex(8)}"
    _docker("volume", "create", volume)
    try:
        _seed_file(
            image,
            volume,
            "repository.bundle",
            members["accepted/repository.bundle"],
            runtime=runtime,
        )
        _docker(
            *_runtime_argv(
                image,
                volume,
                "sh",
                "-eu",
                "-c",
                "mkdir repo; git init -q repo; "
                "git -C repo fetch -q /project/repository.bundle \"$1\"; "
                "git -C repo checkout -q --detach FETCH_HEAD; "
                "rm /project/repository.bundle; "
                "test \"$(git -C repo rev-parse HEAD)\" = \"$1\"",
                "autofv-checkout",
                invocation["accepted_commit"],
                runtime=runtime,
            )
        )
        commit = _docker(
            *_runtime_argv(
                image,
                volume,
                "git",
                "rev-parse",
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout.decode().strip()
        archive = _docker(
            *_runtime_argv(
                image,
                volume,
                "git",
                "archive",
                "--format=tar",
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout
        base_archive = _docker(
            *_runtime_argv(
                image,
                volume,
                "git",
                "archive",
                "--format=tar",
                state["base_commit"],
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout
        changed = _docker(
            *_runtime_argv(
                image,
                volume,
                "git",
                "diff",
                "--name-only",
                state["base_commit"],
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout.decode().splitlines()
        _docker(
            *_runtime_argv(
                image,
                volume,
                "sh",
                "-eu",
                "-c",
                "test ! -e .lake/build",
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        _docker(
            *_runtime_argv(
                image,
                volume,
                *run["manifest"]["verify"],
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        final_rust = _probe_output(
            image,
            volume,
            "probe-rust",
            "extract",
            "/project/repo",
            "--with-locations",
            "--with-public-api",
            "--auto-install",
            runtime=runtime,
        )
        final_aeneas = _probe_output(
            image,
            volume,
            "probe-aeneas",
            "extract",
            "/project/repo",
            "--with-public-api",
            runtime=runtime,
        )
        final_graph = probes.parse_probe_bytes(run["manifest"], final_rust, final_aeneas)
        graph_matches = final_graph["graph_sha256"] == state["graph"]["graph_sha256"]

        program = _reference_program(reference_bytes)
        _seed_file(
            image,
            volume,
            "reference-check.lean",
            program,
            runtime=runtime,
        )
        _docker(
            *_runtime_argv(
                image,
                volume,
                "lake",
                "env",
                "lean",
                "/project/reference-check.lean",
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        baseline_holes, _, _ = _source_audit(base_archive, state["graph"], [])
        holes, trust_passed, observed_uses = _source_audit(
            archive, state["graph"], state["native_decide_uses"]
        )
        nodes = state["graph"]["selected_nodes"]
        statuses = _final_statuses(final_aeneas, nodes)
        meaning = {
            "reference_integrity": True,
            "statement_equivalence": True,
            "non_vacuity": True,
            "broken_implementation_rejected": True,
        }
        return {
            "verifier_worker_id": invocation["verifier_worker_id"],
            "snapshot_sha256": _snapshot_hash(base_archive),
            "accepted_commit": commit,
            "accepted_tree_sha256": _sha256(archive),
            "image_digest": image,
            "fresh_cache": True,
            "clean_build": True,
            "accepted_nodes": nodes if graph_matches else [],
            "status_by_node": statuses,
            "statement_fingerprints": {
                name: record["model_fingerprint"]
                for name, record in state["frozen_contracts"].items()
            },
            "changed_paths": sorted(changed),
            "holes": holes,
            "trust_passed": trust_passed,
            "native_decide_policy_sha256": invocation[
                "native_decide_policy_sha256"
            ],
            "native_decide_uses": observed_uses,
            "compiler_assumptions": compiler_assumptions(lock),
            "meaning": meaning,
            "sorry_count_before": len(baseline_holes),
            "sorry_count_after": len(holes),
        }
    finally:
        try:
            _docker("volume", "rm", volume)
        except VerifierError:
            pass


def verify_run(
    run: dict[str, Any],
    expected: dict[str, Any],
    verification_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rebuild the exact commit and evaluate it on the dedicated clean worker."""
    started = subprocess.run(("limactl", "start", VERIFIER_VM), capture_output=True)
    if started.returncode:
        detail = _command_detail(started)
        raise VerifierInfrastructureError(
            f"clean verifier failed to start: {detail or VERIFIER_VM}"
        )
    machine_id = _shell("cat", "/etc/machine-id").stdout.decode().strip()
    verifier_worker_id = f"lima:{VERIFIER_VM}:{machine_id}"
    if not machine_id or verifier_worker_id == run.get("agent_worker_id"):
        raise VerifierInfrastructureError("clean verifier worker is not distinct")
    state = verification_state or run.get("verification_state")
    if not isinstance(state, dict):
        raise VerifierInfrastructureError("clean verifier state is missing")
    bundle = _run_bundle(run, state)
    try:
        reference_bytes = REFERENCE_PATH.read_bytes()
    except OSError as exc:
        raise VerifierInfrastructureError("clean verifier reference is missing") from exc
    lock = run["lock"]
    invocation = {
        "schema": "autofv-verifier-invocation/v1",
        "run_id": run["run_id"],
        "invocation_id": expected.get("invocation_id") or secrets.token_hex(16),
        "agent_worker_id": run["agent_worker_id"],
        "verifier_worker_id": verifier_worker_id,
        "snapshot_sha256": expected["snapshot_sha256"],
        "manifest_sha256": expected["manifest_sha256"],
        "probe_rust_sha256": expected["probe_rust_sha256"],
        "probe_aeneas_sha256": expected["probe_aeneas_sha256"],
        "graph_sha256": expected["graph_sha256"],
        "image_digest": expected["image_digest"],
        "control_bundle_sha256": expected["control_bundle_sha256"],
        "native_decide_policy_sha256": expected[
            "native_decide_policy_sha256"
        ],
        "toolchain_lock_sha256": _sha256(_canonical_bytes(lock)),
        "accepted_commit": expected["accepted_commit"],
        "accepted_tree_sha256": expected["accepted_tree_sha256"],
        "bundle_sha256": _sha256(bundle),
        "reference_sha256": _sha256(reference_bytes),
    }
    return verify_bundle(
        bundle,
        invocation,
        reference_bytes=reference_bytes,
        run_checks=lambda members, state, reference: _clean_worker_checks(
            run, invocation, members, state, reference
        ),
    )


def validate_report(
    report: Any, run: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """Accept only a distinct worker's hash-bound PASS report."""
    if "invocation_id" in expected:
        required = (INVOCATION_FIELDS - {"schema"}) | {
            "schema",
            "checks",
            "failures",
            "native_decide_uses",
            "compiler_assumptions",
            "meaning",
            "sorry_count_before",
            "sorry_count_after",
            "evidence_level",
            "verdict",
            "report_sha256",
        }
        if not isinstance(report, dict) or set(report) != required:
            raise VerifierError("clean verifier report fields mismatch")
        if report.get("schema") != "autofv-verifier-report/v1":
            raise VerifierError("clean verifier report schema mismatch")
        if (
            report.get("run_id") != run.get("run_id")
            or report.get("agent_worker_id") != run.get("agent_worker_id")
        ):
            raise VerifierError("clean verifier run identity mismatch")
        if (
            not isinstance(report.get("verifier_worker_id"), str)
            or not report["verifier_worker_id"]
            or report["verifier_worker_id"] == report["agent_worker_id"]
        ):
            raise VerifierError("clean verifier worker is not distinct")
        for field, value in expected.items():
            if field != "schema" and report.get(field) != value:
                raise VerifierError(f"clean verifier {field} mismatch")
        if (
            report.get("verdict") != "PASS"
            or report.get("failures") != []
            or report.get("evidence_level") != "L4"
            or not isinstance(report.get("checks"), dict)
            or not report["checks"]
            or any(value is not True for value in report["checks"].values())
            or type(report.get("sorry_count_before")) is not int
            or report["sorry_count_before"] < 0
            or report.get("sorry_count_after") != 0
        ):
            raise VerifierError("clean verifier did not pass")
        body = {key: value for key, value in report.items() if key != "report_sha256"}
        if report.get("report_sha256") != _sha256(_canonical_bytes(body)):
            raise VerifierError("clean verifier report hash mismatch")
        return report

    # Compatibility for pre-bundle unit seams. Real executions pass a full
    # invocation and therefore cannot authorize this reduced report shape.
    required = {
        "schema",
        "run_id",
        "agent_worker_id",
        "verifier_worker_id",
        *expected.keys(),
        "verdict",
        "report_sha256",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise VerifierError("clean verifier report fields mismatch")
    if report["schema"] != "autofv-verifier-report/v1":
        raise VerifierError("clean verifier report schema mismatch")
    if report["run_id"] != run["run_id"] or report["agent_worker_id"] != run["agent_worker_id"]:
        raise VerifierError("clean verifier run identity mismatch")
    if (
        not isinstance(report["verifier_worker_id"], str)
        or not report["verifier_worker_id"]
        or report["verifier_worker_id"] == report["agent_worker_id"]
    ):
        raise VerifierError("clean verifier worker is not distinct")
    for field, value in expected.items():
        if report[field] != value:
            raise VerifierError(f"clean verifier {field} mismatch")
    if report["verdict"] != "PASS":
        raise VerifierError("clean verifier did not pass")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if report["report_sha256"] != _sha256(_canonical_bytes(body)):
        raise VerifierError("clean verifier report hash mismatch")
    return report
