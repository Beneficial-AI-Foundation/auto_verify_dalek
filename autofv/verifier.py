"""Independent clean-worker verification and exact report validation."""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from typing import Any

from . import worker


VERIFIER_VM = "autofv-verifier"


class VerifierError(RuntimeError):
    """The clean verifier failed or returned an unauthoritative report."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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
        raise VerifierError(f"clean verifier command failed: {detail or argv[0]}")
    return completed


def _docker(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return _shell("sudo", "docker", *argv, input_bytes=input_bytes)


def _runtime_argv(image: str, volume: str, *command: str) -> tuple[str, ...]:
    return (
        "run",
        "--rm",
        "--pull",
        "never",
        "--read-only",
        "--network",
        "none",
        "--user",
        worker.AGENT_UID,
        "--workdir",
        "/project",
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


def verify_run(run: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Verify the exact accepted tree on the dedicated clean worker."""
    started = subprocess.run(("limactl", "start", VERIFIER_VM), capture_output=True)
    if started.returncode:
        detail = _command_detail(started)
        raise VerifierError(f"clean verifier failed to start: {detail or VERIFIER_VM}")
    volume = f"autofv-verify-{secrets.token_hex(8)}"
    archive = worker.export_accepted(run)
    if _sha256(archive) != expected["accepted_tree_sha256"]:
        raise VerifierError("accepted tree archive hash mismatch")
    _docker("volume", "create", volume)
    try:
        _docker(
            "run",
            "--rm",
            "-i",
            "--pull",
            "never",
            "--read-only",
            "--network",
            "none",
            "--user",
            "0:0",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            f"type=volume,src={volume},dst=/project,volume-nocopy",
            run["image_digest"],
            "sh",
            "-eu",
            "-c",
            "tar -xf - -C /project && chown -R 65532:65532 /project",
            input_bytes=archive,
        )
        _docker(*_runtime_argv(run["image_digest"], volume, *run["manifest"]["verify"]))
    finally:
        try:
            _docker("volume", "rm", volume)
        except VerifierError:
            pass
    body = {
        "schema": "autofv-verifier-report/v1",
        "run_id": run["run_id"],
        "agent_worker_id": run["agent_worker_id"],
        "verifier_worker_id": f"lima:{VERIFIER_VM}",
        **expected,
        "verdict": "PASS",
    }
    return {**body, "report_sha256": _sha256(_canonical_bytes(body))}


def validate_report(
    report: Any, run: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """Accept only a distinct worker's hash-bound PASS report."""
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
