"""Independent clean-worker verification and exact report validation."""

from __future__ import annotations

import hashlib
import json
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


def _shell(*argv: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ("limactl", "shell", VERIFIER_VM, "--", *argv),
        input=input_bytes,
        capture_output=True,
    )
    if completed.returncode:
        raise VerifierError("clean verifier command failed")
    return completed


def verify_run(run: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Verify the exact accepted tree on the dedicated clean worker."""
    subprocess.run(("limactl", "start", VERIFIER_VM), check=True, capture_output=True)
    directory = _shell("mktemp", "-d", f"/tmp/autofv-{run['run_id']}.XXXXXX").stdout.decode().strip()
    if not directory.startswith("/tmp/autofv-"):
        raise VerifierError("clean verifier returned an unsafe work directory")
    archive = worker.export_accepted(run)
    _shell("tar", "-xf", "-", "-C", directory, input_bytes=archive)
    verify = run["manifest"]["verify"]
    completed = _shell(*verify, input_bytes=None) if directory == "." else subprocess.run(
        ("limactl", "shell", VERIFIER_VM, "--", "env", "-C", directory, *verify),
        capture_output=True,
    )
    verdict = "PASS" if completed.returncode == 0 else "FAIL"
    body = {
        "schema": "autofv-verifier-report/v1",
        "run_id": run["run_id"],
        "agent_worker_id": run["agent_worker_id"],
        "verifier_worker_id": f"lima:{VERIFIER_VM}",
        **expected,
        "verdict": verdict,
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
