"""Explicit local Pi bootstrap, sealed checks, one-call probe, and run grant.

No command implies permission for the next one. ``prepare`` reads provisioning
metadata only. ``qualify`` starts the existing local sealed worker. ``probe``
can use subscription quota exactly once for a separately approved original
clock. Its durable admission is burned before any SDK/auth initialization.
These controller signatures are observations, never provider billing receipts.
"""
from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import pi_backend, pi_process, provider_config, provider_receipts, runtime_profile, subscription_receipts
from .contracts import ContractError, canonical_json_bytes, _sha256, _text

BOOTSTRAP_SCHEMA = "autofv-pi-bootstrap/v1"
ACKNOWLEDGEMENTS = {"no_server_output_cap": True, "unknown_subscription_cost": True,
                    "best_effort_remote_abort": True}
EVIDENCE_KINDS = {"isolation": "sealed_runtime_checks",
                  "callback_cancellation": "supervised_callback_cancellation",
                  "entitlement": "one_generation_usage_attestation"}
_BOOTSTRAP_FIELDS = {"schema", "role_profile", "runtime_identity", "node_executable",
    "credential_store_path", "account_binding_sha256", "receipt_signing_key_path",
    "receipt_authentication", "provisioning_sha256", "auth"}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _private_directory(path: Path, *, create: bool = False) -> Path:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not path.is_absolute() or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ContractError("Pi qualification directory must be private and owned")
    return path.resolve(strict=True)


def _read(path: Path, *, private: bool = True) -> dict[str, Any]:
    path = pi_backend._trusted_path(str(path), "Pi qualification record", private=private)
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    try:
        value = json.loads(raw)
        if len(raw) > 2 * 1024 * 1024 or not isinstance(value, dict) or raw != canonical_json_bytes(value) + b"\n":
            raise ValueError("noncanonical")
    except (ValueError, UnicodeError) as exc:
        raise ContractError("Pi qualification record must be bounded canonical JSON") from exc
    return value


def _write(path: Path, value: dict[str, Any], *, replace: bool = False) -> None:
    _private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not replace):
        raise ContractError("Pi qualification output already exists")
    raw = canonical_json_bytes(value) + b"\n"
    fd, temp = tempfile.mkstemp(prefix=".pi-qualification-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temp, path)
        else:
            # Linking exclusively prevents a concurrent writer replacing evidence.
            os.link(temp, path, follow_symlinks=False)
            os.unlink(temp)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _key(bootstrap: dict[str, Any]) -> Ed25519PrivateKey:
    path = pi_backend._trusted_path(bootstrap["receipt_signing_key_path"], "Pi attestation key", private=True)
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ContractError("Pi attestation key must be a raw Ed25519 seed")
    key = Ed25519PrivateKey.from_private_bytes(raw)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(public).hexdigest() != bootstrap["receipt_authentication"]["public_key_der_sha256"]:
        raise ContractError("Pi bootstrap signing authority changed")
    return key


def _signed(bootstrap: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    auth = bootstrap["receipt_authentication"]
    return {**body, "auth": {"algorithm": "Ed25519", "key_id": auth["key_id"],
        "signature": base64.b64encode(_key(bootstrap).sign(canonical_json_bytes(body))).decode("ascii")}}


def _verify(bootstrap: dict[str, Any], record: dict[str, Any], label: str) -> None:
    provider_receipts.verify_signature({k: v for k, v in record.items() if k != "auth"},
        record.get("auth"), bootstrap["receipt_authentication"], label)


def load_bootstrap(path: str | Path, *, inspect_runtime: bool = True) -> tuple[Path, dict[str, Any]]:
    path = Path(path).absolute()
    root = _private_directory(path.parent)
    value = provider_config.exact_dict(_read(path), _BOOTSTRAP_FIELDS, "Pi bootstrap")
    if value["schema"] != BOOTSTRAP_SCHEMA or value["role_profile"] != runtime_profile.profile():
        raise ContractError("Pi bootstrap profile mismatch")
    runtime_profile.validate_runtime_identity(value["runtime_identity"])
    _sha256(value["account_binding_sha256"], "Pi bootstrap account binding")
    if value["receipt_signing_key_path"] != str(root / "attestation.key"):
        raise ContractError("Pi bootstrap key location mismatch")
    if not Path(value["credential_store_path"]).is_absolute():
        raise ContractError("Pi bootstrap credential location must be absolute")
    _verify(value, value, "Pi bootstrap")
    if inspect_runtime and pi_process.runtime_diagnostic(value["node_executable"])["runtime_identity"] != value["runtime_identity"]:
        raise ContractError("Pi installed runtime changed after bootstrap")
    return root, value


def prepare(*, node: str | Path, provisioning: str | Path, output: str | Path) -> dict[str, Any]:
    """Inspect exact installed code and generate a local observation key, no auth."""
    source = Path(provisioning).absolute()
    metadata = provider_config.exact_dict(_read(source), {"schema", "store_path", "account_binding_sha256",
        "device_id", "account_identity", "entitlement_validated", "model_dispatched"}, "Pi provisioning metadata")
    if (metadata.get("schema") != "autofv-pi-provisioning/v1" or metadata.get("model_dispatched") is not False
        or metadata.get("entitlement_validated") is not False or not isinstance(metadata.get("store_path"), str)
        or not Path(metadata["store_path"]).is_absolute()):
        raise ContractError("Pi provisioning metadata is not from explicit dedicated setup")
    _sha256(metadata.get("account_binding_sha256"), "Pi provisioned account binding")
    observed = pi_process.runtime_diagnostic(node)
    root = Path(output).absolute()
    if root.exists() or root.is_symlink():
        raise ContractError("Pi bootstrap output already exists")
    root = _private_directory(root, create=True)
    key = Ed25519PrivateKey.generate()
    key_path = root / "attestation.key"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        stream.flush()
        os.fsync(stream.fileno())
    public = key.public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest()
    body = {"schema": BOOTSTRAP_SCHEMA, "role_profile": runtime_profile.profile(),
        "runtime_identity": observed["runtime_identity"], "node_executable": str(pi_process._node_path(node)),
        "credential_store_path": metadata["store_path"], "account_binding_sha256": metadata["account_binding_sha256"],
        "receipt_signing_key_path": str(key_path), "provisioning_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "receipt_authentication": {"algorithm": "Ed25519", "key_id": f"autofv-pi-ed25519-{digest[:16]}",
            "public_key_der_sha256": digest, "public_key_pem": public.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")}}
    _write(root / "bootstrap.json", _signed(body, body))
    return {"bootstrap": str(root / "bootstrap.json"), "model_dispatched": False,
            "credential_accessed": False, "live_qualified": False}


@contextmanager
def _approval(root: Path, bootstrap: dict[str, Any], approval_id: str, purpose: str,
              deadline_ms: int, *, max_invocations: int = 0, acknowledgements: dict[str, bool] | None = None, selection_sha256: str | None = None):
    _text(approval_id, "Pi explicit approval identifier")
    if len(approval_id) > 256 or type(deadline_ms) is not int or deadline_ms <= 0:
        raise ContractError("Pi approval identifier or deadline is invalid")
    if max_invocations and acknowledgements != ACKNOWLEDGEMENTS:
        raise ContractError("Pi subscription probe/run requires all explicit acknowledgements")
    approvals = root / "approvals"
    if not approvals.exists():
        try:
            _private_directory(approvals, create=True)
        except FileExistsError:
            pass
    _private_directory(approvals)
    location = approvals / hashlib.sha256(approval_id.encode()).hexdigest()
    if not location.exists():
        try:
            _private_directory(location, create=True)
        except FileExistsError:
            pass
    _private_directory(location)
    fd = os.open(location / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time_ns() // 1_000_000 >= deadline_ms:
                    raise ContractError("Pi original approval deadline expired while waiting")
                time.sleep(.02)
        fixed = {"schema": "autofv-pi-local-approval/v1", "purpose": purpose, "approval_id": approval_id,
            "bootstrap_sha256": _sha(bootstrap), "account_binding_sha256": bootstrap["account_binding_sha256"],
            "selection_sha256": selection_sha256,
            "original_deadline_epoch_ms": deadline_ms, "max_invocations": max_invocations,
            "acknowledgements": acknowledgements or {}}
        path = location / "approval.json"
        if path.exists():
            grant = _read(path)
            _verify(bootstrap, grant, "Pi local approval")
            if {k: v for k, v in grant.items() if k not in {"auth", "original_started_epoch_ms"}} != fixed:
                raise ContractError("Pi approval already used for different purpose, identity, or limits")
        else:
            now = time.time_ns() // 1_000_000
            maximum_window = bootstrap["role_profile"]["parameters"]["timeout_seconds"] * 1000 if purpose == "entitlement_probe" else 86_400_000
            if not now < deadline_ms <= now + maximum_window:
                raise ContractError("Pi explicit original deadline is expired or exceeds this operation limit")
            grant = _signed(bootstrap, {**fixed, "original_started_epoch_ms": now})
            _write(path, grant)
        yield location, grant
    finally:
        os.close(fd)


def _active(grant: dict[str, Any]) -> None:
    if not grant["original_started_epoch_ms"] <= time.time_ns() // 1_000_000 < grant["original_deadline_epoch_ms"]:
        raise ContractError("Pi original approval deadline expired or not started")


def _artifact(bootstrap: dict[str, Any], kind: str, report: Path, output: Path) -> dict[str, Any]:
    body = {"schema": "autofv-pi-qualification/v1", "kind": kind, "status": "passed",
        "evidence_class": "live_entitlement" if kind == "entitlement" else "sealed_runtime",
        "runtime_identity_sha256": _sha(bootstrap["runtime_identity"]),
        "role_profile_sha256": _sha(bootstrap["role_profile"]),
        "account_binding_sha256": bootstrap["account_binding_sha256"],
        "evidence": {"path": str(report), "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                     "kind": EVIDENCE_KINDS[kind], "scope": BOUNDARY_SCOPE}}
    value = _signed(bootstrap, body)
    _write(output, value)
    return value


def verify_artifact(bootstrap: dict[str, Any], path: str | Path, kind: str) -> dict[str, Any]:
    artifact = _read(Path(path))
    expected = {"schema": "autofv-pi-qualification/v1", "kind": kind, "status": "passed",
        "evidence_class": "live_entitlement" if kind == "entitlement" else "sealed_runtime",
        "runtime_identity_sha256": _sha(bootstrap["runtime_identity"]),
        "role_profile_sha256": _sha(bootstrap["role_profile"]),
        "account_binding_sha256": bootstrap["account_binding_sha256"]}
    if set(artifact) != {*expected, "evidence", "auth"} or any(artifact[k] != v for k, v in expected.items()):
        raise ContractError("Pi qualification artifact identity mismatch")
    _verify(bootstrap, artifact, "Pi qualification")
    evidence = provider_config.exact_dict(artifact["evidence"], {"path", "sha256", "kind", "scope"}, "Pi retained evidence")
    if evidence["kind"] != EVIDENCE_KINDS[kind] or evidence["scope"] != BOUNDARY_SCOPE:
        raise ContractError("Pi qualification evidence kind mismatch")
    report = _read(Path(evidence["path"]))
    if hashlib.sha256(Path(evidence["path"]).read_bytes()).hexdigest() != evidence["sha256"]:
        raise ContractError("Pi qualification retained evidence changed")
    if report.get("status") != "passed" or report.get("runtime_identity_sha256") != expected["runtime_identity_sha256"]:
        raise ContractError("Pi qualification retained report mismatch")
    return artifact


def _payload(bootstrap: dict[str, Any], grant: dict[str, Any]) -> dict[str, Any]:
    messages = [{"role": "system", "content": "This is an entitlement probe, not a proof task. No tool will execute."},
        {"role": "user", "content": "Call check_lean with an empty object once. Do not produce any other content."}]
    conversation = _sha({"grant": grant, "purpose": "entitlement_probe"})
    request = {"run_id": "pi-probe-" + conversation[:24], "conversation_id": conversation,
        "request_id": "lane-" + conversation[:16] + "-001", "sequence": 1, "role": "prover",
        "model_id": runtime_profile.PI_MODEL, "history_sha256": _sha(messages),
        "profile_sha256": _sha(bootstrap["role_profile"])}
    schemas = json.loads((pi_process.runtime_path() / "tool-schemas.json").read_bytes())
    tools = [{"type": "function", "function": {"name": s["name"], "description": s["description"],
        "parameters": s["input_schema"]}} for s in schemas]
    return {"request": request, "messages": messages, "continuations": [], "tools": tools,
        "profile": {"provider": "openai", "api": "openai-responses", "model_id": runtime_profile.PI_MODEL,
                    "effort": "xhigh", "tool_choice": "required"},
        "admission": {"request_id": request["request_id"], "sequence": 1,
                      "deadline_ms": grant["original_deadline_epoch_ms"]}}


def probe(*, bootstrap_path: str | Path, approval_id: str, deadline_ms: int,
          approved: bool = False, acknowledgements: dict[str, bool] | None = None) -> dict[str, Any]:
    if approved is not True:
        raise ContractError("Pi probe requires explicit approval for one live model request")
    root, bootstrap = load_bootstrap(bootstrap_path)
    with _approval(root, bootstrap, approval_id, "entitlement_probe", deadline_ms,
                   max_invocations=1, acknowledgements=acknowledgements) as (location, grant):
        payload = _payload(bootstrap, grant)
        journal_path = location / "probe-journal.json"
        if journal_path.exists():
            journal = provider_config.exact_dict(_read(journal_path), {"schema", "purpose", "grant_sha256",
                "request_sha256", "status", "max_invocations", "invocations_used", "report_sha256", "auth"},
                "Pi entitlement probe journal")
            _verify(bootstrap, journal, "Pi entitlement probe journal")
            if (journal.get("schema") != "autofv-pi-probe-journal/v1" or journal.get("purpose") != "entitlement_probe"
                or journal.get("max_invocations") != 1 or journal.get("invocations_used") != 1
                or journal.get("grant_sha256") != _sha(grant) or journal.get("request_sha256") != _sha(payload)):
                raise ContractError("Pi probe journal identity mismatch")
            if journal.get("status") != "completed":
                raise ContractError("Pi probe dispatch is unresolved; this approval can never retry")
            verify_artifact(bootstrap, location / "entitlement.json", "entitlement")
            if journal["report_sha256"] != hashlib.sha256((location / "probe-report.json").read_bytes()).hexdigest():
                raise ContractError("Pi probe completed journal report binding changed")
            return {"status": "passed", "entitlement": str(location / "entitlement.json"),
                    "report": str(location / "probe-report.json"), "replayed": True, "new_model_requests": 0,
                    "live_qualified": False}
        if any((location / name).exists() for name in ("probe-report.json", "entitlement.json", "continuation.json", "process")):
            raise ContractError("Pi original probe journal is missing; another dispatch is forbidden")
        _active(grant)
        body = {"schema": "autofv-pi-probe-journal/v1", "purpose": "entitlement_probe",
            "grant_sha256": _sha(grant), "request_sha256": _sha(payload), "status": "dispatched",
            "max_invocations": 1, "invocations_used": 1, "report_sha256": None}
        _write(journal_path, _signed(bootstrap, body))
        # From this durable point, all failures retain uncertainty and prohibit resend.
        with pi_process.PiProcess(bootstrap["node_executable"], store_path=bootstrap["credential_store_path"],
            account_binding_sha256=bootstrap["account_binding_sha256"], runtime_dir=location / "process") as process:
            result = process.generate_one(payload)
        _active(grant)
        pi_process.validate_continuation(result["continuation"], payload["request"], result)
        usage = subscription_receipts.normalize_usage(result["usage"])
        if (result["requested_effort"] != "xhigh" or result["observed_effort"] not in {None, "xhigh"}
            or result["observed_model"] not in {None, runtime_profile.PI_MODEL}
            or result["continuation"]["native"]["response_id"] != result["provider_response_id"]):
            raise ContractError("Pi entitlement response profile mismatch")
        private = location / "continuation.json"
        _write(private, result["continuation"])
        report = _signed(bootstrap, {"schema": "autofv-pi-entitlement-observation/v1", "status": "passed",
            "purpose": "entitlement_probe", "grant": grant, "request": payload["request"],
            "request_sha256": _sha(payload), "response_sha256": _sha(result),
            "runtime_identity_sha256": _sha(bootstrap["runtime_identity"]),
            "role_profile_sha256": _sha(bootstrap["role_profile"]),
            "account_binding_sha256": bootstrap["account_binding_sha256"],
            "raw_usage": result["usage"], "usage": usage, "continuation_sha256": _sha(result["continuation"]),
            "provider_response_id": result["provider_response_id"], "observed_model": result["observed_model"],
            "requested_effort": "xhigh", "observed_effort": result["observed_effort"],
            "attestation_kind": "controller_usage_observation", "cost_usd": None,
            "dispatch_accounting_complete": True, "monetary_cost_known": False,
            "invocations_used": 1, "tool_callbacks_executed": 0})
        report_path = location / "probe-report.json"
        _write(report_path, report)
        _artifact(bootstrap, "entitlement", report_path, location / "entitlement.json")
        _write(journal_path, _signed(bootstrap, {**body, "status": "completed",
            "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}), replace=True)
        return {"status": "passed", "entitlement": str(location / "entitlement.json"),
                "report": str(report_path), "replayed": False, "new_model_requests": 1,
                "live_qualified": False}


BOUNDARY_SCOPE = {"candidate_boundary": "sealed_runsc_fixed_relay",
    "sidecar_boundary": "trusted_host_fixed_code_fetch_policy", "sidecar_os_network_confinement": False}


def _cancel_check(bootstrap: dict[str, Any], location: Path, grant: dict[str, Any]) -> dict[str, Any]:
    marker = location / "callback-entered.json"
    class CanaryProcess(pi_process.PiProcess):
        def _spawn(self):
            return subprocess.Popen([str(self.node), str(pi_process.runtime_path() / "qualification.mjs"), str(marker)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.directory, env=pi_process.minimal_environment(self.node, self.directory),
                start_new_session=True, close_fds=True, shell=False, bufsize=0)
    payload = _payload(bootstrap, grant)
    outcomes: list[str] = []
    with CanaryProcess(bootstrap["node_executable"], store_path=location / "unused-store",
        account_binding_sha256=bootstrap["account_binding_sha256"], runtime_dir=location / "canary-process") as process:
        def invoke():
            try:
                process.generate_one(payload)
            except pi_process.PiProcessError as exc:
                outcomes.append(exc.code)
        thread = threading.Thread(target=invoke, daemon=True)
        thread.start()
        waiting_until = min(time.monotonic() + 10,
            time.monotonic() + max(0, (grant["original_deadline_epoch_ms"] - time.time_ns() // 1_000_000) / 1000))
        while not marker.exists() and thread.is_alive() and time.monotonic() < waiting_until:
            time.sleep(.01)
        if not marker.exists():
            process.cancel()
            thread.join(3)
            raise ContractError("Pi cancellation canary did not enter the real callback boundary")
        observed = _read(marker)
        expected = {"schema": "autofv-pi-cancellation-canary/v1", "callback_entered": True,
            "sdk_model_requests": 0, "denied_fetch_routes": 6, "underlying_fetch_calls": 0, "intercepted_sdk_requests": 1, "retry_count": 0}
        if observed != expected:
            raise ContractError("Pi cancellation canary evidence mismatch")
        before = time.monotonic_ns()
        process.cancel()
        thread.join(3)
        elapsed = (time.monotonic_ns() - before) // 1_000_000
        if thread.is_alive() or process.process.poll() is None or len(outcomes) != 1 or elapsed > 4000:
            raise ContractError("Pi cancellation failed to stop and reap the local callback")
        try:
            os.killpg(process.process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise ContractError("Pi cancelled process group remains alive")
    return {"schema": "autofv-pi-callback-check/v1", "status": "passed", "scope": BOUNDARY_SCOPE,
        "runtime_identity_sha256": _sha(bootstrap["runtime_identity"]), "canary": observed,
        "supervisor": "autofv.pi_process.PiProcess.cancel", "process_group_reaped": True,
        "callback_stopped": True, "cancellation_ms": elapsed, "remote_abort_observed": False,
        "tool_callbacks_executed": 0}


def _sealed_checks(bootstrap: dict[str, Any], repo: Path, location: Path, grant: dict[str, Any]) -> dict[str, Any]:
    from . import worker, worker_runtime, preflight_runner, prepare_dalek
    from .contracts import load_toolchain_lock, validate_target, validate_native_decide_policy
    pi_backend.validate_private_boundaries(bootstrap, Path(repo).absolute().resolve(),
        record_path=Path(bootstrap["receipt_signing_key_path"]).parent / "bootstrap.json", run_root=location)
    target, manifest = validate_target(repo)
    prepare_dalek._scan_prepared(target)
    # Metadata-only existence/ownership check prevents a nonexistent host auth
    # path from vacuously satisfying the negative container-visibility probe.
    pi_backend._trusted_path(bootstrap["credential_store_path"], "Pi managed credential store", private=True)
    lock = load_toolchain_lock()
    validate_native_decide_policy(lock)
    # The probe contains no credentials or native reasoning; it stands in for
    # private continuation bytes at the same host-only directory boundary.
    private_canary = location / "private-continuation-canary.json"
    _write(private_canary, {"schema": "autofv-pi-private-boundary-canary/v1"})
    forbidden = [bootstrap["credential_store_path"], bootstrap["receipt_signing_key_path"], str(private_canary)]
    check_script = (
        "import json,os,sys; p=json.loads(sys.argv[1]); "
        "visible=[os.path.lexists(x) for x in p]; "
        "print(json.dumps({'schema':'autofv-pi-private-path-check/v1','visible':visible},sort_keys=True,separators=(',',':'))); "
        "sys.exit(1 if any(visible) else 0)"
    )
    run = None
    def docker(*args, **kwargs):
        _active(grant)
        return worker_runtime._docker(*args, **kwargs)
    def permissions(mode):
        docker("run", "--rm", "--pull", "never", "--runtime", lock["tools"]["runsc"]["runtime_name"],
            "--read-only", "--network", "none", "--user", "0:0", "--security-opt", "no-new-privileges",
            "--mount", f"type=volume,src={run['volume']},dst=/volume,volume-nocopy",
            lock["image"]["image_digest"], "chmod", "-R", mode, "/volume/work/project")
    seconds = max(0, (grant["original_deadline_epoch_ms"] - time.time_ns() // 1_000_000) / 1000)
    from decimal import Decimal
    reserve = min(30.0, seconds / 4)
    with worker_runtime.work_deadline(seconds - reserve, wall_limit=Decimal(str(seconds - reserve)), cleanup_reserve_seconds=reserve):
        try:
            _active(grant)
            run = worker.prepare_run(target, manifest, lock)
            permissions("a-w")
            try:
                completed = docker(*worker_runtime._runtime_argv(lock, run["volume"], "python", "-I",
                    "/volume/autofv-control/autofv/preflight_runner.py", "--output", "/volume/evidence/pi-fixed-checks.json"), check=False)
                collected = docker(*worker_runtime._runtime_argv(lock, run["volume"], "cat",
                    "/volume/evidence/pi-fixed-checks.json"), check=False)
            finally:
                permissions("u+w")
            if completed.returncode or collected.returncode:
                raise ContractError("Pi sealed fixed prerequisite suite failed")
            suite = preflight_runner.validate_runner_result(collected.stdout)
            observations = []
            # A real candidate mount is created with the same runsc launcher used
            # by Lean diagnostics; no candidate executable or proof is run here.
            docker(*worker_runtime._runtime_argv(lock, run["volume"], "mkdir", "-p", "/volume/lanes/pi-qualification/work"))
            for boundary, argv in (
                ("worker", worker_runtime._runtime_argv(lock, run["volume"], "python", "-I", "-c", check_script,
                                                       json.dumps(forbidden))),
                ("candidate", worker_runtime._candidate_runtime_argv(lock, run["volume"], "pi-qualification",
                    "python", "-I", "-c", check_script, json.dumps(forbidden))),
            ):
                observed = docker(*argv, check=False)
                try:
                    value = json.loads(observed.stdout)
                except ValueError as exc:
                    raise ContractError("Pi private-path isolation probe was unreadable") from exc
                if observed.returncode or value != {"schema": "autofv-pi-private-path-check/v1", "visible": [False] * len(forbidden)}:
                    raise ContractError("Pi private state is visible across the candidate boundary")
                observations.append({"boundary": boundary, "paths_sha256": _sha(forbidden), "result": value})
            return {"schema": "autofv-pi-sealed-checks/v1", "status": "passed", "scope": BOUNDARY_SCOPE,
                "runtime_identity_sha256": _sha(bootstrap["runtime_identity"]),
                "run_id": run["run_id"], "source_head": run["base_commit"], "fixed_suite": suite,
                "worker_inventory": run["worker_inventory"], "scored_container": run["scored_container_receipt"],
                "private_path_checks": observations, "model_requests": 0,
                "fixed_proxy_sha256": _sha(lock["fixed_proxy"]), "control_bundle_sha256": run["control_bundle_sha256"]}
        finally:
            if run is not None:
                with worker_runtime.cleanup_deadline():
                    worker.force_destroy_worker(run)


def qualify(*, bootstrap_path: str | Path, repo: str | Path, approval_id: str,
            deadline_ms: int, approved: bool = False) -> dict[str, Any]:
    if approved is not True:
        raise ContractError("Pi qualification requires explicit local sealed-worker approval")
    root, bootstrap = load_bootstrap(bootstrap_path)
    with _approval(root, bootstrap, approval_id, "sealed_qualification", deadline_ms) as (location, grant):
        if (location / "isolation.json").exists() and (location / "callback_cancellation.json").exists():
            for kind in ("isolation", "callback_cancellation"):
                verify_artifact(bootstrap, location / f"{kind}.json", kind)
            return {"status": "passed", "isolation": str(location / "isolation.json"),
                "callback_cancellation": str(location / "callback_cancellation.json"), "model_requests": 0,
                "scope": BOUNDARY_SCOPE, "live_qualified": False}
        _active(grant)
        callback = _cancel_check(bootstrap, location, grant)
        _write(location / "callback-report.json", callback)
        sealed = _sealed_checks(bootstrap, Path(repo), location, grant)
        sealed["sidecar_policy_checks"] = callback["canary"]
        _active(grant)
        _write(location / "isolation-report.json", sealed)
        _artifact(bootstrap, "callback_cancellation", location / "callback-report.json", location / "callback_cancellation.json")
        _artifact(bootstrap, "isolation", location / "isolation-report.json", location / "isolation.json")
        return {"status": "passed", "isolation": str(location / "isolation.json"),
            "callback_cancellation": str(location / "callback_cancellation.json"), "model_requests": 0,
            "scope": BOUNDARY_SCOPE, "live_qualified": False}


def grant_experiment(*, bootstrap_path: str | Path, config_path: str | Path,
    isolation: str | Path, callback_cancellation: str | Path, entitlement: str | Path,
    approval_id: str, deadline_ms: int, approved: bool = False,
    acknowledgements: dict[str, bool] | None = None) -> dict[str, Any]:
    if approved is not True:
        raise ContractError("Pi experiment requires a separate explicit experiment approval")
    from .contracts import validate_run_config
    _, config = validate_run_config(config_path)
    if not runtime_profile.is_pi(config):
        raise ContractError("Pi experiment grant requires the distinct v3 run profile")
    root, bootstrap = load_bootstrap(bootstrap_path)
    artifacts = {"isolation": Path(isolation).absolute(), "callback_cancellation": Path(callback_cancellation).absolute(),
                 "entitlement": Path(entitlement).absolute()}
    for kind, path in artifacts.items():
        verify_artifact(bootstrap, path, kind)
    with _approval(root, bootstrap, approval_id, "experiment", deadline_ms,
        max_invocations=config["max_invocations"], acknowledgements=acknowledgements, selection_sha256=_sha(config)) as (location, approval):
        _active(approval)
        if deadline_ms - approval["original_started_epoch_ms"] > config["max_wall_seconds"] * 1000:
            raise ContractError("Pi experiment original deadline exceeds config wall limit")
        run_grant = {"schema": "autofv-pi-run-grant/v1", "approval_id": approval_id,
            "config_sha256": _sha(config),
            "account_binding_sha256": bootstrap["account_binding_sha256"],
            "original_started_epoch_ms": approval["original_started_epoch_ms"],
            "original_deadline_epoch_ms": deadline_ms, "max_invocations": config["max_invocations"],
            "acknowledgements": copy.deepcopy(ACKNOWLEDGEMENTS),
            "qualification": {kind + "_sha256": hashlib.sha256(path.read_bytes()).hexdigest() for kind, path in artifacts.items()}}
        pi_backend.validate_grant(run_grant)
        record = {"schema": pi_backend.RECORD_SCHEMA, "role_profile": bootstrap["role_profile"],
            "runtime_identity": bootstrap["runtime_identity"], "grant": run_grant,
            **{k: bootstrap[k] for k in ("node_executable", "credential_store_path", "receipt_signing_key_path")},
            "preflight_path": str(location / "run-preflight" / "deterministic-preflight.json"),
            "suite_artifact_path": str(location / "run-preflight" / "retained-suite.json"),
            "qualification_paths": {kind + "_sha256": str(path) for kind, path in artifacts.items()}}
        path = location / "runtime-record.json"
        if path.exists():
            if _read(path) != record:
                raise ContractError("Pi experiment approval already binds different evidence")
        else:
            _write(path, record)
        pi_backend.read_runtime_record(path, config=config)
        return {"runtime_record": str(path), "model_requests": 0, "original_deadline_epoch_ms": deadline_ms,
                "max_invocations": config["max_invocations"], "scope": BOUNDARY_SCOPE}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="Inspect installed code and create private bootstrap; no auth/model request")
    prep.add_argument("--node", required=True)
    prep.add_argument("--provisioning", required=True)
    prep.add_argument("--output", required=True)
    for name in ("qualify", "probe", "grant"):
        sub = commands.add_parser(name)
        sub.add_argument("--bootstrap", required=True)
        sub.add_argument("--approval-id", required=True)
        sub.add_argument("--deadline-epoch-ms", type=int, required=True)
        if name == "qualify":
            sub.add_argument("--repo", required=True)
            sub.add_argument("--approve-local-sealed-checks", action="store_true")
        else:
            sub.add_argument("--ack-no-server-output-cap", action="store_true")
            sub.add_argument("--ack-unknown-subscription-cost", action="store_true")
            sub.add_argument("--ack-best-effort-remote-abort", action="store_true")
            if name == "probe":
                sub.add_argument("--approve-one-live-request", action="store_true")
            else:
                sub.add_argument("--approve-experiment", action="store_true")
                sub.add_argument("--config", required=True)
                for kind in ("isolation", "callback-cancellation", "entitlement"):
                    sub.add_argument("--" + kind, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(node=args.node, provisioning=args.provisioning, output=args.output)
        else:
            common = {"bootstrap_path": args.bootstrap, "approval_id": args.approval_id,
                      "deadline_ms": args.deadline_epoch_ms}
            if args.command == "qualify":
                result = qualify(**common, repo=args.repo, approved=args.approve_local_sealed_checks)
            else:
                acknowledgements = {"no_server_output_cap": args.ack_no_server_output_cap,
                    "unknown_subscription_cost": args.ack_unknown_subscription_cost,
                    "best_effort_remote_abort": args.ack_best_effort_remote_abort}
                if args.command == "probe":
                    result = probe(**common, approved=args.approve_one_live_request, acknowledgements=acknowledgements)
                else:
                    result = grant_experiment(**common, config_path=args.config, isolation=args.isolation,
                        callback_cancellation=args.callback_cancellation, entitlement=args.entitlement,
                        approved=args.approve_experiment, acknowledgements=acknowledgements)
    except Exception as exc:
        # Never print SDK messages, process output, credential data, or opaque continuations.
        print(json.dumps({"status": "blocked", "error": str(exc) if isinstance(exc, ContractError)
            else type(exc).__name__, "live_qualified": False}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
