"""Closed Pi/OpenAI subscription binding on the trusted provider-service side.

This module never reads OAuth bytes and never executes role tools. The controller
owns admission, history and replay; the supervised Node process owns one native
provider generation. Runtime records select code and record prior authorization,
not permission to sign in or to qualify a model automatically.
"""
from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import ContractError, canonical_json_bytes, _read_json, _sha256, _text
from . import provider_config, provider_messages, runtime_profile

SCHEMA = "autofv-provider-binding/v3"
RECORD_SCHEMA = "autofv-pi-runtime-record/v1"
ENDPOINT = "https://api.openai.com/v1/responses"
_RECORD_FIELDS = {"schema", "role_profile", "runtime_identity", "grant", "node_executable",
                  "credential_store_path", "receipt_signing_key_path", "preflight_path",
                  "suite_artifact_path", "qualification_paths"}
_PUBLIC_FIELDS = {"schema", "run_id", "proxy_id", "route_id", "fixed_proxy_sha256",
    "client_identity_sha256", "endpoint", "endpoint_sha256", "model_id", "parameters",
    "tool_schema_sha256", "capability_sha256", "receipt_authentication", "role_profile",
    "role_profile_sha256", "source_packet_sha256", "runtime_identity",
    "runtime_identity_sha256", "grant", "binding_sha256"}
_GRANT_FIELDS = {"schema", "approval_id", "account_binding_sha256", "config_sha256", "original_started_epoch_ms",
    "original_deadline_epoch_ms", "max_invocations", "acknowledgements", "qualification"}
_QUALIFICATION_FIELDS = {"isolation_sha256", "callback_cancellation_sha256", "entitlement_sha256"}
_PROCESSES: dict[str, Any] = {}
_RECORDS: dict[str, dict[str, Any]] = {}
_STOPPED: set[str] = set()
_LOCK = threading.RLock()


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def is_pi(run: dict[str, Any]) -> bool:
    return (run.get("provider_binding") or {}).get("schema") == SCHEMA


def validate_grant(value: Any) -> dict[str, Any]:
    value = provider_config.exact_dict(value, _GRANT_FIELDS, "Pi grant")
    if value["schema"] != "autofv-pi-run-grant/v1":
        raise ContractError("Pi grant schema mismatch")
    _text(value["approval_id"], "Pi explicit approval identifier")
    _sha256(value["account_binding_sha256"], "Pi approved account binding")
    _sha256(value["config_sha256"], "Pi approved run configuration")
    for name in ("original_started_epoch_ms", "original_deadline_epoch_ms", "max_invocations"):
        if type(value[name]) is not int or value[name] <= 0:
            raise ContractError("Pi grant limits must be positive integers")
    if value["original_started_epoch_ms"] >= value["original_deadline_epoch_ms"]:
        raise ContractError("Pi grant original clock is invalid")
    if value["max_invocations"] > 1024:
        raise ContractError("Pi grant invocation limit exceeds bounded implementation")
    if value["acknowledgements"] != {"no_server_output_cap": True,
        "unknown_subscription_cost": True, "best_effort_remote_abort": True}:
        raise ContractError("Pi subscription policy requires explicit acknowledgements")
    qualifications = provider_config.exact_dict(value["qualification"], _QUALIFICATION_FIELDS,
                                                 "Pi qualification references")
    for name, digest in qualifications.items():
        _sha256(digest, name)
    return copy.deepcopy(value)


def validate_public_binding(value: Any) -> dict[str, Any]:
    public = provider_config.exact_dict(value, _PUBLIC_FIELDS, "Pi provider binding")
    if public["schema"] != SCHEMA or public["endpoint"] != ENDPOINT:
        raise ContractError("Pi provider binding identity mismatch")
    for name in ("run_id", "proxy_id", "route_id"):
        _text(public[name], name)
    for name in _PUBLIC_FIELDS:
        if name.endswith("_sha256"):
            _sha256(public[name], name)
    profile = runtime_profile.profile()
    runtime_profile.validate_runtime_identity(public["runtime_identity"])
    if (public["role_profile"] != profile or public["role_profile_sha256"] != _sha(profile)
        or public["parameters"] != profile["parameters"]
        or public["model_id"] != runtime_profile.PI_MODEL
        or public["runtime_identity_sha256"] != _sha(public["runtime_identity"])
        or public["endpoint_sha256"] != hashlib.sha256(ENDPOINT.encode()).hexdigest()
        or public["binding_sha256"] != _sha({k: v for k, v in public.items() if k != "binding_sha256"})):
        raise ContractError("Pi immutable profile/runtime binding mismatch")
    validate_grant(public["grant"])
    # The existing verifier checks key ID, DER digest and PEM when used. Validate
    # its structure here too, without manufacturing a provider billing identity.
    auth = provider_config.exact_dict(public["receipt_authentication"],
        {"algorithm", "key_id", "public_key_der_sha256", "public_key_pem"}, "Pi attestation authority")
    if auth["algorithm"] != "Ed25519":
        raise ContractError("Pi attestation algorithm mismatch")
    key = serialization.load_pem_public_key(auth["public_key_pem"].encode())
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(der).hexdigest() != auth["public_key_der_sha256"]:
        raise ContractError("Pi attestation public key mismatch")
    return copy.deepcopy(public)


def _trusted_path(value: Any, label: str, *, private: bool = False) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ContractError(f"{label} must be absolute")
    path = Path(value)
    if path.is_symlink():
        raise ContractError(f"{label} cannot be a symlink")
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ContractError(f"{label} must be a regular file")
    if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ContractError(f"{label} must be private and owned by the controller")
    return path


def read_runtime_record(path: str | Path, *, config: dict[str, Any] | None = None) -> dict[str, Any]:
    source = _trusted_path(str(path), "Pi runtime record")
    value = provider_config.exact_dict(_read_json(source, "Pi runtime record"), _RECORD_FIELDS, "Pi runtime record")
    if source.read_bytes() != canonical_json_bytes(value) + b"\n":
        raise ContractError("Pi runtime record must be canonical JSON")
    if value["schema"] != RECORD_SCHEMA or value["role_profile"] != runtime_profile.profile():
        raise ContractError("Pi runtime record profile mismatch")
    runtime_profile.validate_runtime_identity(value["runtime_identity"])
    grant = validate_grant(value["grant"])
    if config is not None:
        if (not runtime_profile.is_pi(config) or _sha(config) != grant["config_sha256"]
            or config["max_invocations"] != grant["max_invocations"]
            or grant["original_deadline_epoch_ms"] - grant["original_started_epoch_ms"]
            > config["max_wall_seconds"] * 1000):
            raise ContractError("Pi runtime record differs from run approval limits")
    for name in ("node_executable", "credential_store_path", "receipt_signing_key_path",
                 "preflight_path", "suite_artifact_path"):
        if not isinstance(value[name], str) or not Path(value[name]).is_absolute():
            raise ContractError(f"Pi {name} must be absolute")
    provider_config.exact_dict(value["qualification_paths"], _QUALIFICATION_FIELDS, "Pi qualification paths")
    return copy.deepcopy(value)


def diagnostic(record_path: str | Path) -> dict[str, Any]:
    """No store access, runtime initialization, sign-in, discovery or network."""
    from .pi_process import runtime_diagnostic
    record = read_runtime_record(record_path)
    observed = runtime_diagnostic(record["node_executable"])
    matches = observed.get("runtime_identity") == record["runtime_identity"]
    blockers = [] if matches else ["installed_runtime_identity_mismatch"]
    if time.time_ns() // 1_000_000 >= record["grant"]["original_deadline_epoch_ms"]:
        blockers.append("original_grant_expired")
    blockers.append("authentication_entitlement_and_sealed_qualification_not_checked")
    return {"schema": "autofv-pi-doctor/v1", "role_profile": runtime_profile.PI_PROFILE_ID,
            "status": "metadata_match" if matches else "blocked", "blockers": blockers,
            "record_runtime_identity": record["runtime_identity"], "observed": observed,
            "authentication_checked": False, "entitlement_checked": False,
            "live_qualified": False}


def _verify_runtime(record: dict[str, Any]) -> None:
    from .pi_process import runtime_diagnostic
    observed = runtime_diagnostic(record["node_executable"])
    actual = observed.get("runtime_identity", observed)
    if actual != record["runtime_identity"]:
        raise ContractError("Pi installed runtime does not match approved identity")



def validate_private_boundaries(record: dict[str, Any], target: str | Path,
                                *, record_path: str | Path | None = None, run_root: str | Path | None = None) -> None:
    """Check actual host source before any archive/worker allocation occurs."""
    project = Path(target)
    if not project.is_absolute() or not project.is_dir():
        raise ContractError("Pi host source boundary must be an existing absolute directory")
    project = project.resolve(strict=True)
    paths = [record["credential_store_path"], record["receipt_signing_key_path"], record_path, run_root]
    for value in paths:
        if value is not None and Path(value).resolve().is_relative_to(project):
            raise ContractError("Pi private state must be outside the candidate source")


def configure(run: dict[str, Any], config: dict[str, Any], record_path: str | Path,
              *, tool_schemas: Any) -> dict[str, Any]:
    """Pin public identity and signing authority; no OAuth/store read occurs."""
    record = read_runtime_record(record_path, config=config)
    _verify_runtime(record)
    grant = record["grant"]
    now = time.time_ns() // 1_000_000
    if run.get("provider_binding") is None and not grant["original_started_epoch_ms"] <= now < grant["original_deadline_epoch_ms"]:
        raise ContractError("Pi original grant is not active")
    if not isinstance(run.get("input_root"), str):
        raise ContractError("Pi binding requires the actual host input root")
    validate_private_boundaries(record, run["input_root"], record_path=record_path, run_root=run.get("run_root"))
    # This is the controller's attestation key, never an OAuth token/API key.
    key_path = _trusted_path(record["receipt_signing_key_path"], "Pi attestation key", private=True)
    raw_key = key_path.read_bytes()
    if len(raw_key) != 32:
        raise ContractError("Pi attestation key must contain 32 raw Ed25519 seed bytes")
    signing_key = Ed25519PrivateKey.from_private_bytes(raw_key)
    public_key = signing_key.public_key()
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_digest = hashlib.sha256(der).hexdigest()
    token = os.environ.get("AUTOFV_RUN_TOKEN")
    if not isinstance(token, str) or not token or len(token.encode()) > 4096:
        raise ContractError("Pi fixed relay requires a trusted run token")
    route = run["lock"]["fixed_proxy"]
    tools = provider_config._tool_schemas(tool_schemas)
    profile = runtime_profile.profile()
    body = {"schema": SCHEMA, "run_id": run["run_id"], "proxy_id": route["proxy_id"],
        "route_id": route["route_id"], "fixed_proxy_sha256": _sha(route),
        "client_identity_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "endpoint": ENDPOINT, "endpoint_sha256": hashlib.sha256(ENDPOINT.encode()).hexdigest(),
        "model_id": runtime_profile.PI_MODEL, "parameters": profile["parameters"],
        "tool_schema_sha256": _sha(tools),
        "capability_sha256": _sha({"profile": profile, "runtime": record["runtime_identity"]}),
        "receipt_authentication": {"algorithm": "Ed25519", "key_id": f"autofv-pi-ed25519-{key_digest[:16]}",
            "public_key_der_sha256": key_digest,
            "public_key_pem": public_key.public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")},
        "role_profile": profile, "role_profile_sha256": _sha(profile),
        "source_packet_sha256": config["source_packet"]["packet_sha256"],
        "runtime_identity": record["runtime_identity"], "runtime_identity_sha256": _sha(record["runtime_identity"]),
        "grant": grant}
    public = {**body, "binding_sha256": _sha(body)}
    validate_public_binding(public)
    if run.get("provider_binding") not in (None, public):
        raise ContractError("Pi binding changed during resume")
    binding = provider_config.ProviderBinding(public=public, endpoint=ENDPOINT, api_key=bytearray(),
        client_token=bytearray(token.encode()), model_id=runtime_profile.PI_MODEL, route_path=route["path"],
        pricing={}, tools=tools, signing_key=signing_key, secret_markers=(raw_key, raw_key.hex().encode()))
    from . import pi_allocation
    pi_allocation.claim(run, config, record, binding)
    with provider_config._BINDINGS_LOCK:
        if public["binding_sha256"] in provider_config._BINDINGS:
            raise ContractError("Pi binding is already configured")
        provider_config._BINDINGS[public["binding_sha256"]] = binding
    with _LOCK:
        _RECORDS[public["binding_sha256"]] = record
    run.update(provider_binding=copy.deepcopy(public), provider_binding_sha256=public["binding_sha256"],
        proxy_client_identity_sha256=public["client_identity_sha256"], proxy_model_id=runtime_profile.PI_MODEL,
        runtime_identity_sha256=public["runtime_identity_sha256"], cost_classification="subscription_cost_unknown",
        budget_started_epoch_ns=grant["original_started_epoch_ms"] * 1_000_000,
        role_profile=runtime_profile.PI_PROFILE_ID, source_packet_sha256=public["source_packet_sha256"])
    return copy.deepcopy(public)


def _qualification_artifacts(record: dict[str, Any], binding: dict[str, Any]) -> None:
    """Validate signed qualification and its retained, identity-bound report."""
    from . import pi_qualification
    bootstrap = {"runtime_identity": record["runtime_identity"],
        "role_profile": record["role_profile"],
        "account_binding_sha256": record["grant"]["account_binding_sha256"],
        "receipt_authentication": binding["receipt_authentication"]}
    for name, expected in record["grant"]["qualification"].items():
        path = _trusted_path(record["qualification_paths"][name], "Pi qualification artifact")
        raw = path.read_bytes()
        if len(raw) > 262144 or hashlib.sha256(raw).hexdigest() != expected:
            raise ContractError("Pi qualification artifact changed")
        pi_qualification.verify_artifact(bootstrap, path, name.removesuffix("_sha256"))


def finalize_allocation(run: dict[str, Any]) -> None:
    from . import pi_allocation
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise ContractError("Pi allocation binding is unavailable")
    with _LOCK:
        record = _RECORDS[binding.public["binding_sha256"]]
    pi_allocation.finalize(run, record, binding)


def authorize_prepared(run: dict[str, Any], *, repo: str | Path | None = None,
                       run_config: str | Path | None = None, public_rust_root: str | Path | None = None) -> None:
    from . import provider_service, subscription_journal
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise ContractError("Pi binding unavailable")
    with _LOCK:
        record = _RECORDS[binding.public["binding_sha256"]]
    from . import pi_allocation
    pi_allocation.finalize(run, record, binding)
    subscription_journal.initialize(run, binding)
    _qualification_artifacts(record, binding.public)
    max_age = (record["grant"]["original_deadline_epoch_ms"] - record["grant"]["original_started_epoch_ms"]) // 1000
    preflight_path, suite_path = Path(record["preflight_path"]), Path(record["suite_artifact_path"])
    if not preflight_path.exists() and not suite_path.exists():
        if repo is None or run_config is None:
            raise ContractError("Pi same-worker sealed preflight requires prepared source and configuration")
        if (preflight_path.name != "deterministic-preflight.json" or suite_path.name != "retained-suite.json"
            or suite_path.parent != preflight_path.parent):
            raise ContractError("Pi generated preflight locations are invalid")
        from . import preflight_runner
        preflight_runner.run_preflight(repo, run_config, preflight_path.parent,
            max_age_seconds=max_age, public_rust_root=public_rust_root, _prepared_run=run)
    provider_service.load_preflight_authorization(run, preflight_path=preflight_path,
        suite_artifact_path=suite_path, max_age_seconds=max_age)


def authorize(run: dict[str, Any]) -> None:
    from . import preflight
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise ContractError("Pi binding unavailable")
    with _LOCK:
        if binding.public["binding_sha256"] in _STOPPED or run.get("pi_admission_stopped"):
            raise ContractError("Pi admission stopped; reconciliation is required")
        record = _RECORDS.get(binding.public["binding_sha256"])
    if record is None or record["grant"] != binding.public["grant"]:
        raise ContractError("Pi grant is not pinned")
    from . import pi_allocation
    pi_allocation.verify(run, record, binding)
    if time.time_ns() // 1_000_000 >= record["grant"]["original_deadline_epoch_ms"]:
        raise ContractError("Pi original deadline exhausted")
    _qualification_artifacts(record, binding.public)
    preflight.authorize_provider_action(run, binding.public)


def dispatch(run: dict[str, Any], request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    from . import subscription_journal
    from .pi_process import PiProcess, PiProcessError
    binding = provider_config.provider_binding(run)
    if binding is None:
        raise ContractError("Pi binding unavailable")
    messages, monotonic_deadline = provider_messages.take_messages(binding, request)
    match = re.fullmatch(r"lane-([0-9a-f]{16})-[0-9]{3}", request["request_id"])
    if match is None:
        raise ContractError("Pi requires a canonical DeepAgents conversation request")
    digest = binding.public["binding_sha256"]
    def generate(admission, continuations):
        authorize(run)
        with _LOCK:
            if digest in _STOPPED or run.get("pi_admission_stopped"):
                raise ContractError("Pi admission stopped")
            process = _PROCESSES.get(digest)
            if process is None:
                record = _RECORDS[digest]
                process = PiProcess(record["node_executable"], store_path=record["credential_store_path"],
                    account_binding_sha256=record["grant"]["account_binding_sha256"],
                    runtime_dir=Path(run["run_root"]) / "provider-private" / "process")
                _PROCESSES[digest] = process
        deadline_ms = min(binding.public["grant"]["original_deadline_epoch_ms"],
            time.time_ns() // 1_000_000 + max(0, (monotonic_deadline - time.monotonic_ns()) // 1_000_000))
        wire_request = {"run_id": request["run_id"], "conversation_id": request["conversation_id"],
            "request_id": request["request_id"], "sequence": request["sequence"],
            "role": request["role"], "model_id": request["model_id"],
            "history_sha256": _sha(messages), "profile_sha256": binding.public["role_profile_sha256"]}
        result = process.generate_one({"request": wire_request, "messages": messages,
            "profile": {"provider": "openai", "api": "openai-responses", "model_id": request["model_id"],
                "effort": "xhigh", "tool_choice": "required"}, "continuations": continuations,
            "admission": {"deadline_ms": deadline_ms, "sequence": request["sequence"], "request_id": request["request_id"]},
            "tools": binding.tools})
        payload = {"schema": "autofv-lane-tool-call/v1", **result["tool_call"]}
        response = {**{k: v for k, v in request.items() if k not in {"conversation_id", "history_sha256"}}, "schema": "autofv-model-response/v1", "kind": "tool_call",
            "assigned_path": None, "base_commit": run["base_commit"], "statement_fingerprints": [],
            "payload": payload, "payload_sha256": _sha(payload)}
        provider_messages.scan_response(response, binding)
        return response, result["usage"], result["continuation"], {
            "provider_response_id": result["provider_response_id"], "observed_effort": result["observed_effort"],
            "termination": "toolUse"}
    try:
        return subscription_journal.dispatch(run, binding, request, messages, generate)
    except PiProcessError as exc:
        classification = "timeout" if "timeout" in exc.code or "deadline" in exc.code else "upstream_error"
        raise provider_config.ProviderConfigError("Pi transport stopped; dispatch remains unresolved",
            classification=classification) from exc


def stop(run: dict[str, Any]) -> None:
    """Close admission and kill/reap active generation before audits/disposal.

    Signing/journal authority remains attached for conservative reconciliation.
    A local kill is not proof that upstream computation or quota use stopped.
    """
    if not is_pi(run):
        return
    digest = run["provider_binding_sha256"]
    with _LOCK:
        _STOPPED.add(digest)
        run["pi_admission_stopped"] = True
        process = _PROCESSES.get(digest)
    if process is not None:
        process.cancel()


def release(run: dict[str, Any]) -> None:
    digest = run.get("provider_binding_sha256")
    with _LOCK:
        process = _PROCESSES.pop(digest, None)
        _RECORDS.pop(digest, None)
        _STOPPED.discard(digest)
    if process is not None:
        process.close()
