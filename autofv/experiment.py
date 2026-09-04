"""Trusted intake and immutable contracts for sealed AutoFV experiments.

Ed25519 is used only to authenticate receipts produced by the trusted model
proxy.  This package contains the pinned public key, never the signing key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from langgraph.graph import END, START, StateGraph

from . import probes, verifier, worker

try:
    from harness import agentproc
except ModuleNotFoundError as exc:
    if exc.name != "harness":
        raise

    def _missing_run_round(*args, **kwargs):
        raise ContractError("hashed control bundle is missing harness/agentproc.py")

    agentproc = SimpleNamespace(run_round=_missing_run_round)


TOOLCHAIN_LOCK = Path(__file__).resolve().parents[1] / "docker/autofv/toolchain-lock.json"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
DECIMAL_USD = re.compile(r"(?:0|[1-9][0-9]*)\.[0-9]{6}")
NATIVE_DECIDE_CRITERIA = {"allow_audited": "audited_use_inventory"}


class ContractError(ValueError):
    """Input or trusted-contract data failed closed."""


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical UTF-8 JSON for schema-constrained, float-free envelopes."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError(f"value is not canonical JSON: {exc}") from exc


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    missing, unknown = keys - value.keys(), value.keys() - keys
    if missing or unknown:
        raise ContractError(
            f"{label} fields mismatch: missing={sorted(missing)}, unknown={sorted(unknown)}"
        )
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ContractError(f"{label} must be a non-empty control-free string")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _absolute_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ContractError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ContractError(f"{label} does not exist: {path}") from exc
    if directory and not resolved.is_dir():
        raise ContractError(f"{label} must be a directory")
    if not directory and not resolved.is_file():
        raise ContractError(f"{label} must be a regular file")
    return resolved


def _read_json(path: Path, label: str) -> Any:
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_float=Decimal,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite number {token}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ContractError(f"invalid {label}: {exc}") from exc


def validate_run_config(path: str | Path) -> tuple[Path, dict[str, Any]]:
    config_path = _absolute_path(path, "run config", directory=False)
    config = _exact_dict(
        _read_json(config_path, "run config"),
        {"schema", "model", "max_wall_seconds", "max_cost_usd"},
        "run config",
    )
    if config["schema"] != "autofv-run/v1":
        raise ContractError("run config schema must be autofv-run/v1")
    _text(config["model"], "model")
    if type(config["max_wall_seconds"]) is not int or config["max_wall_seconds"] <= 0:
        raise ContractError("max_wall_seconds must be a positive integer")
    cost = config["max_cost_usd"]
    if isinstance(cost, bool) or not isinstance(cost, (int, Decimal)):
        raise ContractError("max_cost_usd must be a positive decimal number")
    try:
        cost = Decimal(cost)
    except InvalidOperation as exc:
        raise ContractError("max_cost_usd must be a positive decimal number") from exc
    if not cost.is_finite() or cost <= 0:
        raise ContractError("max_cost_usd must be a positive decimal number")
    return config_path, {**config, "max_cost_usd": cost}


def validate_target(path: str | Path) -> tuple[Path, dict[str, Any]]:
    target = _absolute_path(path, "target", directory=True)
    manifest_path = target / "autofv.json"
    if not manifest_path.is_file():
        raise ContractError("target must contain root autofv.json")
    if manifest_path.is_symlink() or manifest_path.resolve(strict=True).parent != target:
        raise ContractError("target autofv.json must be a regular file inside the target root")
    manifest = _exact_dict(
        _read_json(manifest_path, "target manifest"),
        {"schema", "targets", "verify"},
        "target manifest",
    )
    if manifest["schema"] != "autofv/v1":
        raise ContractError("target manifest schema must be autofv/v1")
    targets = manifest["targets"]
    if not isinstance(targets, list) or not targets:
        raise ContractError("target manifest targets must be a non-empty array")
    identities = set()
    for index, item in enumerate(targets):
        item = _exact_dict(item, {"function", "spec"}, f"targets[{index}]")
        identity = (_text(item["function"], "target function"), _text(item["spec"], "target spec"))
        if identity in identities:
            raise ContractError("target manifest contains a duplicate target")
        identities.add(identity)
    verify = manifest["verify"]
    if not isinstance(verify, list) or not verify:
        raise ContractError("target manifest verify must be a non-empty argv array")
    for index, arg in enumerate(verify):
        _text(arg, f"verify[{index}]")
    if Path(verify[0]).name != verify[0]:
        raise ContractError("verification executable must be a locked command name")
    return target, manifest


def load_toolchain_lock(path: str | Path = TOOLCHAIN_LOCK) -> dict[str, Any]:
    lock_path = Path(path)
    lock = _read_json(lock_path, "toolchain lock")
    if not isinstance(lock, dict) or lock.get("schema") != "autofv-toolchain-lock/v1":
        raise ContractError("toolchain lock schema must be autofv-toolchain-lock/v1")
    return lock


def validate_native_decide_policy(lock: dict[str, Any]) -> dict[str, Any]:
    policy = _exact_dict(
        lock.get("native_decide_policy"),
        {
            "schema",
            "state",
            "runnable",
            "selection",
            "operator_rationale",
            "criterion",
            "inventory_rules",
            "violation_reason",
            "claim_consequence",
            "downstream_fields",
        },
        "native_decide policy",
    )
    policy_sha256 = _sha256(
        lock.get("native_decide_policy_sha256"), "native_decide policy hash"
    )
    calculated = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()
    if not hmac.compare_digest(policy_sha256, calculated):
        raise ContractError("native_decide policy hash mismatch")
    if policy["schema"] != "autofv-native-decide-policy/v1":
        raise ContractError("native_decide policy schema is unknown")
    if policy.get("state") != "selected" or policy.get("runnable") is not True:
        raise ContractError("native_decide policy decision is required before execution")
    selection = policy["selection"]
    expected_criterion = NATIVE_DECIDE_CRITERIA.get(selection)
    if expected_criterion is None:
        raise ContractError("native_decide policy selection is unknown")
    _text(policy["operator_rationale"], "native_decide operator rationale")
    if policy["violation_reason"] != "native_decide_policy_violation":
        raise ContractError("native_decide violation reason is unknown")
    _text(policy["claim_consequence"], "native_decide claim consequence")
    if policy["downstream_fields"] != [
        "native_decide_policy",
        "native_decide_policy_sha256",
        "native_decide_uses",
        "compiler_assumptions",
    ]:
        raise ContractError("native_decide downstream fields mismatch")

    criterion = _exact_dict(
        policy["criterion"],
        {"kind", "allowed_origins", "scope", "required_compiler_assumptions"},
        "native_decide policy criterion",
    )
    if criterion["kind"] != expected_criterion:
        raise ContractError("native_decide policy criterion does not match selection")
    if criterion["allowed_origins"] != ["baseline", "agent_introduced"]:
        raise ContractError("native_decide policy origins are invalid")
    scope = _exact_dict(criterion["scope"], {"kind"}, "native_decide policy scope")
    if scope["kind"] != "all":
        raise ContractError("native_decide policy scope is unsupported")
    if criterion["required_compiler_assumptions"] != [
        "Lean.ofReduceBool",
        "Lean.trustCompiler",
    ]:
        raise ContractError("native_decide compiler assumptions are invalid")

    inventory_rules = _exact_dict(
        policy["inventory_rules"],
        {
            "native_decide_use_fields",
            "compiler_assumption_fields",
            "ordering",
            "duplicates",
            "completeness",
        },
        "native_decide inventory rules",
    )
    if inventory_rules["native_decide_use_fields"] != [
        "spec",
        "declaration",
        "source_path",
        "source_sha256",
        "expression_sha256",
        "origin",
    ]:
        raise ContractError("native_decide use fields mismatch")
    if inventory_rules["compiler_assumption_fields"] != [
        "assumption",
        "evidence",
        "evidence_sha256",
    ]:
        raise ContractError("native_decide compiler evidence fields mismatch")
    if (
        inventory_rules["ordering"] != "canonical_tuple_ascending"
        or inventory_rules["duplicates"] != "forbidden"
        or inventory_rules["completeness"]
        != "all discovered native_decide uses and supporting compiler assumptions"
    ):
        raise ContractError("native_decide inventory rules are invalid")
    return policy


def evaluate_native_decide_policy(
    lock: dict[str, Any],
    *,
    native_decide_uses: list[dict[str, Any]],
    compiler_assumptions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate exhaustive evidence through the single native_decide policy seam."""
    policy = validate_native_decide_policy(lock)
    criterion = policy["criterion"]
    rules = policy["inventory_rules"]

    if not isinstance(native_decide_uses, list):
        raise ContractError("native_decide_uses must be an array")
    use_keys = []
    seen_uses = set()
    for index, item in enumerate(native_decide_uses):
        item = _exact_dict(
            item,
            set(rules["native_decide_use_fields"]),
            f"native_decide_uses[{index}]",
        )
        for field in ("spec", "declaration", "source_path"):
            _text(item[field], f"native_decide_uses[{index}].{field}")
        _sha256(item["source_sha256"], f"native_decide_uses[{index}].source_sha256")
        _sha256(
            item["expression_sha256"],
            f"native_decide_uses[{index}].expression_sha256",
        )
        if item["origin"] not in criterion["allowed_origins"]:
            raise ContractError("native_decide use origin is not allowed by policy")
        use_digest = hashlib.sha256(canonical_json_bytes(item)).hexdigest()
        if use_digest in seen_uses:
            raise ContractError("native_decide inventory contains a duplicate use")
        seen_uses.add(use_digest)
        use_keys.append(
            (
                item["spec"],
                item["declaration"],
                item["source_path"],
                item["expression_sha256"],
            )
        )
    if use_keys != sorted(use_keys):
        raise ContractError("native_decide inventory is not canonically ordered")

    if not isinstance(compiler_assumptions, list):
        raise ContractError("compiler_assumptions must be an array")
    assumption_names = []
    for index, item in enumerate(compiler_assumptions):
        item = _exact_dict(
            item,
            set(rules["compiler_assumption_fields"]),
            f"compiler_assumptions[{index}]",
        )
        assumption_names.append(
            _text(item["assumption"], f"compiler_assumptions[{index}].assumption")
        )
        _text(item["evidence"], f"compiler_assumptions[{index}].evidence")
        _sha256(
            item["evidence_sha256"],
            f"compiler_assumptions[{index}].evidence_sha256",
        )
    if assumption_names != criterion["required_compiler_assumptions"]:
        raise ContractError("compiler assumption evidence is not exhaustive")

    return {
        "native_decide_policy": policy["selection"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "native_decide_uses": [dict(item) for item in native_decide_uses],
        "compiler_assumptions": [dict(item) for item in compiler_assumptions],
        "claim_consequence": policy["claim_consequence"],
    }


def validate_proxy_receipt(
    receipt: Any,
    *,
    run_id: str,
    sequence: int,
    request_id: str,
    model_id: str,
    request_sha256: str,
    response_sha256: str,
    seen_receipt_sha256: set[str] | frozenset[str],
    seen_request_ids: set[str] | frozenset[str] = frozenset(),
) -> Decimal:
    """Authenticate one exact, ordered receipt before returning its cost."""
    receipt = _exact_dict(
        receipt,
        {
            "schema",
            "proxy_id",
            "route_id",
            "run_id",
            "sequence",
            "request_id",
            "model_id",
            "request_sha256",
            "response_sha256",
            "status",
            "usage",
            "cost",
            "auth",
            "receipt_sha256",
        },
        "proxy receipt",
    )
    lock = load_toolchain_lock()
    proxy, schema = lock["fixed_proxy"], lock["fixed_proxy"]["receipt_schema"]
    if receipt["schema"] != schema["schema"]:
        raise ContractError("proxy receipt schema mismatch")
    expected = {
        "proxy_id": proxy["proxy_id"],
        "route_id": proxy["route_id"],
        "run_id": run_id,
        "sequence": sequence,
        "request_id": request_id,
        "model_id": model_id,
        "request_sha256": request_sha256,
        "response_sha256": response_sha256,
    }
    for field, value in expected.items():
        if receipt[field] != value:
            raise ContractError(f"proxy receipt {field} mismatch")
    if type(receipt["sequence"]) is not int or receipt["sequence"] <= 0:
        raise ContractError("proxy receipt sequence must be a positive integer")
    _text(receipt["run_id"], "receipt run_id")
    _text(receipt["request_id"], "receipt request_id")
    _text(receipt["model_id"], "receipt model_id")
    _sha256(receipt["request_sha256"], "receipt request_sha256")
    _sha256(receipt["response_sha256"], "receipt response_sha256")
    if receipt["status"] not in schema["status_values"]:
        raise ContractError("proxy receipt status is unknown")

    usage = _exact_dict(
        receipt["usage"],
        {"input_tokens", "output_tokens", "total_tokens"},
        "proxy receipt usage",
    )
    if any(type(usage[name]) is not int or usage[name] < 0 for name in usage):
        raise ContractError("proxy receipt token counts must be non-negative integers")
    if usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]:
        raise ContractError("proxy receipt total_tokens must equal input plus output")

    cost = _exact_dict(receipt["cost"], {"amount", "currency"}, "proxy receipt cost")
    if cost["currency"] != schema["cost"]["currency"]:
        raise ContractError("proxy receipt currency mismatch")
    if not isinstance(cost["amount"], str) or DECIMAL_USD.fullmatch(cost["amount"]) is None:
        raise ContractError("proxy receipt cost amount must be canonical scale-6 decimal text")
    amount = Decimal(cost["amount"])

    auth = _exact_dict(
        receipt["auth"], {"algorithm", "key_id", "signature"}, "proxy receipt auth"
    )
    auth_contract = schema["authentication"]
    if auth["algorithm"] != auth_contract["algorithm"]:
        raise ContractError("proxy receipt authentication algorithm mismatch")
    if auth["key_id"] != auth_contract["key_id"]:
        raise ContractError("proxy receipt authentication key mismatch")
    try:
        signature = base64.b64decode(auth["signature"], validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ContractError("proxy receipt signature is not canonical base64") from exc
    if len(signature) != 64:
        raise ContractError("proxy receipt Ed25519 signature must be 64 bytes")

    signed = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    signed["auth"] = {"algorithm": auth["algorithm"], "key_id": auth["key_id"]}
    signed_bytes = canonical_json_bytes(signed)
    digest = hashlib.sha256(signed_bytes).hexdigest()
    receipt_digest = _sha256(receipt["receipt_sha256"], "receipt receipt_sha256")
    if not hmac.compare_digest(digest, receipt_digest):
        raise ContractError("proxy receipt hash mismatch")

    key = serialization.load_pem_public_key(auth_contract["public_key_pem"].encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ContractError("proxy receipt public key is not Ed25519")
    key_der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(
        hashlib.sha256(key_der).hexdigest(), auth_contract["public_key_der_sha256"]
    ):
        raise ContractError("proxy receipt public key identity mismatch")
    try:
        key.verify(signature, signed_bytes)
    except InvalidSignature as exc:
        raise ContractError("proxy receipt signature verification failed") from exc
    if receipt_digest in seen_receipt_sha256:
        raise ContractError("duplicate proxy receipt")
    if receipt["request_id"] in seen_request_ids:
        raise ContractError("duplicate proxy request receipt")
    return amount


class _RunState(TypedDict, total=False):
    run: dict[str, Any]
    manifest: dict[str, Any]
    config: dict[str, Any]
    run_round: Any
    graph: dict[str, Any]
    receipts: list[dict[str, Any]]
    cost: Decimal
    accepted: dict[str, Any]
    result: dict[str, Any]
    verifier_report: dict[str, Any]
    termination_detail: str


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _prompt_sha256(run_id: str, request_id: str, role: str) -> str:
    raw = f"{run_id}\0{request_id}\0{role}\0bounded-v1".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _model_request(
    state: _RunState,
    *,
    request_id: str,
    role: str,
    input_hashes: list[str],
    batch_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    run, config = state["run"], state["config"]
    sequence = len(state["receipts"]) + 1
    request = {
        "schema": "autofv-model-request/v1",
        "run_id": run["run_id"],
        "sequence": sequence,
        "batch_id": batch_id,
        "request_id": request_id,
        "role": role,
        "model_id": config["model"],
        "input_hashes": sorted(set(input_hashes)),
        "prompt_sha256": _prompt_sha256(run["run_id"], request_id, role),
    }
    runner = state["run_round"]
    if runner is agentproc.run_round:
        response, receipt = worker.proxy_round(run, request)
    else:
        response, receipt = runner(request)
    response = _validate_model_response(response, request, run["base_commit"])
    request_sha256 = _canonical_sha256(request)
    response_sha256 = _canonical_sha256(response)
    amount = validate_proxy_receipt(
        receipt,
        run_id=run["run_id"],
        sequence=sequence,
        request_id=request_id,
        model_id=config["model"],
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        seen_receipt_sha256={item["receipt_sha256"] for item in state["receipts"]},
        seen_request_ids={item["request_id"] for item in state["receipts"]},
    )
    if receipt["status"] != "ok":
        raise ContractError("model proxy returned a non-success status")
    new_cost = state["cost"] + amount
    if new_cost > config["max_cost_usd"]:
        raise ContractError("model proxy cost budget exceeded")
    state["cost"] = new_cost
    state["receipts"].append(receipt)
    run["events"].append(f"proxy:{request_id}")
    return response, receipt


def _validate_model_response(
    response: Any, request: dict[str, Any], base_commit: str
) -> dict[str, Any]:
    response = _exact_dict(
        response,
        {
            "schema",
            "run_id",
            "sequence",
            "batch_id",
            "request_id",
            "role",
            "model_id",
            "input_hashes",
            "prompt_sha256",
            "kind",
            "assigned_path",
            "base_commit",
            "statement_fingerprints",
            "payload",
            "payload_sha256",
        },
        "model response",
    )
    linked = {
        key: request[key]
        for key in (
            "run_id",
            "sequence",
            "batch_id",
            "request_id",
            "role",
            "model_id",
            "input_hashes",
            "prompt_sha256",
        )
    }
    if response["schema"] != "autofv-model-response/v1" or any(
        response[key] != value for key, value in linked.items()
    ):
        raise ContractError("model response request identity mismatch")
    if response["base_commit"] != base_commit:
        raise ContractError("model response base commit mismatch")
    if response["kind"] not in {"scout", "dependency_plan", "statement", "patch"}:
        raise ContractError("model response kind is unsupported")
    fingerprints = response["statement_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or fingerprints != sorted(set(fingerprints))
        or any(HEX_SHA256.fullmatch(value) is None for value in fingerprints)
    ):
        raise ContractError("model response statement fingerprints are invalid")
    if not isinstance(response["payload"], dict):
        raise ContractError("model response payload must be an object")
    payload_sha256 = _sha256(response["payload_sha256"], "model response payload hash")
    if not hmac.compare_digest(payload_sha256, _canonical_sha256(response["payload"])):
        raise ContractError("model response payload hash mismatch")
    payload = response["payload"]
    if response["kind"] == "statement":
        if payload.get("schema") != "autofv-statement-candidate/v1":
            raise ContractError("statement candidate schema mismatch")
        text = _text(payload.get("text"), "statement candidate text")
        if payload.get("text_sha256") != hashlib.sha256(text.encode()).hexdigest():
            raise ContractError("statement candidate text hash mismatch")
    elif response["kind"] == "patch":
        if payload.get("schema") != "autofv-candidate-patch/v1":
            raise ContractError("patch candidate schema mismatch")
        patch = payload.get("patch")
        if (
            not isinstance(patch, str)
            or not patch
            or "\r" in patch
            or "\x00" in patch
        ):
            raise ContractError("candidate patch must be canonical UTF-8 text")
        if payload.get("patch_sha256") != hashlib.sha256(patch.encode()).hexdigest():
            raise ContractError("candidate patch hash mismatch")
        if (
            payload.get("assigned_path") != response["assigned_path"]
            or payload.get("base_commit") != base_commit
            or payload.get("statement_fingerprints") != fingerprints
        ):
            raise ContractError("candidate patch bindings mismatch")
    return response


def _statement_fingerprint(run: dict[str, Any], graph: dict[str, Any]) -> str:
    spec = graph["supplied_specs"][graph["frozen_targets"][0]]
    source = worker.read_project_file(run, graph["source_paths"][spec]).decode("utf-8")
    name = spec.removeprefix("probe:").rsplit(".", 1)[-1]
    lines = source.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.lstrip().startswith(f"theorem {name}")),
        None,
    )
    if start is None:
        raise ContractError("supplied target statement is missing from its source")
    statement: list[str] = []
    for line in lines[start:]:
        if ":=" in line:
            statement.append(line.split(":=", 1)[0].rstrip())
            break
        statement.append(line)
    else:
        raise ContractError("supplied target statement has no theorem body")
    return hashlib.sha256("\n".join(statement).encode("utf-8")).hexdigest()


def _freeze(state: _RunState) -> dict[str, Any]:
    rust_raw, aeneas_raw = worker.run_probes(state["run"])
    graph = probes.parse_probe_bytes(state["manifest"], rust_raw, aeneas_raw)
    state["run"]["events"].append("targets_frozen")
    return {"graph": graph}


def _agent_loop(state: _RunState) -> dict[str, Any]:
    graph, run, manifest = state["graph"], state["run"], state["manifest"]
    if len(graph["frozen_targets"]) != 1 or len(graph["proof_batches"]) != 2:
        raise ContractError("the V1 tracer requires one acyclic diamond target")
    top_fingerprint = _statement_fingerprint(run, graph)
    probe_hash = graph["graph_sha256"]

    scout, _ = _model_request(
        state,
        request_id="scout-001",
        role="scout",
        input_hashes=[probe_hash],
    )
    dependency, _ = _model_request(
        state,
        request_id="dependency-plan-001",
        role="dependency-planner",
        input_hashes=[scout["payload_sha256"], probe_hash],
    )
    weak_left, _ = _model_request(
        state,
        request_id="contract-left-001",
        role="contract-author",
        input_hashes=[dependency["payload_sha256"], top_fingerprint],
    )
    right, _ = _model_request(
        state,
        request_id="contract-right-001",
        role="contract-author",
        input_hashes=[dependency["payload_sha256"], top_fingerprint],
    )
    strong_left, _ = _model_request(
        state,
        request_id="contract-left-review-002",
        role="contract-reviewer",
        input_hashes=[weak_left["payload"]["text_sha256"], top_fingerprint],
    )
    left_fingerprint = strong_left["payload"]["text_sha256"]
    right_fingerprint = right["payload"]["text_sha256"]

    proof_left, _ = _model_request(
        state,
        request_id="proof-left-001",
        role="proof-author",
        batch_id="proof-leaves-001",
        input_hashes=[left_fingerprint, probe_hash],
    )
    accepted = worker.accept_candidate(run, proof_left, manifest)
    run["accepted"] = accepted
    proof_right, _ = _model_request(
        state,
        request_id="proof-right-001",
        role="proof-author",
        batch_id="proof-leaves-001",
        input_hashes=[right_fingerprint, probe_hash],
    )
    accepted = worker.accept_candidate(run, proof_right, manifest)
    run["accepted"] = accepted
    proof_top, _ = _model_request(
        state,
        request_id="proof-top-001",
        role="proof-author",
        input_hashes=[
            left_fingerprint,
            right_fingerprint,
            top_fingerprint,
            proof_left["payload"]["patch_sha256"],
            proof_right["payload"]["patch_sha256"],
        ],
    )
    accepted = worker.accept_candidate(run, proof_top, manifest)
    run["accepted"] = accepted
    return {
        "accepted": accepted,
        "receipts": state["receipts"],
        "cost": state["cost"],
    }


def _clean_verify(state: _RunState) -> dict[str, Any]:
    run, graph, accepted = state["run"], state["graph"], state["accepted"]
    expected = {
        "snapshot_sha256": run["snapshot_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "probe_rust_sha256": graph["probe_rust_sha256"],
        "probe_aeneas_sha256": graph["probe_aeneas_sha256"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "accepted_commit": accepted["accepted_commit"],
        "accepted_tree_sha256": accepted["accepted_tree_sha256"],
    }
    report = verifier.validate_report(verifier.verify_run(run, expected), run, expected)
    run["events"].append("clean_verifier:PASS")
    return {"verifier_report": report}


def _build_graph():
    graph = StateGraph(_RunState)
    graph.add_node("freeze", _freeze)
    graph.add_node("agent", _agent_loop)
    graph.add_node("verify", _clean_verify)
    graph.add_edge(START, "freeze")
    graph.add_edge("freeze", "agent")
    graph.add_edge("agent", "verify")
    graph.add_edge("verify", END)
    return graph.compile()


_EXPERIMENT_GRAPH = _build_graph()


def _result(
    run: dict[str, Any], state: _RunState, *, outcome: str, reason: str
) -> dict[str, Any]:
    graph = state.get("graph", {})
    accepted = state.get("accepted", run.get("accepted", {}))
    report = state.get("verifier_report", {})
    cost = sum(
        (Decimal(item["cost"]["amount"]) for item in state.get("receipts", [])),
        Decimal("0.000000"),
    )
    run["events"].append("result_emitted")
    return {
        "schema": "autofv-result/v1",
        "run_id": run["run_id"],
        "execution_tier": run["execution_tier"],
        "cost_classification": run["cost_classification"],
        "outcome": outcome,
        "termination_reason": reason,
        "termination_detail": state.get("termination_detail"),
        "frozen_targets": graph.get("frozen_targets", []),
        "targets_total": len(graph.get("frozen_targets", [])),
        "targets_verified_final": 1 if outcome == "success" else 0,
        "internal_specs_accepted": 2 if outcome == "success" else 0,
        "internal_proofs_accepted": 2 if outcome == "success" else 0,
        "proxy_requests": len(state.get("receipts", [])),
        "cost_usd": f"{cost:.6f}",
        "native_decide_policy": run["native_decide_policy"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "snapshot_sha256": run["snapshot_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "probe_rust_sha256": graph.get("probe_rust_sha256"),
        "probe_aeneas_sha256": graph.get("probe_aeneas_sha256"),
        "graph_sha256": graph.get("graph_sha256"),
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "accepted_commit": accepted.get("accepted_commit"),
        "accepted_tree_sha256": accepted.get("accepted_tree_sha256"),
        "verifier_report_sha256": report.get("report_sha256"),
        "events": list(run["events"]),
    }


def _l0_receipt(run: dict[str, Any], state: _RunState, result: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": "autofv-evidence-l0/v1",
        "run_id": run["run_id"],
        "outcome": result["outcome"],
        "result_sha256": _canonical_sha256(result),
        "proxy_receipt_sha256": [
            item["receipt_sha256"] for item in state.get("receipts", [])
        ],
        "events": result["events"],
    }
    return {**body, "receipt_sha256": _canonical_sha256(body)}


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    run_round=agentproc.run_round,
) -> dict[str, Any]:
    """Run the bounded sealed tracer and reduce every post-allocation exit."""
    target_path, manifest = validate_target(target)
    _, config = validate_run_config(run_config)
    lock = load_toolchain_lock()
    policy = validate_native_decide_policy(lock)
    preparation_failure = None
    try:
        run = worker.prepare_run(target_path, manifest, lock)
    except worker.WorkerError as exc:
        if exc.run is None:
            raise
        run = exc.run
        preparation_failure = exc
    run.update(
        {
            "manifest": manifest,
            "native_decide_policy": policy["selection"],
            "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        }
    )
    state: _RunState = {
        "run": run,
        "manifest": manifest,
        "config": config,
        "run_round": run_round,
        "receipts": [],
        "cost": Decimal("0.000000"),
    }
    try:
        if preparation_failure is not None:
            raise preparation_failure
        for update in _EXPERIMENT_GRAPH.stream(state, stream_mode="updates"):
            for values in update.values():
                state.update(values)
        result = _result(run, state, outcome="success", reason="all_targets_verified")
    except (ContractError, probes.ProbeError, worker.WorkerError, verifier.VerifierError) as exc:
        state["termination_detail"] = str(exc)[:1000]
        result = _result(
            run,
            state,
            outcome="failure",
            reason=(
                "infrastructure_failed"
                if exc is preparation_failure
                else type(exc).__name__.removesuffix("Error").lower()
            ),
        )
    worker.persist_result(run, result, _l0_receipt(run, state, result))
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autofv")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--run-config", required=True)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    try:
        result = run_experiment(args.target, args.run_config)
    except ContractError as exc:
        parser.error(str(exc))
    print(canonical_json_bytes(result).decode("utf-8"))
    if result["outcome"] != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
