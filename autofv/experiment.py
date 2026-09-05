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
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
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


class ContractInconclusive(ContractError):
    """The bounded provisional consumer proof could not freeze contracts."""


class BudgetExhausted(ContractError):
    """A run-wide wall or authenticated-cost limit stopped new work."""

    def __init__(self, kind: str, limit: Decimal, used: Decimal):
        self.kind = kind
        self.detail = {
            "kind": kind,
            "limit": f"{limit:.6f}",
            "used": f"{used:.6f}",
        }
        super().__init__(
            f"{kind} budget stopped new work: used={used:.6f}, limit={limit:.6f}"
        )


CHECKPOINT_SCHEMA = "autofv-checkpoint/v1"
CHECKPOINT_RUN_FIELDS = (
    "run_id",
    "run_root",
    "project_dir",
    "evidence_dir",
    "volume",
    "agent_worker_id",
    "execution_tier",
    "cost_classification",
    "snapshot_sha256",
    "manifest_sha256",
    "image_digest",
    "control_bundle_sha256",
    "native_decide_policy",
    "native_decide_policy_sha256",
    "base_commit",
    "events",
)
CHECKPOINT_STATE_FIELDS = (
    "graph",
    "contracts",
    "receipts",
    "accepted",
    "working",
    "result",
    "verifier_report",
    "lanes",
    "lane_intervals",
    "candidate_receipts",
    "processed_candidate_sha256",
    "accepted_sequence",
    "accepted_nodes",
    "pending_model_exchanges",
    "model_exchanges",
    "inflight_transition",
    "receipt_rejections",
    "wall_seconds_used",
    "finalization_reserve_seconds",
)


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
    if (
        isinstance(cost, bool)
        or not isinstance(cost, (int, Decimal, str))
        or isinstance(cost, str)
        and DECIMAL_USD.fullmatch(cost) is None
    ):
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
    contracts: dict[str, Any]
    receipts: list[dict[str, Any]]
    cost: Decimal
    accepted: dict[str, Any]
    result: dict[str, Any]
    verifier_report: dict[str, Any]
    termination_detail: str | dict[str, str]
    lanes: list[dict[str, Any]]
    lane_intervals: dict[str, dict[str, int]]
    candidate_receipts: list[dict[str, Any]]
    processed_candidate_sha256: list[str]
    accepted_sequence: list[dict[str, Any]]
    accepted_nodes: list[str]
    receipt_rejections: list[dict[str, Any]]
    wall_seconds_used: Decimal
    finalization_reserve_seconds: Decimal
    wall_started_monotonic_ns: int
    _accept_lock: Any


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _finalization_reserve(config: dict[str, Any]) -> Decimal:
    return min(Decimal("5.000000"), Decimal(config["max_wall_seconds"]) / 10)


def _charge_wall(state: _RunState) -> Decimal:
    now = time.monotonic_ns()
    started = state.get("wall_started_monotonic_ns")
    state["wall_started_monotonic_ns"] = now
    used = Decimal(state.get("wall_seconds_used", Decimal("0.000000")))
    if started is not None:
        if now < started:
            raise ContractError("monotonic clock moved backwards")
        used += Decimal(now - started) / Decimal(1_000_000_000)
    state["wall_seconds_used"] = used
    return used


def _check_wall_budget(state: _RunState) -> None:
    used = _charge_wall(state)
    config = state.get("config", {})
    if "max_wall_seconds" not in config:
        return
    limit = Decimal(config["max_wall_seconds"])
    reserve = Decimal(
        state.get("finalization_reserve_seconds", _finalization_reserve(config))
    )
    if used >= limit - reserve:
        raise BudgetExhausted("wall_seconds", limit, used)


def _check_budget(state: _RunState) -> None:
    _check_wall_budget(state)
    config = state.get("config", {})
    if "max_cost_usd" not in config:
        return
    cost = Decimal(state.get("cost", Decimal("0.000000")))
    limit = Decimal(config["max_cost_usd"])
    if cost >= limit:
        raise BudgetExhausted("cost_usd", limit, cost)


def _checkpoint_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return f"{value:.6f}"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _checkpoint_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_checkpoint_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ContractError(f"checkpoint value is not serializable: {type(value).__name__}")


def _checkpoint_identities(run: dict[str, Any]) -> dict[str, Any]:
    identities = {
        name: run[name]
        for name in (
            "run_id",
            "snapshot_sha256",
            "manifest_sha256",
            "image_digest",
            "control_bundle_sha256",
            "native_decide_policy_sha256",
            "volume",
            "base_commit",
        )
        if name in run
    }
    lock = run.get("lock")
    if isinstance(lock, dict):
        identities["toolchain_lock_sha256"] = _canonical_sha256(lock)
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        if name in run:
            identities[name] = run[name]
    return identities


def _checkpoint_config_sha256(config: dict[str, Any]) -> str:
    return _canonical_sha256(_checkpoint_value(config))


def _checkpoint_payload(state: _RunState, transition: str, sequence: int) -> dict[str, Any]:
    run = state["run"]
    identities = _checkpoint_identities(run)
    identities["run_config_sha256"] = _checkpoint_config_sha256(state["config"])
    graph = state.get("graph", {})
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        if name in graph:
            identities[name] = graph[name]
    body = {
        "schema": CHECKPOINT_SCHEMA,
        "complete": True,
        "checkpoint_sequence": sequence,
        "event_sequence": sequence,
        "event_id": f"checkpoint-{sequence:08d}",
        "transition": _text(transition, "checkpoint transition"),
        "identities": identities,
        "run": {
            name: _checkpoint_value(run[name])
            for name in CHECKPOINT_RUN_FIELDS
            if name in run
        },
        "state": {
            name: _checkpoint_value(state[name])
            for name in CHECKPOINT_STATE_FIELDS
            if name in state
        },
        "cost_usd_used": f"{state.get('cost', Decimal('0.000000')):.6f}",
    }
    return {**body, "content_sha256": _canonical_sha256(body)}


def _write_checkpoint(state: _RunState, transition: str) -> Path:
    """Durably replace one complete checkpoint without trusting directory order."""
    sequence = int(state.get("checkpoint_sequence", 0)) + 1
    state["checkpoint_sequence"] = sequence
    payload = _checkpoint_payload(state, transition, sequence)
    directory = Path(state["run"]["run_root"]) / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{sequence:08d}.json"
    temporary = directory / f".{sequence:08d}.tmp"
    with temporary.open("wb") as output:
        output.write(canonical_json_bytes(payload) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return destination


def _valid_checkpoint(
    value: Any, expected_identities: dict[str, Any]
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if set(value) != {
        "schema",
        "complete",
        "checkpoint_sequence",
        "event_sequence",
        "event_id",
        "transition",
        "identities",
        "run",
        "state",
        "cost_usd_used",
        "content_sha256",
    }:
        return None
    content_hash = value.get("content_sha256")
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    if (
        value.get("schema") != CHECKPOINT_SCHEMA
        or value.get("complete") is not True
        or type(value.get("checkpoint_sequence")) is not int
        or value["checkpoint_sequence"] <= 0
        or value.get("event_sequence") != value["checkpoint_sequence"]
        or value.get("event_id")
        != f"checkpoint-{value['checkpoint_sequence']:08d}"
        or not isinstance(content_hash, str)
        or not hmac.compare_digest(content_hash, _canonical_sha256(body))
        or not isinstance(value.get("identities"), dict)
        or not isinstance(value.get("run"), dict)
        or not isinstance(value.get("state"), dict)
        or not isinstance(value.get("cost_usd_used"), str)
        or DECIMAL_USD.fullmatch(value["cost_usd_used"]) is None
    ):
        return None
    identities, run = value["identities"], value["run"]
    if any(
        identities.get(name) != run.get(name)
        for name in (
            "run_id",
            "snapshot_sha256",
            "manifest_sha256",
            "image_digest",
            "control_bundle_sha256",
            "native_decide_policy_sha256",
            "volume",
            "base_commit",
        )
    ):
        return None
    if any(value["identities"].get(key) != item for key, item in expected_identities.items()):
        return None
    return value


def _load_checkpoint(
    run_root: str | Path, expected_identities: dict[str, Any]
) -> dict[str, Any]:
    valid: dict[int, dict[str, Any]] = {}
    for path in (Path(run_root) / "checkpoints").glob("*.json"):
        try:
            candidate = _valid_checkpoint(_read_json(path, "checkpoint"), expected_identities)
        except ContractError:
            continue
        if candidate is None:
            continue
        try:
            checkpoint_root = Path(candidate["run"]["run_root"]).resolve(strict=True)
        except (KeyError, OSError, TypeError):
            continue
        if checkpoint_root != Path(run_root).resolve(strict=True):
            continue
        sequence = candidate["checkpoint_sequence"]
        previous = valid.get(sequence)
        if previous is not None and previous["content_sha256"] != candidate["content_sha256"]:
            raise ContractError(f"conflicting checkpoint sequence {sequence}")
        valid[sequence] = candidate
    if not valid:
        raise ContractError("no complete hash-valid compatible checkpoint")
    return valid[max(valid)]


def _resume_record_matches(observed: dict[str, Any], expected: dict[str, Any]) -> bool:
    return bool(
        observed.get("valid")
        and observed.get("accepted_commit") == expected.get("accepted_commit")
        and observed.get("accepted_tree_sha256")
        == expected.get("accepted_tree_sha256")
    )


def _restore_checkpoint(
    checkpoint: dict[str, Any],
    *,
    manifest: dict[str, Any],
    config: dict[str, Any],
    lock: dict[str, Any],
    run_round: Any,
) -> _RunState:
    """Reattach trusted runtime objects and recover working state or accepted Git."""
    run = dict(checkpoint["run"])
    run["lock"] = lock
    state: _RunState = dict(checkpoint["state"])
    state.update(
        {
            "run": run,
            "manifest": manifest,
            "config": config,
            "run_round": run_round,
            "cost": Decimal(checkpoint["cost_usd_used"]),
            "wall_seconds_used": Decimal(
                state.get("wall_seconds_used", "0.000000")
            ),
            "finalization_reserve_seconds": Decimal(
                state.get(
                    "finalization_reserve_seconds", _finalization_reserve(config)
                )
            ),
            "checkpoint_sequence": checkpoint["checkpoint_sequence"],
            "_accept_lock": threading.Lock(),
        }
    )
    accepted = state.get("accepted")
    working = state.get("working") or accepted
    observed = worker.inspect_resume_state(run, manifest)
    inflight = state.pop("inflight_transition", None)
    if isinstance(inflight, dict) and inflight.get("kind") == "candidate_accept":
        digest = inflight.get("candidate_sha256")
        processed = state.setdefault("processed_candidate_sha256", [])
        if digest in processed:
            processed.remove(digest)
        for lane in state.get("lanes", []):
            if lane.get("node") == inflight.get("node"):
                lane["status"] = "interrupted"
                lane["requeueable"] = True
    if isinstance(working, dict) and _resume_record_matches(observed, working):
        source = "working"
    else:
        if not isinstance(accepted, dict) or not {
            "accepted_commit",
            "accepted_tree_sha256",
        } <= accepted.keys():
            raise ContractError("checkpoint has no restorable accepted state")
        observed = worker.restore_accepted(run, accepted, manifest)
        if not _resume_record_matches(observed, accepted):
            raise ContractError("restored accepted state did not match checkpoint")
        state["working"] = dict(accepted)
        source = "accepted"
    for lane in state.get("lanes", []):
        if lane.get("status") in {"preparing", "running"}:
            lane["status"] = "interrupted"
            lane["requeueable"] = True
    state["recovery_source"] = source
    event = f"resumed:{source}"
    if event not in run.setdefault("events", []):
        run["events"].append(event)
    _write_checkpoint(state, event)
    return state


def _checkpoint_if_enabled(state: _RunState, transition: str) -> None:
    if state.get("checkpoint_enabled"):
        _write_checkpoint(state, transition)


def _event_once(run: dict[str, Any], event: str) -> None:
    if event not in run.setdefault("events", []):
        run["events"].append(event)


def _external_call(state: _RunState, transition: str, call) -> Any:
    _check_budget(state)
    _checkpoint_if_enabled(state, f"{transition}:before")
    try:
        value = call()
    except Exception:
        _charge_wall(state)
        _checkpoint_if_enabled(state, f"{transition}:failed")
        raise
    _charge_wall(state)
    _checkpoint_if_enabled(state, f"{transition}:after")
    return value


def _prompt_sha256(run_id: str, request_id: str, role: str) -> str:
    raw = f"{run_id}\0{request_id}\0{role}\0bounded-v1".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _model_envelope(
    state: _RunState,
    *,
    request_id: str,
    role: str,
    input_hashes: list[str],
    batch_id: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    run, config = state["run"], state["config"]
    return {
        "schema": "autofv-model-request/v1",
        "run_id": run["run_id"],
        "sequence": sequence if sequence is not None else len(state["receipts"]) + 1,
        "batch_id": batch_id,
        "request_id": request_id,
        "role": role,
        "model_id": config["model"],
        "input_hashes": sorted(set(input_hashes)),
        "prompt_sha256": _prompt_sha256(run["run_id"], request_id, role),
    }


def _invoke_model(
    state: _RunState, request: dict[str, Any], *, checkpoint: bool = True
) -> tuple[dict[str, Any], dict[str, Any]]:
    if checkpoint:
        _check_budget(state)
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:before")
    runner = state["run_round"]
    try:
        if runner is agentproc.run_round:
            exchange = worker.proxy_round(state["run"], request)
        else:
            exchange = runner(request)
    except Exception:
        if checkpoint:
            _charge_wall(state)
            _checkpoint_if_enabled(state, f"model:{request['request_id']}:failed")
        raise
    if checkpoint:
        _charge_wall(state)
        state.setdefault("pending_model_exchanges", {})[request["request_id"]] = {
            "request": request,
            "response": exchange[0],
            "receipt": exchange[1],
        }
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:after")
    return exchange


def _accept_model_exchange(
    state: _RunState,
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
    *,
    enforce_budget: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    run, config = state["run"], state["config"]
    response = _validate_model_response(response, request, run["base_commit"])
    request_sha256 = _canonical_sha256(request)
    response_sha256 = _canonical_sha256(response)
    try:
        amount = validate_proxy_receipt(
            receipt,
            run_id=run["run_id"],
            sequence=request["sequence"],
            request_id=request["request_id"],
            model_id=config["model"],
            request_sha256=request_sha256,
            response_sha256=response_sha256,
            seen_receipt_sha256={
                item["receipt_sha256"] for item in state["receipts"]
            },
            seen_request_ids={item["request_id"] for item in state["receipts"]},
        )
        if request["sequence"] != len(state["receipts"]) + 1:
            raise ContractError("proxy receipt sequence is not next for this run")
    except ContractError as exc:
        try:
            payload_sha256 = _canonical_sha256(receipt)
        except ContractError:
            payload_sha256 = hashlib.sha256(
                f"noncanonical:{type(receipt).__name__}".encode()
            ).hexdigest()
        state.setdefault("receipt_rejections", []).append(
            {
                "request_id": request.get("request_id"),
                "sequence": request.get("sequence"),
                "receipt_payload_sha256": payload_sha256,
                "reason": str(exc)[:1000],
            }
        )
        _checkpoint_if_enabled(state, f"receipt:{request.get('request_id')}:rejected")
        raise

    request = json.loads(canonical_json_bytes(request))
    response = json.loads(canonical_json_bytes(response))
    receipt = json.loads(canonical_json_bytes(receipt))
    new_cost = state["cost"] + amount
    state["cost"] = new_cost
    state["receipts"].append(receipt)
    exchange = {"request": request, "response": response, "receipt": receipt}
    state.setdefault("model_exchanges", {})[request["request_id"]] = exchange
    state.setdefault("pending_model_exchanges", {}).pop(request["request_id"], None)
    _event_once(run, f"proxy:{request['request_id']}")
    if enforce_budget and new_cost > config["max_cost_usd"]:
        _checkpoint_if_enabled(state, "budget:cost_usd")
        raise BudgetExhausted("cost_usd", config["max_cost_usd"], new_cost)
    if receipt["status"] != "ok":
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:rejected")
        raise ContractError("model proxy returned a non-success status")
    if enforce_budget:
        try:
            _check_wall_budget(state)
        except BudgetExhausted:
            _checkpoint_if_enabled(state, "budget:wall_seconds")
            raise
    _checkpoint_if_enabled(state, f"model:{request['request_id']}:accepted")
    return response, receipt


def _model_request(
    state: _RunState,
    *,
    request_id: str,
    role: str,
    input_hashes: list[str],
    batch_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = _model_envelope(
        state,
        request_id=request_id,
        role=role,
        input_hashes=input_hashes,
        batch_id=batch_id,
    )
    completed = state.setdefault("model_exchanges", {}).get(request_id)
    if completed is not None:
        if completed.get("request") != request:
            raise ContractError(f"resumed model request changed: {request_id}")
        return completed["response"], completed["receipt"]
    pending = state.setdefault("pending_model_exchanges", {}).get(request_id)
    if pending is not None:
        if pending.get("request") != request:
            raise ContractError(f"pending model request changed: {request_id}")
        return _accept_model_exchange(
            state, request, pending.get("response"), pending.get("receipt")
        )
    return _accept_model_exchange(state, request, *_invoke_model(state, request))


def _parallel_model_requests(
    state: _RunState, requests: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Run one proof frontier concurrently and account for it serially."""
    if len(requests) < 2:
        raise ContractError("a parallel proof frontier needs at least two lanes")
    stored = {
        **state.setdefault("model_exchanges", {}),
        **state.setdefault("pending_model_exchanges", {}),
    }
    used_sequences = [
        exchange["request"]["sequence"]
        for exchange in stored.values()
        if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict)
    ] + [item["sequence"] for item in state["receipts"]]
    next_sequence = max(used_sequences, default=0) + 1
    envelopes = []
    for spec in requests:
        previous = stored.get(spec["request_id"])
        sequence = (
            previous["request"]["sequence"] if previous is not None else next_sequence
        )
        envelope = _model_envelope(state, sequence=sequence, **spec)
        if previous is not None and previous.get("request") != envelope:
            raise ContractError(f"resumed model request changed: {spec['request_id']}")
        if previous is None:
            next_sequence += 1
        envelopes.append(envelope)

    missing = [
        (index, request)
        for index, request in enumerate(envelopes)
        if request["request_id"] not in stored
    ]
    start_barrier = threading.Barrier(len(missing)) if len(missing) > 1 else None

    def invoke(request):
        started = time.monotonic_ns()
        if start_barrier is not None:
            start_barrier.wait()
        response, receipt = _invoke_model(state, request, checkpoint=False)
        return response, receipt, started, time.monotonic_ns()

    raw: list[tuple[dict[str, Any], dict[str, Any], int, int] | None] = [
        None
    ] * len(envelopes)
    for index, request in enumerate(envelopes):
        previous = stored.get(request["request_id"])
        if previous is not None:
            raw[index] = (previous["response"], previous["receipt"], 0, 0)
    if missing:
        _check_budget(state)
        _checkpoint_if_enabled(state, "model:proof-leaves:before")
        try:
            if len(missing) == 1:
                index, request = missing[0]
                raw[index] = invoke(request)
            else:
                with ThreadPoolExecutor(
                    max_workers=len(missing), thread_name_prefix="autofv-proof-lane"
                ) as pool:
                    futures = [
                        (index, request, pool.submit(invoke, request))
                        for index, request in missing
                    ]
                    for index, _request, future in futures:
                        raw[index] = future.result()
        except Exception:
            _charge_wall(state)
            _checkpoint_if_enabled(state, "model:proof-leaves:failed")
            raise
        _charge_wall(state)
        for index, request in missing:
            response, receipt, _, _ = raw[index]
            state["pending_model_exchanges"][request["request_id"]] = {
                "request": request,
                "response": response,
                "receipt": receipt,
            }
            _checkpoint_if_enabled(state, f"model:{request['request_id']}:after")

    intervals = {
        request["request_id"]: {
            "started_monotonic_ns": item[2],
            "finished_monotonic_ns": item[3],
        }
        for request, item in zip(envelopes, raw, strict=True)
        if item is not None and item[2]
    }
    if len(missing) > 1 and max(
        item["started_monotonic_ns"] for item in intervals.values()
    ) >= min(item["finished_monotonic_ns"] for item in intervals.values()):
        raise ContractError("parallel proof lanes did not overlap")
    state.setdefault("lane_intervals", {}).update(intervals)
    for request, (response, receipt, _, _) in zip(envelopes, raw, strict=True):
        if request["request_id"] in state["model_exchanges"]:
            continue
        _accept_model_exchange(
            state, request, response, receipt, enforce_budget=False
        )
    if state["cost"] > state["config"]["max_cost_usd"]:
        _checkpoint_if_enabled(state, "budget:cost_usd")
        raise BudgetExhausted(
            "cost_usd", state["config"]["max_cost_usd"], state["cost"]
        )
    try:
        _check_wall_budget(state)
    except BudgetExhausted:
        _checkpoint_if_enabled(state, "budget:wall_seconds")
        raise
    exchanges = [
        (
            state["model_exchanges"][request["request_id"]]["response"],
            state["model_exchanges"][request["request_id"]]["receipt"],
        )
        for request in envelopes
    ]
    if len(missing) > 1:
        _event_once(state["run"], "proof_lanes:overlapped")
    elif missing:
        _event_once(state["run"], "proof_lanes:resumed")
    _checkpoint_if_enabled(state, "model:proof-leaves:accepted")
    return exchanges


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


def _statement_record(response: dict[str, Any], policy_sha256: str) -> dict[str, Any]:
    payload = response["payload"]
    text = payload["text"]
    return {
        "declaration": payload["declaration"],
        "kind": "theorem",
        "canon": text,
        "canonical_sha256": _canonical_sha256({"kind": "theorem", "canon": text}),
        "model_fingerprint": payload["text_sha256"],
        "consumer_fingerprints": [
            value
            for value in response["statement_fingerprints"]
            if value != payload["text_sha256"]
        ],
        "native_decide_policy_sha256": policy_sha256,
        "status": "provisional",
    }


def _candidate_binding_is_current(
    fingerprints: list[str],
    policy_sha256: str,
    current_fingerprints: list[str],
    current_policy_sha256: str,
) -> bool:
    """Return whether candidate inputs are a non-empty subset of current truth."""
    return (
        isinstance(fingerprints, list)
        and bool(fingerprints)
        and all(isinstance(value, str) for value in fingerprints)
        and fingerprints == sorted(set(fingerprints))
        and isinstance(current_fingerprints, list)
        and all(isinstance(value, str) for value in current_fingerprints)
        and set(fingerprints) <= set(current_fingerprints)
        and isinstance(policy_sha256, str)
        and isinstance(current_policy_sha256, str)
        and hmac.compare_digest(policy_sha256, current_policy_sha256)
    )


def _lane_descriptors(
    run: dict[str, Any],
    graph: dict[str, Any],
    nodes: list[str],
    *,
    base_commit: str | None = None,
) -> list[dict[str, Any]]:
    """Describe private one-file lanes without granting canonical-tree access."""
    root = (
        str(Path(run["run_root"]) / "lanes")
        if Path(run.get("project_dir", "/volume/work/project")).is_dir()
        else "/volume/lanes"
    )
    base = base_commit or run.get("accepted", {}).get(
        "accepted_commit", run["base_commit"]
    )
    lanes = []
    assigned = set()
    for node in nodes:
        leaf = node.rsplit(".", 1)[-1].lower()
        if re.fullmatch(r"[a-z0-9-]+", leaf) is None:
            raise ContractError("proof node cannot form a safe lane identity")
        path = graph["source_paths"].get(node)
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.suffix != ".lean"
            or path in assigned
        ):
            raise ContractError("proof lane must own one distinct safe Lean path")
        assigned.add(path)
        request_id = f"proof-{leaf}-001"
        lane_root = f"{root}/{request_id}"
        lanes.append(
            {
                "schema": "autofv-proof-lane/v1",
                "lane_id": request_id,
                "request_id": request_id,
                "node": node,
                "base_commit": base,
                "assigned_path": path,
                "worktree_path": f"{lane_root}/work",
                "cache_path": f"{lane_root}/cache",
                "result_path": f"{lane_root}/result/candidate.json",
            }
        )
    return lanes


def _worker_lane(lane: dict[str, Any]) -> dict[str, Any]:
    return {
        key: lane[key]
        for key in (
            "schema",
            "lane_id",
            "request_id",
            "node",
            "base_commit",
            "assigned_path",
            "worktree_path",
            "cache_path",
            "result_path",
        )
    }


def _candidate_record(
    response: dict[str, Any], lane: dict[str, Any], policy_sha256: str
) -> dict[str, Any]:
    """Bind an untrusted lane response to its frozen inputs and private path."""
    if response.get("kind") != "patch":
        raise ContractError("proof lane returned a non-patch result")
    payload = response.get("payload", {})
    patch = payload.get("patch")
    path = lane.get("assigned_path")
    if (
        response.get("request_id") != lane.get("request_id")
        or response.get("assigned_path") != path
        or payload.get("assigned_path") != path
        or payload.get("base_commit") != response.get("base_commit")
        or not isinstance(patch, str)
        or not patch.startswith(f"diff --git a/{path} b/{path}\n")
        or patch.count("diff --git ") != 1
        or payload.get("patch_sha256") != hashlib.sha256(patch.encode()).hexdigest()
    ):
        raise ContractError("proof lane result escaped its assignment")
    local_gate = {
        "schema": "autofv-lane-gate-receipt/v1",
        "lane_id": lane["lane_id"],
        "request_id": lane["request_id"],
        "assigned_path": path,
        "source_base_commit": response["base_commit"],
        "checked_base_commit": lane["base_commit"],
        "patch_sha256": payload["patch_sha256"],
        "statement_fingerprints": response["statement_fingerprints"],
        "native_decide_policy_sha256": policy_sha256,
        "status": "passed",
        "checks": [
            "assigned_path_scope",
            "patch_sha256",
            "statement_fingerprint_binding",
            "native_decide_policy_binding",
        ],
    }
    body = {
        "schema": "autofv-candidate/v1",
        "lane_id": lane["lane_id"],
        "request_id": lane["request_id"],
        "node": lane["node"],
        "base_commit": response["base_commit"],
        "checked_base_commit": lane["base_commit"],
        "assigned_path": lane["assigned_path"],
        "worktree_path": lane["worktree_path"],
        "cache_path": lane["cache_path"],
        "result_path": lane["result_path"],
        "patch_sha256": payload.get("patch_sha256"),
        "statement_fingerprints": response.get("statement_fingerprints"),
        "native_decide_policy_sha256": policy_sha256,
        "native_decide_inventory_delta": [],
        "local_gate_receipt": local_gate,
        "local_gate_receipt_sha256": _canonical_sha256(local_gate),
        "result_sha256": _canonical_sha256(response),
    }
    return {
        **body,
        "candidate_sha256": _canonical_sha256(body),
        "response": response,
    }


def _proof_ready_nodes(graph: dict[str, Any], accepted_nodes: set[str]) -> list[str]:
    dependencies = {node: set() for node in graph["selected_nodes"]}
    for consumer, dependency in graph["term_dependencies"]:
        dependencies[consumer].add(dependency)
    return sorted(
        node
        for node, required in dependencies.items()
        if node not in accepted_nodes and required <= accepted_nodes
    )


def _checkpoint_candidate(
    state: _RunState,
    candidate: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Deduplicate and gate one candidate under the sole canonical writer."""
    lock = state.setdefault("_accept_lock", threading.Lock())
    with lock:
        response = candidate.get("response")
        body = {
            key: value
            for key, value in candidate.items()
            if key not in {"candidate_sha256", "response"}
        }
        digest = _sha256(candidate.get("candidate_sha256"), "candidate hash")
        if not hmac.compare_digest(digest, _canonical_sha256(body)):
            raise ContractError("candidate hash mismatch")
        processed = state.setdefault("processed_candidate_sha256", [])
        current = state.get("accepted") or state["run"].get("accepted") or {
            "accepted_commit": state["run"]["base_commit"]
        }
        if digest in processed:
            return {
                "status": "duplicate",
                "reason": "candidate_already_processed",
                "candidate_sha256": digest,
                "accepted_commit": current["accepted_commit"],
            }
        processed.append(digest)

        def reject(reason: str, *, requeue: bool = False) -> dict[str, Any]:
            status = "requeue" if requeue else "rejected"
            receipt = {
                "candidate_sha256": digest,
                "node": candidate.get("node"),
                "status": status,
                "reason": reason,
                "accepted_commit": current["accepted_commit"],
            }
            state.setdefault("candidate_receipts", []).append(receipt)
            state["run"]["events"].append(
                f"candidate_{status}:{candidate.get('request_id')}"
            )
            state.pop("inflight_transition", None)
            _checkpoint_if_enabled(
                state, f"candidate:{candidate.get('request_id')}:{status}"
            )
            return receipt

        if not isinstance(response, dict) or response.get("kind") != "patch":
            return reject("candidate_result_invalid")
        local_gate = candidate.get("local_gate_receipt")
        if (
            not isinstance(local_gate, dict)
            or local_gate.get("status") != "passed"
            or candidate.get("local_gate_receipt_sha256")
            != _canonical_sha256(local_gate)
            or local_gate.get("request_id") != candidate.get("request_id")
            or local_gate.get("assigned_path") != candidate.get("assigned_path")
            or local_gate.get("source_base_commit") != candidate.get("base_commit")
            or local_gate.get("checked_base_commit")
            != candidate.get("checked_base_commit")
            or local_gate.get("native_decide_policy_sha256")
            != candidate.get("native_decide_policy_sha256")
        ):
            return reject("candidate_local_gate_mismatch")
        payload = response.get("payload", {})
        path = candidate.get("assigned_path")
        patch = payload.get("patch")
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if (
            pure is None
            or pure.is_absolute()
            or ".." in pure.parts
            or not isinstance(patch, str)
            or response.get("request_id") != candidate.get("request_id")
            or response.get("assigned_path") != path
            or payload.get("assigned_path") != path
            or response.get("base_commit") != candidate.get("base_commit")
            or payload.get("base_commit") != candidate.get("base_commit")
            or candidate.get("patch_sha256") != payload.get("patch_sha256")
            or not patch.startswith(f"diff --git a/{path} b/{path}\n")
            or patch.count("diff --git ") != 1
        ):
            return reject("candidate_scope_mismatch")
        if not hmac.compare_digest(
            candidate.get("result_sha256", ""), _canonical_sha256(response)
        ):
            return reject("candidate_result_mismatch")
        frozen = state["contracts"]["frozen_fingerprints"]
        if not _candidate_binding_is_current(
            candidate.get("statement_fingerprints"),
            candidate.get("native_decide_policy_sha256", ""),
            frozen,
            state["run"]["native_decide_policy_sha256"],
        ):
            reason = (
                "candidate_policy_mismatch"
                if candidate.get("native_decide_policy_sha256")
                != state["run"]["native_decide_policy_sha256"]
                else "candidate_fingerprint_mismatch"
            )
            return reject(reason)
        if not isinstance(candidate.get("native_decide_inventory_delta"), list):
            return reject("candidate_native_decide_inventory_invalid")

        stale = candidate["base_commit"] != current["accepted_commit"]
        state["inflight_transition"] = {
            "kind": "candidate_accept",
            "candidate_sha256": digest,
            "request_id": candidate["request_id"],
            "node": candidate["node"],
            "base_commit": candidate["base_commit"],
            "previous_accepted_commit": current["accepted_commit"],
        }
        try:
            accepted = _external_call(
                state,
                f"candidate:{candidate['request_id']}:apply-build",
                lambda: worker.accept_candidate(state["run"], response, manifest),
            )
        except worker.WorkerError as exc:
            return reject(str(exc)[:1000], requeue=stale)
        if accepted.get("accepted_commit") == current["accepted_commit"]:
            return reject("candidate_did_not_advance")

        status = "accepted_reverified" if stale else "accepted"
        transition = {
            "sequence": len(state.setdefault("accepted_sequence", [])) + 1,
            "candidate_sha256": digest,
            "node": candidate["node"],
            "status": status,
            "base_commit": candidate["base_commit"],
            "previous_accepted_commit": current["accepted_commit"],
            "accepted_commit": accepted["accepted_commit"],
        }
        transition["transition_sha256"] = _canonical_sha256(transition)
        state["accepted_sequence"].append(transition)
        state["accepted"] = accepted
        state["working"] = dict(accepted)
        state["run"]["accepted"] = accepted
        accepted_nodes = state.setdefault("accepted_nodes", [])
        if candidate["node"] not in accepted_nodes:
            accepted_nodes.append(candidate["node"])
        receipt = {
            "candidate_sha256": digest,
            "node": candidate["node"],
            "status": status,
            "reason": None,
            "local_gate_receipt_sha256": candidate[
                "local_gate_receipt_sha256"
            ],
            "accepted_commit": accepted["accepted_commit"],
        }
        state.setdefault("candidate_receipts", []).append(receipt)
        state["run"]["events"].append(
            f"candidate_{status}:{candidate['request_id']}"
        )
        state.pop("inflight_transition", None)
        _checkpoint_if_enabled(
            state, f"candidate:{candidate['request_id']}:accepted"
        )
        return receipt


def _repair_contracts(
    state: _RunState,
    dependency: dict[str, Any],
    top_fingerprint: str,
) -> dict[str, Any]:
    """Run the bounded weak-draft, consumer-check, review, and freeze sequence."""
    run = state["run"]
    previous = state.get("contracts")
    if isinstance(previous, dict) and previous.get("frozen_fingerprints"):
        return previous
    policy_sha256 = run["native_decide_policy_sha256"]
    contracts = {
        "attempts": [],
        "provisional": {},
        "frozen": {},
        "frozen_fingerprints": [],
        "invalidated_fingerprints": [],
        "feasibility": [],
    }
    state["contracts"] = contracts

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
    weak_record = _statement_record(weak_left, policy_sha256)
    right_record = _statement_record(right, policy_sha256)
    contracts["attempts"].extend((weak_record, right_record))
    contracts["provisional"] = {
        weak_record["declaration"]: weak_record,
        right_record["declaration"]: right_record,
    }
    for event in (
        f"contract_draft:{weak_record['declaration']}",
        f"contract_draft:{right_record['declaration']}",
        "provisional_contracts_applied",
    ):
        _event_once(run, event)

    feasibility = _external_call(
        state,
        "build:provisional-consumer-weak",
        lambda: worker.check_contract_feasibility(
            run, [weak_record["canon"], right_record["canon"]]
        ),
    )
    contracts["feasibility"].append(feasibility)
    _event_once(run, f"provisional_consumer:{feasibility['status']}")
    if feasibility["status"] != "failed":
        raise ContractError("fixture weak contract unexpectedly passed consumer proof")

    strong_left, _ = _model_request(
        state,
        request_id="contract-left-review-002",
        role="contract-reviewer",
        input_hashes=[weak_record["model_fingerprint"], top_fingerprint],
    )
    strong_record = _statement_record(strong_left, policy_sha256)
    if (
        strong_record["declaration"] != weak_record["declaration"]
        or strong_record["model_fingerprint"] == weak_record["model_fingerprint"]
    ):
        raise ContractError("contract review did not replace the weak statement")
    contracts["attempts"].append(strong_record)
    contracts["invalidated_fingerprints"].append(weak_record["model_fingerprint"])
    contracts["provisional"][strong_record["declaration"]] = strong_record
    for event in (
        f"contract_review:{strong_record['declaration']}",
        f"statement_invalidated:{weak_record['model_fingerprint']}",
    ):
        _event_once(run, event)

    feasibility = _external_call(
        state,
        "build:provisional-consumer-strong",
        lambda: worker.check_contract_feasibility(
            run, [strong_record["canon"], right_record["canon"]]
        ),
    )
    contracts["feasibility"].append(feasibility)
    _event_once(run, f"provisional_consumer:{feasibility['status']}")
    if feasibility["status"] != "passed":
        _event_once(run, "contract_inconclusive")
        raise ContractInconclusive(feasibility["diagnostic"])

    contracts["frozen"] = {
        record["declaration"]: {**record, "status": "frozen"}
        for record in (strong_record, right_record)
    }
    contracts["provisional"] = {}
    contracts["frozen_fingerprints"] = sorted(
        [
            top_fingerprint,
            strong_record["model_fingerprint"],
            right_record["model_fingerprint"],
        ]
    )
    _event_once(run, "statements_frozen")
    _checkpoint_if_enabled(state, "contracts:frozen")
    return contracts


def _freeze(state: _RunState) -> dict[str, Any]:
    if state.get("graph"):
        return {"graph": state["graph"]}
    rust_raw, aeneas_raw = _external_call(
        state, "probe", lambda: worker.run_probes(state["run"])
    )
    graph = probes.parse_probe_bytes(state["manifest"], rust_raw, aeneas_raw)
    state["graph"] = graph
    for name in ("probe_rust_sha256", "probe_aeneas_sha256", "graph_sha256"):
        state["run"][name] = graph[name]
    _event_once(state["run"], "targets_frozen")
    _checkpoint_if_enabled(state, "probe:parsed")
    return {"graph": graph}


def _agent_loop(state: _RunState) -> dict[str, Any]:
    graph, run, manifest = state["graph"], state["run"], state["manifest"]
    if len(graph["frozen_targets"]) != 1 or len(graph["proof_batches"]) != 2:
        raise ContractError("the V1 tracer requires one acyclic diamond target")
    top_fingerprint = _external_call(
        state,
        "source:read-top-statement",
        lambda: _statement_fingerprint(run, graph),
    )
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
    contracts = _repair_contracts(state, dependency, top_fingerprint)
    leaf_nodes = graph["proof_batches"][0]
    if _proof_ready_nodes(graph, set()) != leaf_nodes:
        raise ContractError("the V1 leaf proof frontier is inconsistent")
    lanes = state.setdefault("lanes", [])
    existing_lane_ids = {lane["lane_id"] for lane in lanes}
    new_lanes = [
        {**lane, "status": "preparing"}
        for lane in _lane_descriptors(run, graph, leaf_nodes)
        if lane["lane_id"] not in existing_lane_ids
    ]
    if new_lanes:
        lanes.extend(new_lanes)
        _external_call(
            state,
            "lanes:prepare-leaves",
            lambda: worker.prepare_lanes(
                run,
                [_worker_lane(lane) for lane in new_lanes],
            ),
        )
        for lane in new_lanes:
            lane["status"] = "running"
    leaf_lanes = [lane for lane in lanes if lane["node"] in leaf_nodes]
    for key in (
        "lane_intervals",
        "candidate_receipts",
        "processed_candidate_sha256",
        "accepted_sequence",
        "accepted_nodes",
    ):
        value = state.setdefault(key, {} if key == "lane_intervals" else [])
        run[key] = value
    run["lanes"] = lanes
    exchanges = _parallel_model_requests(
        state,
        [
            {
                "request_id": lane["request_id"],
                "role": "proof-author",
                "batch_id": "proof-leaves-001",
                "input_hashes": [
                    contracts["frozen"][
                        f"{lane['node'].removeprefix('probe:')}_spec"
                    ]["model_fingerprint"],
                    probe_hash,
                ],
            }
            for lane in leaf_lanes
        ],
    )
    leaf_patches = []
    for lane, (response, _) in zip(leaf_lanes, exchanges, strict=True):
        candidate = _candidate_record(
            response, lane, run["native_decide_policy_sha256"]
        )
        if candidate["candidate_sha256"] not in state["processed_candidate_sha256"]:
            _external_call(
                state,
                f"lane:{lane['lane_id']}:persist",
                lambda candidate=candidate, lane=lane: worker.persist_lane_result(
                    run,
                    lane,
                    {
                        key: value
                        for key, value in candidate.items()
                        if key != "response"
                    },
                ),
            )
        transition = _checkpoint_candidate(state, candidate, manifest)
        if transition["status"].startswith("accepted") or (
            transition["status"] == "duplicate"
            and lane["node"] in state["accepted_nodes"]
        ):
            lane["status"] = "accepted"
            lane["requeueable"] = False
        else:
            raise ContractError(
                f"leaf candidate {lane['request_id']} was {transition['status']}: "
                f"{transition['reason']}"
            )
        leaf_patches.append(response["payload"]["patch_sha256"])

    top_batch = graph["proof_batches"][1]
    if set(top_batch) <= set(state["accepted_nodes"]):
        return {
            "accepted": state["accepted"],
            "contracts": contracts,
            "receipts": state["receipts"],
            "cost": state["cost"],
            "lanes": lanes,
            "lane_intervals": state["lane_intervals"],
            "candidate_receipts": state["candidate_receipts"],
            "processed_candidate_sha256": state["processed_candidate_sha256"],
            "accepted_sequence": state["accepted_sequence"],
            "accepted_nodes": state["accepted_nodes"],
        }
    ready = _proof_ready_nodes(graph, set(state["accepted_nodes"]))
    if ready != top_batch:
        raise ContractError("top proof became ready before both leaves were accepted")
    left_fingerprint = contracts["frozen"]["Diamond.left_spec"]["model_fingerprint"]
    right_fingerprint = contracts["frozen"]["Diamond.right_spec"]["model_fingerprint"]
    proof_top, _ = _model_request(
        state,
        request_id="proof-top-001",
        role="proof-author",
        input_hashes=[
            left_fingerprint,
            right_fingerprint,
            top_fingerprint,
            *leaf_patches,
        ],
    )
    desired_top = _lane_descriptors(run, graph, ready)[0]
    top_lane = next(
        (lane for lane in lanes if lane["lane_id"] == desired_top["lane_id"]), None
    )
    if top_lane is None:
        top_lane = {**desired_top, "status": "preparing"}
        lanes.append(top_lane)
        _external_call(
            state,
            "lanes:prepare-top",
            lambda: worker.prepare_lanes(run, [_worker_lane(top_lane)]),
        )
        top_lane["status"] = "running"
    top_candidate = _candidate_record(
        proof_top, top_lane, run["native_decide_policy_sha256"]
    )
    if top_candidate["candidate_sha256"] not in state["processed_candidate_sha256"]:
        _external_call(
            state,
            f"lane:{top_lane['lane_id']}:persist",
            lambda: worker.persist_lane_result(
                run,
                top_lane,
                {
                    key: value
                    for key, value in top_candidate.items()
                    if key != "response"
                },
            ),
        )
    transition = _checkpoint_candidate(state, top_candidate, manifest)
    if transition["status"].startswith("accepted") or (
        transition["status"] == "duplicate"
        and top_lane["node"] in state["accepted_nodes"]
    ):
        top_lane["status"] = "accepted"
        top_lane["requeueable"] = False
    else:
        raise ContractError(
            f"top candidate was {transition['status']}: {transition['reason']}"
        )
    accepted = state["accepted"]
    return {
        "accepted": accepted,
        "contracts": contracts,
        "receipts": state["receipts"],
        "cost": state["cost"],
        "lanes": lanes,
        "lane_intervals": state["lane_intervals"],
        "candidate_receipts": state["candidate_receipts"],
        "processed_candidate_sha256": state["processed_candidate_sha256"],
        "accepted_sequence": state["accepted_sequence"],
        "accepted_nodes": state["accepted_nodes"],
    }


def _clean_verify(state: _RunState) -> dict[str, Any]:
    if state.get("verifier_report", {}).get("verdict") == "PASS":
        return {"verifier_report": state["verifier_report"]}
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
    _check_budget(state)
    _checkpoint_if_enabled(state, "verifier:before")
    try:
        report = verifier.validate_report(
            verifier.verify_run(run, expected), run, expected
        )
    except Exception:
        _charge_wall(state)
        _checkpoint_if_enabled(state, "verifier:failed")
        raise
    _charge_wall(state)
    state["verifier_report"] = report
    _event_once(run, "clean_verifier:PASS")
    _checkpoint_if_enabled(state, "verifier:after")
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
    wall = _charge_wall(state)
    accepted = state.get("accepted", run.get("accepted", {}))
    report = state.get("verifier_report", {})
    frozen_contracts = state.get("contracts", {}).get("frozen", {})
    internal_nodes = set(state.get("accepted_nodes", [])) - set(
        graph.get("frozen_targets", [])
    )
    cost = sum(
        (Decimal(item["cost"]["amount"]) for item in state.get("receipts", [])),
        Decimal("0.000000"),
    )
    _event_once(run, "result_emitted")
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
        "internal_specs_accepted": len(frozen_contracts),
        "internal_proofs_accepted": len(internal_nodes),
        "proxy_requests": len(state.get("receipts", [])),
        "cost_usd": f"{cost:.6f}",
        "wall_seconds": f"{wall:.6f}",
        "finalization_reserve_seconds": (
            f"{state.get('finalization_reserve_seconds', Decimal('0')):.6f}"
        ),
        "receipt_rejections": state.get("receipt_rejections", []),
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
        "lanes": state.get("lanes", run.get("lanes", [])),
        "lane_intervals": state.get(
            "lane_intervals", run.get("lane_intervals", {})
        ),
        "candidate_receipts": state.get(
            "candidate_receipts", run.get("candidate_receipts", [])
        ),
        "processed_candidate_sha256": state.get(
            "processed_candidate_sha256",
            run.get("processed_candidate_sha256", []),
        ),
        "accepted_sequence": state.get(
            "accepted_sequence", run.get("accepted_sequence", [])
        ),
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


def _resume_identities(
    target: Path,
    manifest: dict[str, Any],
    config: dict[str, Any],
    lock: dict[str, Any],
) -> dict[str, Any]:
    control_manifest, _ = worker._control_manifest(lock)
    return {
        "snapshot_sha256": worker.hash_tree(target),
        "manifest_sha256": _canonical_sha256(manifest),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": control_manifest["bundle_sha256"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "toolchain_lock_sha256": _canonical_sha256(lock),
        "run_config_sha256": _checkpoint_config_sha256(config),
    }


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    run_round=agentproc.run_round,
    resume_from: str | Path | None = None,
) -> dict[str, Any]:
    """Run the bounded sealed tracer and reduce every post-allocation exit."""
    target_path, manifest = validate_target(target)
    _, config = validate_run_config(run_config)
    lock = load_toolchain_lock()
    policy = validate_native_decide_policy(lock)
    wall_started = time.monotonic_ns()
    preparation_failure = None
    if resume_from is not None:
        resume_root = _absolute_path(resume_from, "resume root", directory=True)
        checkpoint = _load_checkpoint(
            resume_root,
            _resume_identities(target_path, manifest, config, lock),
        )
        state = _restore_checkpoint(
            checkpoint,
            manifest=manifest,
            config=config,
            lock=lock,
            run_round=run_round,
        )
        run = state["run"]
    else:
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
                "native_decide_policy_sha256": lock[
                    "native_decide_policy_sha256"
                ],
            }
        )
        accepted = run.get("accepted") or {"accepted_commit": run.get("base_commit")}
        state = {
            "run": run,
            "manifest": manifest,
            "config": config,
            "run_round": run_round,
            "receipts": [],
            "cost": Decimal("0.000000"),
            "accepted": accepted,
            "working": dict(accepted),
            "pending_model_exchanges": {},
            "model_exchanges": {},
            "receipt_rejections": [],
            "wall_seconds_used": Decimal("0.000000"),
            "finalization_reserve_seconds": _finalization_reserve(config),
        }
    state["wall_started_monotonic_ns"] = wall_started
    state.setdefault("receipt_rejections", [])
    state.setdefault("wall_seconds_used", Decimal("0.000000"))
    state.setdefault("finalization_reserve_seconds", _finalization_reserve(config))
    _charge_wall(state)
    state["checkpoint_enabled"] = bool(run.get("run_root"))
    if resume_from is None:
        _checkpoint_if_enabled(state, "run:prepared")
    elif state.get("result"):
        result = state["result"]
        _checkpoint_if_enabled(state, "result:before-export")
        worker.persist_result(run, result, _l0_receipt(run, state, result))
        _checkpoint_if_enabled(state, "result:after-export")
        return result
    try:
        if preparation_failure is not None:
            raise preparation_failure
        for update in _EXPERIMENT_GRAPH.stream(state, stream_mode="updates"):
            for values in update.values():
                state.update(values)
        result = _result(run, state, outcome="success", reason="all_targets_verified")
    except BudgetExhausted as exc:
        state["termination_detail"] = exc.detail
        result = _result(
            run,
            state,
            outcome="budget_exhausted",
            reason=(
                "cost_budget_exhausted"
                if exc.kind == "cost_usd"
                else "wall_budget_exhausted"
            ),
        )
    except (ContractError, probes.ProbeError, worker.WorkerError, verifier.VerifierError) as exc:
        state["termination_detail"] = str(exc)[:1000]
        result = _result(
            run,
            state,
            outcome="failure",
            reason=(
                "infrastructure_failed"
                if exc is preparation_failure
                else "contract_inconclusive"
                if isinstance(exc, ContractInconclusive)
                else type(exc).__name__.removesuffix("Error").lower()
            ),
        )
    state["result"] = result
    _checkpoint_if_enabled(state, "result:before-export")
    worker.persist_result(run, result, _l0_receipt(run, state, result))
    _checkpoint_if_enabled(state, "result:after-export")
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
