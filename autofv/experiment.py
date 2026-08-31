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
from types import SimpleNamespace
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    policy = lock.get("native_decide")
    if not isinstance(policy, dict):
        raise ContractError("native_decide policy is absent")
    if policy.get("state") != "selected" or policy.get("runnable") is not True:
        raise ContractError("native_decide policy decision is required before execution")
    return policy


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


def run_experiment(
    target: str | Path,
    run_config: str | Path,
    *,
    run_round=agentproc.run_round,
) -> dict[str, Any]:
    """Validate the sole experiment intake before any worker or agent action."""
    target_path, manifest = validate_target(target)
    config_path, config = validate_run_config(run_config)
    policy = validate_native_decide_policy(load_toolchain_lock())
    return {
        "target": str(target_path),
        "run_config": str(config_path),
        "manifest": manifest,
        "config": config,
        "native_decide": policy,
    }


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
        run_experiment(args.target, args.run_config)
    except ContractError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
