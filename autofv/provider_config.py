"""Strict trusted-provider environment loading and immutable startup binding."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import stat
import threading
import urllib.parse
from dataclasses import dataclass, field
from decimal import Decimal, DecimalException
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json_bytes
from .worker_runtime import WorkerError


_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,6})?")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ENV_NAMES = frozenset(
    {
        "AUTOFV_PROVIDER_ENDPOINT",
        "AUTOFV_PROVIDER_MODEL",
        "AUTOFV_PROVIDER_API_KEY",
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64",
    }
)
_PARAMETERS = {
    "temperature": 0,
    "stream": False,
    "tool_choice": "required",
    "review_max_output_tokens": 4096,
    "work_max_output_tokens": 8192,
    "timeout_seconds": 30,
}


class ProviderConfigError(WorkerError):
    """Trusted provider configuration failed closed."""

    def __init__(
        self,
        message: str,
        *,
        classification: str = "malformed_response",
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.classification = classification
        self.status_code = status_code


@dataclass
class ProviderBinding:
    public: dict[str, Any]
    endpoint: str
    api_key: bytearray
    client_token: bytearray
    model_id: str
    route_path: str
    pricing: dict[str, str]
    tools: list[dict[str, Any]]
    signing_key: Ed25519PrivateKey | None
    secret_markers: tuple[bytes, ...]
    seen_request_ids: set[str] = field(default_factory=set)
    seen_sequences: set[int] = field(default_factory=set)
    pending_messages: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_BINDINGS: dict[str, ProviderBinding] = {}
_BINDINGS_LOCK = threading.Lock()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProviderConfigError(f"{label} fields mismatch")
    return value


def endpoint_identity(value: str) -> str:
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else b""
    except UnicodeEncodeError as exc:
        raise ProviderConfigError("provider endpoint is invalid") from exc
    if not isinstance(value, str) or len(encoded) > 2048:
        raise ProviderConfigError("provider endpoint is invalid")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProviderConfigError("provider endpoint is invalid") from exc
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in ({"https"} | ({"http"} if loopback else set()))
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or not parsed.path.endswith("/chat/completions")
    ):
        raise ProviderConfigError("provider endpoint is invalid")
    return value


def _canonical_rate(value: str, label: str) -> str:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        raise ProviderConfigError(f"{label} must be canonical decimal text")
    try:
        amount = Decimal(value)
    except DecimalException as exc:
        raise ProviderConfigError(f"{label} must be canonical decimal text") from exc
    if not amount.is_finite() or not 0 <= amount <= Decimal("1000000"):
        raise ProviderConfigError(f"{label} is outside the supported bound")
    return f"{amount:.6f}"


def _environment_path(
    explicit: str | Path | None,
    *,
    project_root: Path | None,
    config_home: Path | None,
) -> tuple[Path, str]:
    override = explicit or os.environ.get("AUTOFV_PROVIDER_ENV")
    if override is not None:
        return Path(override).expanduser(), "explicit"
    root = project_root or Path(__file__).resolve().parents[1]
    if (root / ".git").exists():
        return root / ".env", "development"
    home = config_home or Path.home() / ".config"
    return home / "autofv" / "providers.env", "installed"


def _load_environment(
    explicit: str | Path | None,
    *,
    project_root: Path | None,
    config_home: Path | None,
) -> tuple[dict[str, str], dict[str, str]]:
    path, source_kind = _environment_path(
        explicit, project_root=project_root, config_home=config_home
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProviderConfigError("provider environment is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 65_536
        ):
            raise ProviderConfigError(
                "provider environment ownership, mode, or size is invalid"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(65_537)
    finally:
        os.close(descriptor)
    if len(raw) > 65_536:
        raise ProviderConfigError("provider environment exceeds its bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderConfigError("provider environment is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line or line.startswith((" ", "\t", "export ")):
            raise ProviderConfigError("provider environment line is malformed")
        name, value = line.split("=", 1)
        if (
            name not in _ENV_NAMES
            or name in values
            or not value
            or value != value.strip()
            or any(ord(character) < 32 for character in value)
        ):
            raise ProviderConfigError("provider environment field is invalid")
        values[name] = value
    if set(values) != _ENV_NAMES:
        raise ProviderConfigError("provider environment fields mismatch")
    return values, {
        "kind": source_kind,
        "path_sha256": hashlib.sha256(str(path.absolute()).encode()).hexdigest(),
    }


def _tool_schemas(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ProviderConfigError("provider tool schemas must be a non-empty array")
    tools, names = [], set()
    for item in value:
        item = exact_dict(
            item, {"name", "description", "input_schema"}, "lane tool"
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
            or name in names
            or not isinstance(item["description"], str)
            or not item["description"]
            or not isinstance(item["input_schema"], dict)
        ):
            raise ProviderConfigError("provider tool schema is invalid")
        names.add(name)
        tools.append(
            json.loads(
                canonical_json_bytes(
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": item["description"],
                            "parameters": item["input_schema"],
                        },
                    }
                )
            )
        )
    return sorted(tools, key=lambda tool: tool["function"]["name"])


def configure_provider(
    run: dict[str, Any],
    *,
    env_path: str | Path | None = None,
    tool_schemas: Any,
    project_root: Path | None = None,
    config_home: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(run, dict) or not isinstance(run.get("run_id"), str):
        raise ProviderConfigError("provider run identity is invalid")
    route = run.get("lock", {}).get("fixed_proxy")
    if not isinstance(route, dict):
        raise ProviderConfigError("provider fixed route is unavailable")
    fixed_proxy_sha256 = canonical_sha256(route)
    if run.get("fixed_proxy_sha256") != fixed_proxy_sha256:
        raise ProviderConfigError("provider fixed route identity changed")
    for field in ("proxy_id", "route_id"):
        if not isinstance(route.get(field), str) or not route[field]:
            raise ProviderConfigError("provider fixed route identity is invalid")
    if route.get("method") != "POST" or not isinstance(route.get("path"), str):
        raise ProviderConfigError("provider fixed route is invalid")
    client_token = os.environ.get("AUTOFV_RUN_TOKEN")
    try:
        client_token_bytes = (
            client_token.encode("utf-8") if isinstance(client_token, str) else b""
        )
    except UnicodeEncodeError as exc:
        raise ProviderConfigError("provider run credential is unavailable") from exc
    if (
        not isinstance(client_token, str)
        or not client_token
        or len(client_token_bytes) > 4096
        or any(ord(character) < 32 for character in client_token)
    ):
        raise ProviderConfigError("provider run credential is unavailable")
    values, source = _load_environment(
        env_path, project_root=project_root, config_home=config_home
    )
    endpoint = endpoint_identity(values["AUTOFV_PROVIDER_ENDPOINT"])
    model_id = values["AUTOFV_PROVIDER_MODEL"]
    if (
        not model_id
        or model_id != model_id.strip()
        or len(model_id.encode("utf-8")) > 256
    ):
        raise ProviderConfigError("provider model identity is invalid")
    if len(values["AUTOFV_PROVIDER_API_KEY"].encode("utf-8")) > 4096:
        raise ProviderConfigError("provider credential is invalid")
    tools = _tool_schemas(tool_schemas)
    pricing = {
        "input_usd_per_million": _canonical_rate(
            values["AUTOFV_PROVIDER_INPUT_USD_PER_MILLION"], "input pricing"
        ),
        "cached_input_usd_per_million": _canonical_rate(
            values["AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION"],
            "cached input pricing",
        ),
        "output_usd_per_million": _canonical_rate(
            values["AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION"], "output pricing"
        ),
        "currency": "USD",
    }
    try:
        private_raw = base64.b64decode(
            values["AUTOFV_RECEIPT_SIGNING_KEY_B64"], validate=True
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ProviderConfigError("provider receipt signing key is invalid") from exc
    public_key = signing_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    key_digest = hashlib.sha256(public_der).hexdigest()
    parameters = dict(_PARAMETERS)
    endpoint_sha256 = hashlib.sha256(endpoint.encode()).hexdigest()
    pricing_sha256 = canonical_sha256(pricing)
    tool_schema_sha256 = canonical_sha256(tools)
    capability = {
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "fixed_proxy_sha256": fixed_proxy_sha256,
        "endpoint_sha256": endpoint_sha256,
        "model_id": model_id,
        "parameters": parameters,
        "pricing_sha256": pricing_sha256,
        "tool_schema_sha256": tool_schema_sha256,
    }
    body = {
        "schema": "autofv-provider-binding/v1",
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "fixed_proxy_sha256": fixed_proxy_sha256,
        "client_identity_sha256": hashlib.sha256(client_token.encode()).hexdigest(),
        "endpoint": endpoint,
        "endpoint_sha256": endpoint_sha256,
        "model_id": model_id,
        "parameters": parameters,
        "pricing": pricing,
        "pricing_sha256": pricing_sha256,
        "tool_schema_sha256": tool_schema_sha256,
        "capability_sha256": canonical_sha256(capability),
        "environment_source": source,
        "receipt_authentication": {
            "algorithm": "Ed25519",
            "key_id": f"autofv-provider-ed25519-{key_digest[:16]}",
            "public_key_der_sha256": key_digest,
            "public_key_pem": public_pem,
        },
    }
    public = {**body, "binding_sha256": canonical_sha256(body)}
    existing = run.get("provider_binding")
    if existing not in (None, public):
        raise ProviderConfigError("provider binding changed during the run")
    private_key_text = values["AUTOFV_RECEIPT_SIGNING_KEY_B64"]
    secret_markers = tuple(
        marker
        for marker in {
            values["AUTOFV_PROVIDER_API_KEY"].encode(),
            base64.b64encode(values["AUTOFV_PROVIDER_API_KEY"].encode()),
            private_key_text.encode(),
            private_raw,
            private_raw.hex().encode(),
        }
        if marker
    )
    binding = ProviderBinding(
        public=copy.deepcopy(public),
        endpoint=endpoint,
        api_key=bytearray(values["AUTOFV_PROVIDER_API_KEY"].encode()),
        client_token=bytearray(client_token.encode()),
        model_id=model_id,
        route_path=route["path"],
        pricing=pricing,
        tools=tools,
        signing_key=signing_key,
        secret_markers=secret_markers,
    )
    with _BINDINGS_LOCK:
        if public["binding_sha256"] in _BINDINGS:
            raise ProviderConfigError("provider binding is already configured")
        _BINDINGS[public["binding_sha256"]] = binding
    run["provider_binding"] = copy.deepcopy(public)
    run["provider_binding_sha256"] = public["binding_sha256"]
    run["proxy_client_identity_sha256"] = public["client_identity_sha256"]
    run["proxy_model_id"] = model_id
    run["cost_classification"] = "provider_authenticated"
    return copy.deepcopy(public)


def provider_binding(run: dict[str, Any]) -> ProviderBinding | None:
    public = run.get("provider_binding")
    if not isinstance(public, dict):
        return None
    digest = public.get("binding_sha256")
    if not isinstance(digest, str):
        raise ProviderConfigError("provider binding identity is invalid")
    with _BINDINGS_LOCK:
        binding = _BINDINGS.get(digest)
    route = run.get("lock", {}).get("fixed_proxy")
    if binding is None or binding.public != public or public.get("run_id") != run.get(
        "run_id"
    ) or not isinstance(route, dict) or any(
        (
            public["fixed_proxy_sha256"] != canonical_sha256(route),
            public["proxy_id"] != route.get("proxy_id"),
            public["route_id"] != route.get("route_id"),
            binding.route_path != route.get("path"),
            run.get("provider_binding_sha256") != digest,
            run.get("proxy_client_identity_sha256")
            != public["client_identity_sha256"],
            run.get("proxy_model_id") != public["model_id"],
        )
    ):
        raise ProviderConfigError("provider binding is unavailable or changed")
    return binding


def release_provider(run: dict[str, Any]) -> None:
    """Release process-held credentials and staged content for one disposed run."""
    digest = run.get("provider_binding_sha256")
    if not isinstance(digest, str):
        return
    with _BINDINGS_LOCK:
        binding = _BINDINGS.pop(digest, None)
    if binding is None:
        return
    with binding.lock:
        binding.pending_messages.clear()
        for secret in (binding.api_key, binding.client_token):
            secret[:] = b"\0" * len(secret)
        binding.signing_key = None
        binding.secret_markers = ()


def secret_markers(run: dict[str, Any]) -> tuple[bytes, ...]:
    """Expose provider canaries only to the trusted pre-disposal scanner."""
    binding = provider_binding(run)
    return () if binding is None else tuple(binding.secret_markers)


def abort_configuration(run: dict[str, Any]) -> None:
    """Clear public state after the trusted listener fails to start."""
    release_provider(run)
    for name in (
        "provider_binding",
        "provider_binding_sha256",
        "proxy_client_identity_sha256",
        "proxy_model_id",
        "cost_classification",
        "provider_service",
        "proxy_base",
    ):
        run.pop(name, None)


def validate_public_binding(value: Any) -> dict[str, Any]:
    binding = exact_dict(
        value,
        {
            "schema",
            "run_id",
            "proxy_id",
            "route_id",
            "fixed_proxy_sha256",
            "client_identity_sha256",
            "endpoint",
            "endpoint_sha256",
            "model_id",
            "parameters",
            "pricing",
            "pricing_sha256",
            "tool_schema_sha256",
            "capability_sha256",
            "environment_source",
            "receipt_authentication",
            "binding_sha256",
        },
        "provider binding",
    )
    if binding["schema"] != "autofv-provider-binding/v1":
        raise ProviderConfigError("provider binding schema mismatch")
    if (
        not isinstance(binding["run_id"], str)
        or not binding["run_id"]
        or not isinstance(binding["proxy_id"], str)
        or not binding["proxy_id"]
        or not isinstance(binding["route_id"], str)
        or not binding["route_id"]
        or not isinstance(binding["model_id"], str)
        or not binding["model_id"]
        or any(
            not isinstance(binding[name], str) or _SHA256.fullmatch(binding[name]) is None
            for name in (
                "fixed_proxy_sha256",
                "client_identity_sha256",
                "endpoint_sha256",
                "pricing_sha256",
                "tool_schema_sha256",
                "capability_sha256",
                "binding_sha256",
            )
        )
    ):
        raise ProviderConfigError("provider binding identity is invalid")
    body = {key: item for key, item in binding.items() if key != "binding_sha256"}
    if binding["binding_sha256"] != canonical_sha256(body):
        raise ProviderConfigError("provider binding hash mismatch")
    endpoint_identity(binding["endpoint"])
    if binding["endpoint_sha256"] != hashlib.sha256(
        binding["endpoint"].encode()
    ).hexdigest():
        raise ProviderConfigError("provider endpoint hash mismatch")
    parameters = exact_dict(
        binding["parameters"], set(_PARAMETERS), "provider parameters"
    )
    if parameters != _PARAMETERS:
        raise ProviderConfigError("provider parameters mismatch")
    pricing = exact_dict(
        binding["pricing"],
        {
            "input_usd_per_million",
            "cached_input_usd_per_million",
            "output_usd_per_million",
            "currency",
        },
        "provider pricing",
    )
    if pricing["currency"] != "USD" or any(
        pricing[name] != _canonical_rate(pricing[name], name)
        for name in (
            "input_usd_per_million",
            "cached_input_usd_per_million",
            "output_usd_per_million",
        )
    ):
        raise ProviderConfigError("provider pricing is invalid")
    if binding["pricing_sha256"] != canonical_sha256(pricing):
        raise ProviderConfigError("provider pricing hash mismatch")
    source = exact_dict(
        binding["environment_source"], {"kind", "path_sha256"}, "provider source"
    )
    if source["kind"] not in {"explicit", "development", "installed"} or (
        not isinstance(source["path_sha256"], str)
        or _SHA256.fullmatch(source["path_sha256"]) is None
    ):
        raise ProviderConfigError("provider source identity is invalid")
    authentication = exact_dict(
        binding["receipt_authentication"],
        {"algorithm", "key_id", "public_key_der_sha256", "public_key_pem"},
        "provider receipt authentication",
    )
    if (
        authentication["algorithm"] != "Ed25519"
        or not isinstance(authentication["key_id"], str)
        or not authentication["key_id"]
        or not isinstance(authentication["public_key_der_sha256"], str)
        or _SHA256.fullmatch(authentication["public_key_der_sha256"]) is None
        or not isinstance(authentication["public_key_pem"], str)
    ):
        raise ProviderConfigError("provider receipt authentication is invalid")
    capability = {
        "run_id": binding["run_id"],
        "proxy_id": binding["proxy_id"],
        "route_id": binding["route_id"],
        "fixed_proxy_sha256": binding["fixed_proxy_sha256"],
        "endpoint_sha256": binding["endpoint_sha256"],
        "model_id": binding["model_id"],
        "parameters": binding["parameters"],
        "pricing_sha256": binding["pricing_sha256"],
        "tool_schema_sha256": binding["tool_schema_sha256"],
    }
    if binding["capability_sha256"] != canonical_sha256(capability):
        raise ProviderConfigError("provider capability hash mismatch")
    return binding
