"""Fixed model-proxy relay, policy, and egress checks."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from . import evidence, provider_config, provider_service, provider_transport
from .worker_runtime import (
    AGENT_UID,
    FORWARD_CHAIN,
    NETWORK_ENFORCER,
    OUTPUT_CHAIN,
    WorkerError,
    _atomic_write,
    _canonical_bytes,
    _docker,
    _firewall,
    _firewall_snapshot,
    _json_output,
    _labels,
    _lima,
    _install_worker_firewall,
    lima_host_address,
    _proxy_endpoint,
    _resource_matches,
    _runtime_argv,
    _sha256,
)


RELAY_PORT = 8080
SHA256 = re.compile(r"[0-9a-f]{64}")
PROXY_REQUEST_FIELDS = frozenset(
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
    }
)

_RELAY_PROGRAM = r"""
import http.server
import os
import socket
import urllib.error
import urllib.request

path = os.environ["AUTOFV_PROXY_PATH"]
upstream = os.environ["AUTOFV_PROXY_BASE"].rstrip("/") + path
token = os.environ["AUTOFV_RUN_TOKEN"]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

class Handler(http.server.BaseHTTPRequestHandler):
    def send_value(self, status, raw=b'{"error":"rejected"}'):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        if self.path != path:
            self.send_value(404)
            return
        if self.headers.get("Authorization") or self.headers.get("X-AutoFV-Upstream-Host"):
            self.send_value(403)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length <= 0 or length > 1_000_000:
                raise ValueError
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError
            request = urllib.request.Request(
                upstream,
                data=raw,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-AutoFV-Run-Token": token,
                },
            )
            with opener.open(request, timeout=30) as reply:
                response = reply.read(1_000_001)
                if len(response) > 1_000_000:
                    self.send_value(502, b'{"error":"fixed proxy response too large"}')
                else:
                    self.send_value(reply.status, response)
        except urllib.error.HTTPError as error:
            self.send_value(error.code, b'{"error":"fixed proxy rejected"}')
        except (TimeoutError, socket.timeout):
            self.send_value(504, b'{"error":"fixed proxy timeout"}')
        except urllib.error.URLError as error:
            status = 504 if isinstance(error.reason, (TimeoutError, socket.timeout)) else 502
            self.send_value(status, b'{"error":"fixed proxy unavailable"}')
        except Exception:
            self.send_value(502, b'{"error":"fixed proxy failed"}')

    def do_CONNECT(self):
        self.send_value(405)

    def do_GET(self):
        self.send_value(405 if self.path == path else 404)

    def log_message(self, *args):
        return

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""

_PROXY_CLIENT_PROGRAM = r"""
import json
import sys
import urllib.error
import urllib.request

raw = sys.stdin.buffer.read(1_000_001)
if not 0 < len(raw) <= 1_000_000:
    raise SystemExit(22)
request = urllib.request.Request(
    sys.argv[1], data=raw, method="POST", headers={"Content-Type": "application/json"}
)
try:
    with urllib.request.urlopen(request, timeout=30) as reply:
        output = reply.read(1_000_001)
        if len(output) > 1_000_000:
            output = (
                b'{"proxy_error":{"classification":"malformed_response",'
                b'"status_code":null}}'
            )
except urllib.error.HTTPError as error:
    classification = {
        400: "malformed_response",
        401: "authentication_error",
        403: "authentication_error",
        408: "timeout",
        429: "rate_limited",
        504: "timeout",
    }.get(error.code, "upstream_error")
    output = json.dumps(
        {"proxy_error": {"classification": classification, "status_code": error.code}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
except urllib.error.URLError as error:
    classification = "timeout" if isinstance(error.reason, TimeoutError) else "upstream_error"
    output = json.dumps(
        {"proxy_error": {"classification": classification, "status_code": None}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
except TimeoutError:
    output = b'{"proxy_error":{"classification":"timeout","status_code":null}}'
sys.stdout.buffer.write(output)
"""

_PROXY_POLICY_CLIENT_PROGRAM = r"""
import http.client
import json
import sys

host = sys.argv[1]
port = int(sys.argv[2])
method = sys.argv[3]
path = sys.argv[4]
header = sys.argv[5]
raw = sys.stdin.buffer.read(1_000_001)
headers = {"Content-Type": "application/json"}
if header:
    headers[header] = "caller-controlled"
connection = http.client.HTTPConnection(host, port, timeout=5)
connection.request(method, path, body=raw, headers=headers)
reply = connection.getresponse()
reply.read()
blocked = not 200 <= reply.status < 300
print(
    json.dumps(
        {"blocked": blocked, "status": reply.status},
        sort_keys=True,
        separators=(",", ":"),
    )
)
raise SystemExit(0 if blocked else 23)
"""

_DENIED_EGRESS = (
    ("external_dns", "dns", "example.com", 443),
    ("literal_ipv4", "ipv4", "1.1.1.1", 443),
    ("literal_ipv6", "ipv6", "2606:4700:4700::1111", 443),
    ("link_local_metadata", "ipv4", "169.254.169.254", 80),
)


def _egress_fixture(run: dict[str, Any]) -> dict[str, Any]:
    route = run["lock"]["fixed_proxy"]
    return {
        "schema": "autofv-linux-isolation-fixture/v1",
        "denied": [
            {"id": case_id, "kind": kind, "host": host, "port": port}
            for case_id, kind, host, port in _DENIED_EGRESS
        ],
        "fixed_proxy": {"method": route["method"], "path": route["path"]},
    }


def verify_egress(run: dict[str, Any]) -> dict[str, Any]:
    """Run the fixed Phase 1 egress contract for a scored experiment."""
    return run_egress_matrix(run, _egress_fixture(run))


def _proxy_resources(run: dict[str, Any]) -> tuple[str, str]:
    return f"{run['volume']}-network", f"{run['volume']}-relay"


def _validate_proxy_request(run: dict[str, Any], request: Any) -> str:
    """Reject any model call not produced by the fixed request envelope."""
    route = run.get("lock", {}).get("fixed_proxy")
    if not isinstance(route, dict):
        raise WorkerError("fixed proxy policy is missing")
    observed_policy = _sha256(_canonical_bytes(route))
    bound_policy = run.setdefault("fixed_proxy_sha256", observed_policy)
    if not isinstance(bound_policy, str) or not secrets.compare_digest(
        bound_policy, observed_policy
    ):
        raise WorkerError("fixed proxy policy changed during the run")
    if route.get("method") != "POST" or not isinstance(route.get("path"), str):
        raise WorkerError("fixed proxy policy is invalid")
    if not isinstance(request, dict) or set(request) != PROXY_REQUEST_FIELDS:
        raise WorkerError("fixed proxy request fields mismatch")
    if request["schema"] != "autofv-model-request/v1" or request["run_id"] != run.get(
        "run_id"
    ):
        raise WorkerError("fixed proxy request identity mismatch")
    if type(request["sequence"]) is not int or request["sequence"] <= 0:
        raise WorkerError("fixed proxy request sequence is invalid")
    if request["batch_id"] is not None and (
        not isinstance(request["batch_id"], str) or not request["batch_id"]
    ):
        raise WorkerError("fixed proxy request batch identity is invalid")
    for field in ("request_id", "role", "model_id"):
        if not isinstance(request[field], str) or not request[field]:
            raise WorkerError(f"fixed proxy request {field} is invalid")
    model_id = run.get("proxy_model_id")
    if model_id is not None and model_id != request["model_id"]:
        raise WorkerError("fixed proxy request model identity mismatch")
    expected_prompt = _sha256(
        (
            f"{run['run_id']}\0{request['request_id']}\0{request['role']}\0bounded-v1"
        ).encode("utf-8")
    )
    hashes = request["input_hashes"]
    if (
        not isinstance(hashes, list)
        or any(not isinstance(value, str) for value in hashes)
        or hashes != sorted(set(hashes))
        or any(SHA256.fullmatch(value) is None for value in hashes)
        or not isinstance(request["prompt_sha256"], str)
        or SHA256.fullmatch(request["prompt_sha256"]) is None
        or not secrets.compare_digest(request["prompt_sha256"], expected_prompt)
    ):
        raise WorkerError("fixed proxy request hashes are invalid")
    run.setdefault("proxy_model_id", request["model_id"])
    return _sha256(_canonical_bytes(request))


def _bind_proxy_client_identity(run: dict[str, Any], token: str) -> str:
    digest = _sha256(token.encode("utf-8"))
    bound = run.setdefault("proxy_client_identity_sha256", digest)
    if not isinstance(bound, str) or not secrets.compare_digest(bound, digest):
        raise WorkerError("trusted proxy client identity changed during the run")
    return digest


def _record_proxy_policy(run: dict[str, Any]) -> dict[str, Any]:
    route = run["lock"]["fixed_proxy"]
    provider_binding = run.get("provider_binding")
    if isinstance(provider_binding, dict):
        endpoint_sha256 = _sha256(run["proxy_base"].encode("utf-8"))
        client_identity_sha256 = run.get("proxy_client_identity_sha256")
        receipt_schema = provider_transport.PROVIDER_RECEIPT_SCHEMA
    else:
        endpoint_sha256 = _sha256(run["proxy_base"].encode("utf-8"))
        client_identity_sha256 = run["proxy_client_identity_sha256"]
        receipt_schema = route["receipt_schema"]
    body = {
        "schema": "autofv-fixed-proxy-policy/v1",
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "method": route["method"],
        "path": route["path"],
        "auth_scope": "run-scoped-fixed-inference",
        "provider_authorization_location": route["provider_authorization_location"],
        "proxy_endpoint_sha256": endpoint_sha256,
        "proxy_client_identity_sha256": client_identity_sha256,
        "receipt_schema_sha256": _sha256(_canonical_bytes(receipt_schema)),
        "fixed_proxy_sha256": run["fixed_proxy_sha256"],
        "image_digest": run["image_digest"],
        "control_bundle_sha256": run["control_bundle_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
    }
    if isinstance(provider_binding, dict):
        body["provider_binding"] = json.loads(_canonical_bytes(provider_binding))
        body["provider_endpoint_sha256"] = provider_binding["endpoint_sha256"]
        body["provider_receipt_schema"] = receipt_schema
    receipt = {**body, "policy_sha256": _sha256(_canonical_bytes(body))}
    existing = run.get("proxy_policy_sha256")
    if existing not in (None, receipt["policy_sha256"]):
        raise WorkerError("fixed proxy policy evidence changed during the run")
    _atomic_write(
        Path(run["evidence_dir"]) / "fixed-proxy-policy.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["proxy_policy_sha256"] = receipt["policy_sha256"]
    run["proxy_policy_receipt"] = receipt
    if "fixed_proxy_policy_bound" not in run["events"]:
        run["events"].append("fixed_proxy_policy_bound")
    return receipt


def _record_proxy_error(
    run: dict[str, Any],
    request: dict[str, Any],
    request_sha256: str,
    classification: str,
    status_code: int | None,
    detail: bytes | str,
) -> dict[str, Any]:
    allowed = set(run["lock"]["fixed_proxy"]["receipt_schema"]["status_values"]) - {
        "ok"
    }
    if classification not in allowed:
        raise WorkerError("fixed proxy error classification is invalid")
    if status_code is not None and (
        type(status_code) is not int or not 100 <= status_code <= 599
    ):
        raise WorkerError("fixed proxy error status is invalid")
    if isinstance(detail, str):
        raw_detail = detail.encode("utf-8", "replace")
    elif isinstance(detail, bytes):
        raw_detail = detail
    else:
        raise WorkerError("fixed proxy error detail is invalid")
    route = run["lock"]["fixed_proxy"]
    body = {
        "schema": "autofv-proxy-error/v1",
        "run_id": run["run_id"],
        "proxy_id": route["proxy_id"],
        "route_id": route["route_id"],
        "sequence": request["sequence"],
        "request_id": request["request_id"],
        "model_id": request["model_id"],
        "request_sha256": request_sha256,
        "classification": classification,
        "status_code": status_code,
        "detail_sha256": _sha256(raw_detail),
        "fixed_proxy_sha256": run.get("fixed_proxy_sha256"),
        "proxy_policy_sha256": run.get("proxy_policy_sha256"),
        "proxy_client_identity_sha256": run.get("proxy_client_identity_sha256"),
        "image_digest": run.get("image_digest"),
        "control_bundle_sha256": run.get("control_bundle_sha256"),
        "native_decide_policy_sha256": run.get("native_decide_policy_sha256"),
        "worker_inventory_sha256": run.get("worker_inventory_sha256"),
    }
    receipt = {**body, "error_sha256": _sha256(_canonical_bytes(body))}
    name = f"{request['sequence']:08d}-{_sha256(request['request_id'].encode())[:16]}.json"
    _atomic_write(
        Path(run["run_root"]) / "evidence" / "proxy-errors" / name,
        _canonical_bytes(receipt) + b"\n",
    )
    event = f"proxy_error:{classification}"
    if event not in run["events"]:
        run["events"].append(event)
    return receipt


def _configure_proxy_firewall(
    run: dict[str, Any], network: str, relay: str
) -> dict[str, Any]:
    base = (
        run.get("proxy_base")
        if provider_transport.is_configured(run)
        else os.environ.get("AUTOFV_PROXY_BASE") or run.get("proxy_base")
    )
    if not isinstance(base, str):
        raise WorkerError("trusted proxy identity is not configured")
    upstream_address, upstream_port = _proxy_endpoint(base)
    networks = _json_output(_docker("network", "inspect", network), "proxy network")
    relays = _json_output(_docker("container", "inspect", relay), "proxy relay")
    try:
        network_id = networks[0]["Id"]
        internal_address = relays[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        bridge_address = relays[0]["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        ipaddress.IPv4Address(internal_address)
        ipaddress.IPv4Address(bridge_address)
    except (KeyError, IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("proxy relay network identity is incomplete") from exc
    identity = {
        "base": base.rstrip("/"),
        "network_id": network_id,
        "internal_address": internal_address,
        "bridge_address": bridge_address,
        "upstream_address": upstream_address,
        "upstream_port": upstream_port,
    }
    if run.get("proxy_firewall") not in (None, identity):
        raise WorkerError("trusted proxy endpoint changed during the run")
    allows = (
        (
            "-i",
            f"br-{network_id[:12]}",
            "-d",
            f"{internal_address}/32",
            "-p",
            "tcp",
            "--dport",
            str(RELAY_PORT),
            "-j",
            "ACCEPT",
        ),
        (
            "-s",
            f"{bridge_address}/32",
            "-d",
            f"{upstream_address}/32",
            "-p",
            "tcp",
            "--dport",
            str(upstream_port),
            "-j",
            "ACCEPT",
        ),
    )
    if run.get("proxy_firewall") is None:
        try:
            snapshot = _firewall_snapshot(allows)
        except WorkerError:
            _firewall_snapshot()
            for position, rule in enumerate(allows, start=2):
                _firewall("iptables", "-I", FORWARD_CHAIN, str(position), *rule)
            snapshot = _firewall_snapshot(allows)
    else:
        snapshot = _firewall_snapshot(allows)
    run["proxy_base"] = identity["base"]
    run["proxy_firewall"] = identity
    return {**identity, "rules": snapshot}


def _ensure_proxy_relay(run: dict[str, Any]) -> tuple[str, str]:
    network, relay = _proxy_resources(run)
    if provider_transport.is_configured(run):
        base = provider_service.relay_base(run, lima_host_address())
        run["proxy_base"] = base
    else:
        base = os.environ.get("AUTOFV_PROXY_BASE") or run.get("proxy_base")
    token = os.environ.get("AUTOFV_RUN_TOKEN")
    if not isinstance(base, str) or not token:
        raise WorkerError("trusted proxy identity is not configured")
    _proxy_endpoint(base)
    _bind_proxy_client_identity(run, token)

    if _resource_matches("network", network, run) and _resource_matches(
        "relay", relay, run
    ):
        values = _json_output(_docker("container", "inspect", relay), "proxy relay")
        expected_environment = {
            f"AUTOFV_PROXY_BASE={base.rstrip('/')}",
            f"AUTOFV_PROXY_PATH={run['lock']['fixed_proxy']['path']}",
            f"AUTOFV_RUN_TOKEN={token}",
        }
        environment = set(values[0].get("Config", {}).get("Env") or [])
        if not expected_environment.issubset(environment):
            raise WorkerError("trusted proxy relay identity mismatch")
        address = values[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        _configure_proxy_firewall(run, network, relay)
        run["proxy_network"] = network
        run["proxy_relay"] = relay
        _record_proxy_policy(run)
        return network, address

    if _docker("network", "inspect", network, check=False).returncode == 0:
        raise WorkerError("proxy network identity already exists")
    _docker("network", "create", "--internal", *_labels(run, "network"), network)
    if not _resource_matches("network", network, run):
        raise WorkerError("proxy network claim mismatch")
    if _docker("container", "inspect", relay, check=False).returncode == 0:
        raise WorkerError("proxy relay identity already exists")
    _docker(
        "run",
        "-d",
        "--name",
        relay,
        *_labels(run, "relay"),
        "--pull",
        "never",
        "--read-only",
        "--network",
        "bridge",
        "--user",
        AGENT_UID,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--env",
        f"AUTOFV_PROXY_BASE={base.rstrip('/')}",
        "--env",
        f"AUTOFV_PROXY_PATH={run['lock']['fixed_proxy']['path']}",
        "--env",
        f"AUTOFV_RUN_TOKEN={token}",
        run["image_digest"],
        "python",
        "-c",
        _RELAY_PROGRAM,
    )
    _docker("network", "connect", network, relay)
    if not _resource_matches("relay", relay, run):
        raise WorkerError("proxy relay claim mismatch")
    values = _json_output(_docker("container", "inspect", relay), "proxy relay")
    try:
        address = values[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        ipaddress.IPv4Address(address)
    except (KeyError, IndexError, ipaddress.AddressValueError) as exc:
        raise WorkerError("proxy relay address is unavailable") from exc
    _configure_proxy_firewall(run, network, relay)
    run["proxy_network"] = network
    run["proxy_relay"] = relay
    run["events"].append("fixed_proxy_relay_started")
    _record_proxy_policy(run)
    return network, address


def proxy_round(
    run: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Call only the launcher-selected fixed route from the runsc worker."""
    request_sha256 = _validate_proxy_request(run, request)
    route = run["lock"]["fixed_proxy"]
    try:
        provider_configured = provider_transport.is_configured(run)
    except provider_transport.ProviderError as exc:
        raise WorkerError(str(exc), run=run) from exc
    if (
        run.get("cost_classification") == "provider_authenticated"
        and not provider_configured
    ):
        raise WorkerError("provider binding is unavailable", run=run)
    try:
        network, address = _ensure_proxy_relay(run)
    except WorkerError as exc:
        _record_proxy_error(
            run, request, request_sha256, "upstream_error", None, str(exc)
        )
        raise WorkerError("fixed proxy upstream_error", run=run) from exc
    completed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _PROXY_CLIENT_PROGRAM,
            f"http://{address}:{RELAY_PORT}{route['path']}",
            network=network,
        ),
        input_bytes=_canonical_bytes(request),
        check=False,
    )
    if completed.returncode:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "upstream_error",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy upstream_error", run=run)
    try:
        body = _json_output(completed, "fixed proxy response")
    except WorkerError as exc:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "malformed_response",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy malformed_response", run=run) from exc
    if isinstance(body, dict) and set(body) == {"proxy_error"}:
        error = body["proxy_error"]
        if not isinstance(error, dict) or set(error) != {"classification", "status_code"}:
            classification, status_code = "malformed_response", None
        else:
            classification, status_code = error["classification"], error["status_code"]
            allowed = set(route["receipt_schema"]["status_values"]) - {"ok"}
            if classification not in allowed or (
                status_code is not None
                and (type(status_code) is not int or not 100 <= status_code <= 599)
            ):
                classification, status_code = "malformed_response", None
        _record_proxy_error(
            run,
            request,
            request_sha256,
            classification,
            status_code,
            completed.stdout + completed.stderr,
        )
        raise WorkerError(f"fixed proxy {classification}", run=run)
    if not isinstance(body, dict) or set(body) != {"response", "receipt"}:
        _record_proxy_error(
            run,
            request,
            request_sha256,
            "malformed_response",
            None,
            completed.stdout + completed.stderr,
        )
        raise WorkerError("fixed proxy malformed_response", run=run)
    return body["response"], body["receipt"]


def configure_provider(
    run: dict[str, Any],
    *,
    env_path: str | Path | None = None,
    tool_schemas: Any,
    project_root: Path | None = None,
    config_home: Path | None = None,
) -> dict[str, Any]:
    """Bind one trusted upstream without retaining its credential in run state."""
    try:
        public = provider_transport.configure_provider(
            run,
            env_path=env_path,
            tool_schemas=tool_schemas,
            project_root=project_root,
            config_home=config_home,
        )
    except provider_transport.ProviderError as exc:
        raise WorkerError(str(exc), run=run) from exc
    try:
        provider_service.start(run)
    except provider_transport.ProviderError as exc:
        provider_config.abort_configuration(run)
        raise WorkerError(str(exc), run=run) from exc
    return public


def has_retained_provider_transport(run: dict[str, Any]) -> bool:
    return "provider_transport_rebind" in run or any(
        name in run
        for name in (
            "proxy_firewall",
            "proxy_network",
            "proxy_relay",
            "proxy_policy_sha256",
            "proxy_policy_receipt",
            "egress_policy_sha256",
            "egress_receipt",
        )
    )


_TRANSPORT_REBIND_FIELDS = {
    "schema",
    "binding_sha256",
    "phase",
    "stale",
    "validation",
    "replacement_port",
    "files",
}
_TRANSPORT_STALE_FIELDS = (
    "proxy_firewall",
    "proxy_network",
    "proxy_relay",
)
_TRANSPORT_REPLACED_FIELDS = (
    "proxy_firewall",
    "proxy_network",
    "proxy_relay",
    "proxy_policy_sha256",
    "proxy_policy_receipt",
    "egress_policy_sha256",
    "egress_receipt",
)
_TRANSPORT_VALIDATION_FIELDS = (
    "run_id",
    "provider_binding",
    "provider_binding_sha256",
    "fixed_proxy_sha256",
    "proxy_client_identity_sha256",
    "proxy_policy_sha256",
    "proxy_policy_receipt",
    "image_digest",
    "control_bundle_sha256",
    "native_decide_policy_sha256",
    "worker_inventory_sha256",
    "upstream_policy_sha256",
    "upstream_policy_receipt",
    "egress_policy_sha256",
    "egress_receipt",
    "proxy_firewall",
)


def _transport_history(run: dict[str, Any], intent: dict[str, Any]) -> Path:
    validation = intent.get("validation")
    files = intent.get("files")
    binding_sha256 = intent.get("binding_sha256")
    policy_sha256 = (
        validation.get("proxy_policy_sha256")
        if isinstance(validation, dict)
        else None
    )
    if (
        not isinstance(binding_sha256, str)
        or SHA256.fullmatch(binding_sha256) is None
        or not isinstance(policy_sha256, str)
        or SHA256.fullmatch(policy_sha256) is None
        or not isinstance(files, dict)
    ):
        raise WorkerError("provider transport policy identity is invalid")
    try:
        generation_sha256 = _sha256(
            _canonical_bytes(
                {
                    "schema": "autofv-provider-transport-generation/v1",
                    "binding_sha256": binding_sha256,
                    "validation": validation,
                    "files": files,
                }
            )
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise WorkerError("provider transport generation identity is invalid") from exc
    return (
        Path(run["evidence_dir"])
        / "history"
        / "provider-transport"
        / binding_sha256
        / policy_sha256
        / generation_sha256
    )


def _provider_transport_intent(run: dict[str, Any]) -> dict[str, Any]:
    intent = run.get("provider_transport_rebind")
    if not isinstance(intent, dict) or set(intent) != _TRANSPORT_REBIND_FIELDS:
        raise WorkerError("provider transport rebind intent is invalid")
    binding_sha256 = run.get("provider_binding_sha256")
    files = intent.get("files")
    validation = intent.get("validation")
    if (
        intent.get("schema") != "autofv-provider-transport-rebind/v1"
        or intent.get("binding_sha256") != binding_sha256
        or not isinstance(binding_sha256, str)
        or SHA256.fullmatch(binding_sha256) is None
        or intent.get("phase")
        not in {
            "intent",
            "service_rebound",
            "recreated_service_rebound",
            "transport_restored",
        }
        or not isinstance(intent.get("stale"), dict)
        or not isinstance(validation, dict)
        or set(validation)
        != {*_TRANSPORT_VALIDATION_FIELDS, "fixed_proxy_route"}
        or not isinstance(files, dict)
        or set(files) not in (
            {"fixed-proxy-policy.json", "egress.json"},
            {
                "fixed-proxy-policy.json",
                "egress.json",
                "proxy-policy-matrix.json",
            },
        )
    ):
        raise WorkerError("provider transport rebind intent is invalid")
    replacement_port = intent.get("replacement_port")
    if (
        replacement_port is not None
        and (type(replacement_port) is not int or not 1 <= replacement_port <= 65535)
    ) or (
        intent.get("phase") == "recreated_service_rebound"
        and replacement_port is None
    ):
        raise WorkerError("provider replacement listener identity is invalid")
    for name, metadata in files.items():
        if (
            not isinstance(metadata, dict)
            or set(metadata) != {"sha256", "size"}
            or not isinstance(metadata.get("sha256"), str)
            or SHA256.fullmatch(metadata["sha256"]) is None
            or type(metadata.get("size")) is not int
            or not 0 < metadata["size"] <= 2_000_000
        ):
            raise WorkerError("provider transport archive identity is invalid")
        try:
            _value, raw = evidence._read_provider_artifact(
                _transport_history(run, intent) / name,
                "provider transport history",
            )
        except provider_config.ProviderConfigError as exc:
            raise WorkerError(str(exc), run=run) from exc
        if len(raw) != metadata["size"] or _sha256(raw) != metadata["sha256"]:
            raise WorkerError("provider transport history changed")
    current_lock = run.get("lock")
    fixed_proxy_route = validation.get("fixed_proxy_route")
    if not isinstance(current_lock, dict) or not isinstance(fixed_proxy_route, dict):
        raise WorkerError("provider transport validation identity is invalid")
    archived_run = {
        **run,
        **validation,
        "lock": {**current_lock, "fixed_proxy": fixed_proxy_route},
        "evidence_dir": str(_transport_history(run, intent)),
    }
    try:
        evidence.authenticate_provider_transport_evidence(archived_run)
    except provider_config.ProviderConfigError as exc:
        raise WorkerError(str(exc), run=run) from exc
    return intent


def prepare_provider_transport_rebind(run: dict[str, Any]) -> None:
    """Authenticate and durably archive stale transport before rotating it."""
    if "provider_transport_rebind" in run:
        _provider_transport_intent(run)
        return
    binding = provider_config.provider_binding(run)
    if binding is None or binding.public != run.get("provider_binding"):
        raise WorkerError("provider transport binding is not process-pinned")
    try:
        authenticated = evidence.authenticate_provider_transport_evidence(run)
    except provider_config.ProviderConfigError as exc:
        raise WorkerError(str(exc), run=run) from exc
    stale = {}
    for name in _TRANSPORT_STALE_FIELDS:
        value = run.get(name)
        if value is None:
            continue
        stale[name] = (
            json.loads(_canonical_bytes(value))
            if isinstance(value, (dict, list))
            else value
        )
    validation = {}
    for name in _TRANSPORT_VALIDATION_FIELDS:
        if name not in run:
            raise WorkerError(
                f"provider transport validation identity is missing {name}"
            )
        value = run[name]
        validation[name] = (
            json.loads(_canonical_bytes(value))
            if isinstance(value, (dict, list))
            else value
        )
    route = run.get("lock", {}).get("fixed_proxy")
    if not isinstance(route, dict):
        raise WorkerError("provider transport fixed route identity is missing")
    validation["fixed_proxy_route"] = json.loads(_canonical_bytes(route))
    intent = {
        "schema": "autofv-provider-transport-rebind/v1",
        "binding_sha256": binding.public["binding_sha256"],
        "phase": "intent",
        "stale": stale,
        "validation": validation,
        "replacement_port": None,
        "files": {
            name: {"sha256": _sha256(raw), "size": len(raw)}
            for name, raw in authenticated["files"].items()
        },
    }
    history = _transport_history(run, intent)
    for name, raw in authenticated["files"].items():
        destination = history / name
        if os.path.lexists(destination):
            try:
                _value, retained = evidence._read_provider_artifact(
                    destination, "provider transport history"
                )
            except provider_config.ProviderConfigError as exc:
                raise WorkerError(str(exc), run=run) from exc
            if retained != raw:
                raise WorkerError("provider transport history changed")
        else:
            _atomic_write(destination, raw)
    run["provider_transport_rebind"] = intent


def rebind_provider_transport(
    run: dict[str, Any], *, worker_recreated: bool = False
) -> None:
    """Rotate provider service while retaining durable stale-resource identity."""
    intent = _provider_transport_intent(run)
    binding = provider_config.provider_binding(run)
    if binding is None or binding.public["binding_sha256"] != intent["binding_sha256"]:
        raise WorkerError("provider transport binding is not process-pinned")
    stale = intent["stale"]
    firewall = stale.get("proxy_firewall")
    stale_port = firewall.get("upstream_port") if isinstance(firewall, dict) else None
    if type(stale_port) is not int:
        raise WorkerError("stale provider listener identity is invalid")
    try:
        if worker_recreated:
            replacement_port = intent.get("replacement_port")
            if replacement_port is None:
                replacement_base = provider_service.rebind(
                    run, forbidden_ports=frozenset({stale_port})
                )
                _address, replacement_port = _proxy_endpoint(replacement_base)
                if replacement_port == stale_port:
                    raise WorkerError(
                        "recreated provider listener reused stale transport"
                    )
                intent["replacement_port"] = replacement_port
            else:
                provider_service.rebind(run, required_port=replacement_port)
        else:
            provider_service.rebind(run, required_port=stale_port)
    except provider_transport.ProviderError as exc:
        raise WorkerError(str(exc), run=run) from exc
    for name in _TRANSPORT_REPLACED_FIELDS:
        run.pop(name, None)
    intent["phase"] = (
        "recreated_service_rebound" if worker_recreated else "service_rebound"
    )
    if "provider_transport_rebound" not in run.setdefault("events", []):
        run["events"].append("provider_transport_rebound")


def restore_provider_transport(run: dict[str, Any]) -> None:
    """Replace owned relay/firewall resources after the worker is recoverable."""
    intent = _provider_transport_intent(run)
    stale = intent["stale"]
    firewall = stale.get("proxy_firewall")
    if isinstance(firewall, dict):
        try:
            network_id = firewall["network_id"]
            internal_address = firewall["internal_address"]
            bridge_address = firewall["bridge_address"]
            upstream_address = firewall["upstream_address"]
            upstream_port = firewall["upstream_port"]
            old_rules = (
                (
                    "-i", f"br-{network_id[:12]}", "-d", f"{internal_address}/32",
                    "-p", "tcp", "--dport", str(RELAY_PORT), "-j", "ACCEPT",
                ),
                (
                    "-s", f"{bridge_address}/32", "-d", f"{upstream_address}/32",
                    "-p", "tcp", "--dport", str(upstream_port), "-j", "ACCEPT",
                ),
            )
        except (KeyError, TypeError):
            raise WorkerError("stale provider firewall identity is invalid")
        for rule in old_rules:
            _firewall("iptables", "-D", FORWARD_CHAIN, *rule, check=False)
    relay = stale.get("proxy_relay")
    if isinstance(relay, str) and _resource_matches("relay", relay, run):
        _docker("container", "rm", "--force", relay)
    network = stale.get("proxy_network")
    if isinstance(network, str) and _resource_matches("network", network, run):
        _docker("network", "rm", network)
    matrix = Path(run["evidence_dir"]) / "proxy-policy-matrix.json"
    if os.path.lexists(matrix):
        try:
            matrix.unlink()
        except OSError as exc:
            raise WorkerError("stale provider policy matrix cleanup failed") from exc
    verify_egress(run)
    intent["phase"] = "transport_restored"


def finish_provider_transport_rebind(run: dict[str, Any]) -> None:
    """Forget stale resources only after replacement evidence was checkpointed."""
    intent = _provider_transport_intent(run)
    if intent["phase"] != "transport_restored":
        raise WorkerError("provider transport rebind is incomplete")
    try:
        evidence.authenticate_provider_transport_evidence(run)
    except provider_config.ProviderConfigError as exc:
        raise WorkerError(str(exc), run=run) from exc
    run.pop("provider_transport_rebind")


validate_provider_receipt = provider_service.validate_pinned_receipt
validate_provider_preflight = provider_service.validate_pinned_preflight
provider_messages_sha256 = provider_transport.messages_sha256
provider_reservation_usd = provider_transport.reservation_usd
stage_provider_messages = provider_transport.stage_messages
discard_provider_messages = provider_transport.discard_messages


def run_proxy_policy_matrix(
    run: dict[str, Any], fixture: dict[str, Any]
) -> dict[str, Any]:
    """Prove that the worker-visible relay exposes only fixed inference."""
    cases = fixture.get("rejected_proxy")
    expected_ids = [
        "connect_tunnel",
        "caller_upstream",
        "caller_authorization",
        "provider_admin",
        "file_transfer",
        "batch_jobs",
        "unclassified_surface",
    ]
    if (
        not isinstance(cases, list)
        or any(not isinstance(case, dict) for case in cases)
        or [case.get("id") for case in cases] != expected_ids
    ):
        raise WorkerError("proxy policy fixture cases mismatch")
    network, address = _ensure_proxy_relay(run)
    observed = []
    for case in cases:
        expected_fields = {"id", "method", "path"} | (
            {"header"}
            if case["id"] in {"caller_upstream", "caller_authorization"}
            else set()
        )
        if set(case) != expected_fields:
            raise WorkerError(f"proxy policy case fields mismatch: {case.get('id')}")
        completed = _docker(
            *_runtime_argv(
                run["lock"],
                run["volume"],
                "python",
                "-c",
                _PROXY_POLICY_CLIENT_PROGRAM,
                address,
                str(RELAY_PORT),
                case["method"],
                case["path"],
                case.get("header", ""),
                network=network,
            ),
            input_bytes=_canonical_bytes(
                {
                    "schema": "autofv-model-request/v1",
                    "run_id": run["run_id"],
                    "sequence": 1,
                    "batch_id": None,
                    "request_id": "policy-probe",
                    "role": "policy-probe",
                    "model_id": "policy-probe",
                    "input_hashes": [],
                    "prompt_sha256": "0" * 64,
                }
            ),
            check=False,
        )
        value = _json_output(completed, f"proxy policy case {case['id']}")
        if (
            completed.returncode != 0
            or not isinstance(value, dict)
            or set(value) != {"blocked", "status"}
            or value["blocked"] is not True
            or type(value["status"]) is not int
        ):
            raise WorkerError(f"fixed proxy allowed {case['id']}")
        observed.append({"id": case["id"], **value})

    body = {
        "schema": "autofv-proxy-policy-matrix/v1",
        "run_id": run["run_id"],
        "proxy_policy_sha256": run["proxy_policy_sha256"],
        "fixture_sha256": _sha256(_canonical_bytes(fixture)),
        "rejected": observed,
    }
    receipt = {**body, "matrix_sha256": _sha256(_canonical_bytes(body))}
    _atomic_write(
        Path(run["evidence_dir"]) / "proxy-policy-matrix.json",
        _canonical_bytes(receipt) + b"\n",
    )
    run["events"].append("proxy_policy_matrix_passed")
    return receipt


def run_egress_matrix(
    run: dict[str, Any], fixture: dict[str, Any]
) -> dict[str, Any]:
    """Exercise the outer policy, worker firewall, and fixed relay."""
    if fixture.get("schema") != "autofv-linux-isolation-fixture/v1":
        raise WorkerError("egress fixture schema mismatch")
    denied = fixture.get("denied")
    if not isinstance(denied, list) or [item.get("id") for item in denied] != [
        "external_dns",
        "literal_ipv4",
        "literal_ipv6",
        "link_local_metadata",
    ]:
        raise WorkerError("egress fixture cases mismatch")
    if fixture.get("fixed_proxy") != {
        "method": run["lock"]["fixed_proxy"]["method"],
        "path": run["lock"]["fixed_proxy"]["path"],
    }:
        raise WorkerError("egress fixed route mismatch")
    upstream = run.get("upstream_policy_receipt")
    if not isinstance(upstream, dict):
        raise WorkerError("upstream egress policy evidence is missing")
    upstream_body = {
        key: value for key, value in upstream.items() if key != "policy_sha256"
    }
    if (
        upstream.get("schema") != "autofv-upstream-egress-policy/v1"
        or upstream.get("run_id") != run["run_id"]
        or upstream.get("enforcer") != "macos-seatbelt-network-outbound"
        or upstream.get("policy_sha256") != _sha256(_canonical_bytes(upstream_body))
        or upstream.get("policy_sha256") != run.get("upstream_policy_sha256")
    ):
        raise WorkerError("upstream egress policy evidence is invalid")
    probe = (
        "import json,socket,sys;"
        "kind,host,port=sys.argv[1],sys.argv[2],int(sys.argv[3]);"
        "socket.setdefaulttimeout(2);"
        "blocked=False;reason='';"
        "\ntry:\n"
        "  if kind=='dns': socket.getaddrinfo(host,port)\n"
        "  else:\n"
        "    family=socket.AF_INET6 if kind=='ipv6' else socket.AF_INET\n"
        "    address=(host,port,0,0) if family==socket.AF_INET6 else (host,port)\n"
        "    sock=socket.socket(family,socket.SOCK_STREAM);sock.connect(address)\n"
        "except OSError as error:\n"
        "  blocked=True;reason=type(error).__name__\n"
        "print(json.dumps({'blocked':blocked,'reason':reason},sort_keys=True,separators=(',',':')))\n"
        "raise SystemExit(0 if blocked else 23)"
    )

    def observe(layer: str, *, container: bool = False) -> list[dict[str, Any]]:
        observed = []
        for case in denied:
            if set(case) != {"id", "kind", "host", "port"}:
                raise WorkerError("egress case fields mismatch")
            argv = (
                "python3",
                "-c",
                probe,
                case["kind"],
                case["host"],
                str(case["port"]),
            )
            completed = (
                _docker(
                    *_runtime_argv(
                        run["lock"], run["volume"], *argv, network=network
                    ),
                    check=False,
                )
                if container
                else _lima(*argv, check=False)
            )
            value = _json_output(completed, f"egress case {case['id']}")
            if completed.returncode != 0 or value.get("blocked") is not True:
                raise WorkerError(f"external policy allowed {case['id']} at {layer}")
            observed.append({"id": case["id"], **value})
        return observed

    _firewall_snapshot()
    try:
        for tool in ("iptables", "ip6tables"):
            if _firewall(tool, "-C", "OUTPUT", "-j", OUTPUT_CHAIN, check=False).returncode:
                raise WorkerError("worker firewall bypass precondition failed")
            _firewall(tool, "-D", "OUTPUT", "-j", OUTPUT_CHAIN)
        upstream_denied = observe("upstream_denied")
    finally:
        _install_worker_firewall()

    network, address = _ensure_proxy_relay(run)
    layers = {
        "upstream_denied": upstream_denied,
        "worker_denied": observe("worker_denied"),
        "container_denied": observe("container_denied", container=True),
    }

    route = run["lock"]["fixed_proxy"]
    fixed = _docker(
        *_runtime_argv(
            run["lock"],
            run["volume"],
            "python",
            "-c",
            _PROXY_POLICY_CLIENT_PROGRAM,
            address,
            str(RELAY_PORT),
            route["method"],
            route["path"],
            "",
            network=network,
        ),
        input_bytes=b"{}",
        check=False,
    )
    fixed_value = _json_output(fixed, "fixed proxy reachability")
    if fixed.returncode or fixed_value != {"blocked": True, "status": 400}:
        raise WorkerError("fixed proxy route probe failed")
    network_values = _json_output(
        _docker("network", "inspect", network), "proxy network"
    )
    policy = {
        "schema": "autofv-egress-policy/v1",
        "enforcer": NETWORK_ENFORCER,
        "upstream_policy_sha256": upstream["policy_sha256"],
        "network_id": network_values[0].get("Id"),
        "internal": network_values[0].get("Internal"),
        "firewall": _configure_proxy_firewall(
            run, network, _proxy_resources(run)[1]
        ),
        "fixture_sha256": _sha256(_canonical_bytes(fixture)),
    }
    if policy["internal"] is not True or not policy["network_id"]:
        raise WorkerError("external egress policy inspection mismatch")
    body = {
        "schema": "autofv-egress-evidence/v1",
        "run_id": run["run_id"],
        "policy": {**policy, "policy_sha256": _sha256(_canonical_bytes(policy))},
        "upstream_policy": upstream,
        "fixed_proxy_sha256": run["fixed_proxy_sha256"],
        "proxy_policy_sha256": run["proxy_policy_sha256"],
        **layers,
        "fixed_proxy": {
            "status": "reachable",
            "probe_status": fixed_value["status"],
        },
    }
    evidence = {**body, "evidence_sha256": _sha256(_canonical_bytes(body))}
    path = Path(run["evidence_dir"])
    path.mkdir(parents=True, exist_ok=True)
    _atomic_write(path / "egress.json", _canonical_bytes(evidence) + b"\n")
    run["egress_policy_sha256"] = evidence["policy"]["policy_sha256"]
    run["egress_receipt"] = evidence
    run["events"].append("egress_matrix_passed")
    return evidence
