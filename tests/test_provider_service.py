from __future__ import annotations

import base64
import copy
import errno
import hashlib
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import (
    experiment,
    preflight,
    provider_config,
    provider_receipts,
    provider_service,
    provider_transport,
    worker_proxy,
)


ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "docker/autofv/toolchain-lock.json").read_bytes())
RUN_TOKEN = "provider-service-run-token"
MODEL_ID = "fixture-model-v1"


def _sha(value) -> str:
    return hashlib.sha256(experiment.canonical_json_bytes(value)).hexdigest()


def _tools() -> list[dict]:
    return [{
        "name": "read_allowed",
        "description": "Read one allowlisted file.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    }]


def _messages() -> list[dict]:
    return [
        {"role": "system", "content": "Act only as scout."},
        {"role": "user", "content": "Inspect one declaration."},
    ]


def _environment(root: Path, *, endpoint: str | None = None) -> Path:
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    values = {
        "AUTOFV_PROVIDER_ENDPOINT": endpoint or "https://provider.invalid/v1/chat/completions",
        "AUTOFV_PROVIDER_MODEL": MODEL_ID,
        "AUTOFV_PROVIDER_API_KEY": "provider-service-canary",
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.000000",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "1.000000",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "4.000000",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(key).decode(),
    }
    path = root / "providers.env"
    path.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
    path.chmod(0o600)
    return path


def _run(root: Path) -> dict:
    return {
        "run_id": "provider-service-run-001",
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "volume": "provider-service-volume",
        "base_commit": "1" * 40,
        "lock": copy.deepcopy(LOCK),
        "image_digest": LOCK["image"]["image_digest"],
        "worker_inventory_sha256": "2" * 64,
        "native_decide_policy_sha256": LOCK["native_decide_policy_sha256"],
        "fixed_proxy_sha256": _sha(LOCK["fixed_proxy"]),
        "events": [],
    }


def _request(messages: list[dict]) -> dict:
    request_id = "provider-service-request-001"
    role = "scout"
    return {
        "schema": "autofv-model-request/v1",
        "run_id": "provider-service-run-001",
        "sequence": 1,
        "batch_id": None,
        "request_id": request_id,
        "role": role,
        "model_id": MODEL_ID,
        "input_hashes": [worker_proxy.provider_messages_sha256(messages)],
        "prompt_sha256": hashlib.sha256(
            f"provider-service-run-001\0{request_id}\0{role}\0bounded-v1".encode()
        ).hexdigest(),
    }


def _install_trusted_authorization_fixture(run: dict, root: Path) -> None:
    binding = run["provider_binding"]
    identities = {
        "image_digest": run["image_digest"],
        "runtime_sha256": run["worker_inventory_sha256"],
        "native_decide_policy_sha256": run["native_decide_policy_sha256"],
        "tool_schema_sha256": binding["tool_schema_sha256"],
        "provider_identity_sha256": binding["binding_sha256"],
    }
    artifact_dir = root / "retained-checks"
    artifact_dir.mkdir(exist_ok=True)
    groups = {}
    for prefix, names in (
        ("case", experiment.DETERMINISTIC_PREFLIGHT_CASES),
        ("gate", experiment.DETERMINISTIC_PREFLIGHT_GATES),
    ):
        paths = {}
        for index, name in enumerate(names):
            path = artifact_dir / f"{prefix}-{index:02d}.json"
            preflight.write_check_outcome(
                path,
                check_name=name,
                check_id=f"tests.test_provider_service::{prefix}_{name}",
                status="passed",
                origin="trusted_runner",
                execution_class="sealed_runtime",
                applicability="applicable_sealed_runtime",
                identities=identities,
                source_head=run["base_commit"],
            )
            paths[name] = path
        groups[prefix] = paths
    suite_path = root / "retained-suite.json"
    preflight.write_retained_suite_result(
        suite_path,
        case_outcomes=groups["case"],
        gate_outcomes=groups["gate"],
        identities=identities,
        source_head=run["base_commit"],
        completed_at_unix=int(time.time()),
    )
    suite_sha256 = hashlib.sha256(suite_path.read_bytes()).hexdigest()

    def evidence(prefix: str, name: str) -> dict[str, str]:
        check_id = f"tests.test_provider_service::{prefix}_{name}"
        return experiment.named_check_evidence(
            check_id,
            groups[prefix][name].read_bytes(),
            suite_sha256=suite_sha256,
            evidence_kind="sealed_runtime",
            applicability="applicable_sealed_runtime",
        )

    preflight_path = root / "deterministic-preflight.json"
    experiment.write_deterministic_preflight(
        preflight_path,
        suite_sha256=suite_sha256,
        case_evidence={
            name: evidence("case", name)
            for name in experiment.DETERMINISTIC_PREFLIGHT_CASES
        },
        gate_evidence={
            name: evidence("gate", name)
            for name in experiment.DETERMINISTIC_PREFLIGHT_GATES
        },
        identities=identities,
        zero_secret_scan_sha256="7" * 64,
        source_head=run["base_commit"],
        completed_at_unix=int(time.time()),
    )
    provider_service.load_preflight_authorization(
        run,
        preflight_path=preflight_path,
        suite_artifact_path=suite_path,
        max_age_seconds=300,
    )


def _reply() -> dict:
    return {
        "id": "provider-service-response-001",
        "model": MODEL_ID,
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call-001",
                    "type": "function",
                    "function": {
                        "name": "read_allowed",
                        "arguments": '{"path":"Diamond/Left.lean"}',
                    },
                }],
            },
        }],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 40,
            "total_tokens": 160,
            "prompt_tokens_details": {"cached_tokens": 20},
            "cost": 0.00038,
        },
    }


class _Reply:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return experiment.canonical_json_bytes(_reply())


class _InertServer:
    server_port = 19083

    def serve_forever(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def server_close(self) -> None:
        return None


class _TrackedServer(_InertServer):
    def __init__(self, events: list[str]):
        self.events = events

    def shutdown(self) -> None:
        self.events.append("shutdown")

    def close_active(self) -> None:
        self.events.append("connections_closed")

    def server_close(self) -> None:
        self.events.append("listener_closed")


class _PortServer(_TrackedServer):
    def __init__(self, events: list[str], port: int):
        super().__init__(events)
        self.server_port = port


class ProviderServiceTests(unittest.TestCase):
    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            provider_service.release(
                {"provider_binding_sha256": binding.public["binding_sha256"]}
            )

    def _configured(self, root: Path):
        run = _run(root)
        with mock.patch.dict(
            os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
        ), mock.patch("autofv.provider_service._serve", return_value=_InertServer()):
            worker_proxy.configure_provider(
                run, env_path=_environment(root), tool_schemas=_tools()
            )
        _install_trusted_authorization_fixture(run, root)
        messages = _messages()
        request = _request(messages)
        worker_proxy.stage_provider_messages(run, request, messages)
        return run, request

    def test_completed_journal_reconciles_a_lagging_dispatched_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            real_remember = provider_service._remember
            calls = 0

            def crash_after_completion(target, record):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("simulated crash after durable completion")
                real_remember(target, record)

            opener = mock.Mock(return_value=_Reply())
            with mock.patch(
                "autofv.provider_transport._open_upstream", opener
            ), mock.patch.object(
                provider_service, "_remember", side_effect=crash_after_completion
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)

            response, receipt = provider_service.dispatch(
                run, request, run_token=RUN_TOKEN
            )
            self.assertEqual(response["request_id"], request["request_id"])
            self.assertEqual(receipt["status"], "ok")
            self.assertEqual(opener.call_count, 1)

    def test_service_authenticates_and_fails_closed_on_ambiguous_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            opener = mock.Mock(return_value=_Reply())
            with mock.patch("autofv.provider_transport._open_upstream", opener):
                with self.assertRaisesRegex(provider_transport.ProviderError, "authentication"):
                    provider_service.dispatch(run, request, run_token="caller-token")
                response, receipt = provider_service.dispatch(
                    run, request, run_token=RUN_TOKEN
                )
                self.assertEqual(
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN),
                    (response, receipt),
                )
            self.assertEqual(opener.call_count, 1)

            ambiguous = copy.deepcopy(request)
            ambiguous.update({"sequence": 2, "request_id": "provider-ambiguous-002"})
            worker_proxy.stage_provider_messages(run, ambiguous, _messages())
            with mock.patch(
                "autofv.provider_transport._open_upstream", side_effect=TimeoutError
            ), self.assertRaises(provider_transport.ProviderError):
                provider_service.dispatch(run, ambiguous, run_token=RUN_TOKEN)
            worker_proxy.stage_provider_messages(run, ambiguous, _messages())
            with self.assertRaisesRegex(provider_transport.ProviderError, "ambiguous"):
                provider_service.dispatch(run, ambiguous, run_token=RUN_TOKEN)

    def test_concurrent_calls_retain_each_completion_before_single_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, first = self._configured(root)
            second = copy.deepcopy(first)
            second.update({"sequence": 2, "request_id": "provider-concurrent-002"})
            worker_proxy.stage_provider_messages(run, second, _messages())
            barrier = threading.Barrier(2)

            def upstream(_request, *, timeout, deadline_monotonic_ns=None):
                self.assertGreater(timeout, 0)
                self.assertIsInstance(deadline_monotonic_ns, int)
                barrier.wait(timeout=5)
                return _Reply()

            original = provider_service._write_preflight

            def retained_first(binding, candidate_run, request, response, receipt):
                records = [
                    json.loads(path.read_bytes())
                    for path in (root / "evidence/provider-journal").glob("*.json")
                ]
                self.assertTrue(any(
                    item["request_id"] == request["request_id"]
                    and item["status"] == "completed"
                    for item in records
                ))
                return original(binding, candidate_run, request, response, receipt)

            with mock.patch(
                "autofv.provider_transport._open_upstream", side_effect=upstream
            ), mock.patch.object(
                provider_service, "_write_preflight", side_effect=retained_first
            ), ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(
                    lambda request: provider_service.dispatch(
                        run, request, run_token=RUN_TOKEN
                    ),
                    (first, second),
                ))
            self.assertEqual(len(results), 2)
            self.assertEqual(
                len(list((root / "evidence/provider-journal").glob("*.json"))), 2
            )
            self.assertTrue((root / "evidence/provider-preflight.json").is_file())

    def test_replayed_completed_exchange_is_secret_scanned_before_return(self) -> None:
        encoded_key = "\\u0070\\u0072\\u006f\\u0076\\u0069\\u0064\\u0065\\u0072\\u002d\\u0073\\u0065\\u0072\\u0076\\u0069\\u0063\\u0065\\u002d\\u0063\\u0061\\u006e\\u0061\\u0072\\u0079"
        for surface in ("response", "receipt"):
            with self.subTest(surface=surface), tempfile.TemporaryDirectory() as temporary:
                run, request = self._configured(Path(temporary))
                with mock.patch(
                    "autofv.provider_transport._open_upstream", return_value=_Reply()
                ):
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)

                journal = next(
                    (Path(run["evidence_dir"]) / "provider-journal").iterdir()
                )
                record = json.loads(journal.read_bytes())
                record[surface][encoded_key] = "x"
                body = {
                    key: value for key, value in record.items() if key != "record_sha256"
                }
                record["record_sha256"] = _sha(body)
                journal.write_bytes(experiment.canonical_json_bytes(record) + b"\n")
                run["provider_journal"].clear()

                with self.assertRaisesRegex(
                    provider_transport.ProviderError, "credential material"
                ):
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)

    def test_service_bounds_connections_and_closes_them_before_secret_release(self) -> None:
        self.assertLessEqual(provider_service._BoundedHTTPServer.request_queue_size, 16)
        self.assertTrue(provider_service._BoundedHTTPServer.daemon_threads)
        self.assertFalse(provider_service._BoundedHTTPServer.block_on_close)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = _run(root)
            events: list[str] = []
            server = _TrackedServer(events)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch("autofv.provider_service._serve", return_value=server):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            binding = provider_config.provider_binding(run)
            api_key, client_token = binding.api_key, binding.client_token
            real_release = provider_config.release_provider

            def release(target):
                events.append("secrets_released")
                real_release(target)

            with mock.patch.object(provider_config, "release_provider", side_effect=release):
                provider_service.release(run)

            self.assertLess(
                events.index("connections_closed"), events.index("secrets_released")
            )
            self.assertEqual(api_key, bytearray(len(api_key)))
            self.assertEqual(client_token, bytearray(len(client_token)))
            self.assertEqual(binding.pending_messages, {})

    def test_stable_provider_rebind_rotates_transient_listener_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_events: list[str] = []
            second_events: list[str] = []
            first = _PortServer(first_events, 19082)
            second = _PortServer(second_events, 19083)
            run = _run(root)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch(
                "autofv.provider_service._serve", return_value=first
            ):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            stable_binding = copy.deepcopy(run["provider_binding"])
            stale_base = run["proxy_base"]

            with mock.patch(
                "autofv.provider_service._serve", return_value=second
            ):
                refreshed = provider_service.rebind(run)

            self.assertEqual(run["provider_binding"], stable_binding)
            self.assertNotEqual(refreshed, stale_base)
            self.assertEqual(refreshed, "http://127.0.0.1:19083")
            self.assertEqual(run["provider_service"]["port"], 19083)
            self.assertEqual(
                first_events,
                ["shutdown", "connections_closed", "listener_closed"],
            )

    def test_same_port_rebind_dispatches_and_accounts_against_restored_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, request = self._configured(root)
            restored = copy.deepcopy(run)
            digest = run["provider_binding_sha256"]

            with mock.patch.object(provider_service, "_serve") as serve:
                provider_service.rebind(restored, required_port=19083)
            serve.assert_not_called()

            with provider_service._SERVICES_LOCK:
                context = provider_service._SERVICES[digest].context
            with mock.patch(
                "autofv.provider_transport._open_upstream", return_value=_Reply()
            ):
                response, receipt = context.dispatch(
                    request, run_token=RUN_TOKEN
                )

            self.assertNotIn(request["request_id"], run.get("provider_journal", {}))
            self.assertIn(request["request_id"], restored["provider_journal"])
            reduced = provider_receipts.reduce_accounting(
                restored,
                {
                    "config": {"model": MODEL_ID},
                    "receipts": [receipt],
                    "model_exchanges": {
                        request["request_id"]: {
                            "request": request,
                            "response": response,
                            "receipt": receipt,
                            "call_kind": "explicit",
                        }
                    },
                    "pending_model_exchanges": {},
                },
                binding=restored["provider_binding"],
            )
            self.assertTrue(reduced["accounting_complete"])
            self.assertEqual(reduced["requests"], 1)

    def test_surviving_service_rebinds_the_checkpoint_listener_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = _PortServer([], 19082)
            run = _run(root)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch(
                "autofv.provider_service._serve", return_value=initial
            ):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            digest = run["provider_binding_sha256"]
            with provider_service._SERVICES_LOCK:
                stopped = provider_service._SERVICES.pop(digest)
            provider_service._stop_service(stopped)
            replacement = _PortServer([], 19082)

            with mock.patch(
                "autofv.provider_service._serve", return_value=replacement
            ) as serve:
                refreshed = provider_service.rebind(run, required_port=19082)

            self.assertEqual(refreshed, "http://127.0.0.1:19082")
            serve.assert_called_once_with(mock.ANY, 19082)

    def test_surviving_service_fails_closed_if_checkpoint_port_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = _PortServer([], 19082)
            run = _run(root)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch(
                "autofv.provider_service._serve", return_value=initial
            ):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            digest = run["provider_binding_sha256"]
            with provider_service._SERVICES_LOCK:
                stopped = provider_service._SERVICES.pop(digest)
            provider_service._stop_service(stopped)
            wrong_events: list[str] = []
            wrong = _PortServer(wrong_events, 19083)

            with mock.patch(
                "autofv.provider_service._serve", return_value=wrong
            ), self.assertRaisesRegex(
                provider_transport.ProviderError, "required listener port"
            ):
                provider_service.rebind(run, required_port=19082)

            self.assertEqual(wrong_events, ["listener_closed"])
            self.assertNotIn(digest, provider_service._SERVICES)

    def test_recreated_service_refuses_the_checkpoint_transport_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = _PortServer([], 19082)
            run = _run(root)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch(
                "autofv.provider_service._serve", return_value=initial
            ):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            digest = run["provider_binding_sha256"]
            with provider_service._SERVICES_LOCK:
                stopped = provider_service._SERVICES.pop(digest)
            provider_service._stop_service(stopped)
            refused_events: list[str] = []
            refused = _PortServer(refused_events, 19082)
            replacement = _PortServer([], 19083)

            with mock.patch(
                "autofv.provider_service._serve",
                side_effect=[refused, replacement],
            ):
                refreshed = provider_service.rebind(
                    run, forbidden_ports=frozenset({19082})
                )

            self.assertEqual(refreshed, "http://127.0.0.1:19083")
            self.assertEqual(refused_events, ["listener_closed"])

    def test_actual_host_service_is_reached_only_through_simulated_runsc_relay(self) -> None:
        upstream_requests: list[dict] = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                upstream_requests.append({
                    "authorization": self.headers.get("Authorization"),
                    "body": json.loads(self.rfile.read(length)),
                })
                raw = experiment.canonical_json_bytes(_reply())
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args) -> None:
                return

        try:
            upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        except PermissionError as exc:
            self.skipTest(f"managed sandbox forbids loopback bind: {exc}")
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run = _run(root)
                endpoint = (
                    f"http://127.0.0.1:{upstream.server_port}/v1/chat/completions"
                )
                with mock.patch.dict(
                    os.environ,
                    {
                        "AUTOFV_RUN_TOKEN": RUN_TOKEN,
                        "AUTOFV_PROXY_BASE": "https://attacker.invalid/proxy",
                    },
                    clear=False,
                ):
                    worker_proxy.configure_provider(
                        run, env_path=_environment(root, endpoint=endpoint), tool_schemas=_tools()
                    )
                    binding = provider_config.provider_binding(run)
                    messages = _messages()
                    request = _request(messages)
                    worker_proxy.stage_provider_messages(run, request, messages)
                    service_base = run["proxy_base"]
                    relay_environment = {
                        "AUTOFV_PROXY_BASE": service_base,
                        "AUTOFV_PROXY_PATH": LOCK["fixed_proxy"]["path"],
                        "AUTOFV_RUN_TOKEN": RUN_TOKEN,
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                    relay_environment_bytes = repr(relay_environment).encode()
                    for marker in binding.secret_markers:
                        self.assertNotIn(marker, relay_environment_bytes)
                    try:
                        relay = subprocess.Popen(
                            [sys.executable, "-c", worker_proxy._RELAY_PROGRAM],
                            env=relay_environment,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                    except OSError as exc:
                        if exc.errno in {errno.EPERM, errno.EACCES, errno.EADDRINUSE}:
                            self.skipTest(f"loopback relay unavailable: {exc}")
                        raise
                    try:
                        deadline = time.monotonic() + 3
                        while True:
                            if relay.poll() is not None:
                                _stdout, stderr = relay.communicate()
                                detail = stderr.decode("utf-8", "replace")
                                unavailable = (
                                    "[Errno 1] Operation not permitted",
                                    "[Errno 13] Permission denied",
                                    "[Errno 48] Address already in use",
                                    "[Errno 98] Address already in use",
                                )
                                if any(marker in detail for marker in unavailable):
                                    self.skipTest(
                                        "loopback relay unavailable: " + detail.strip()
                                    )
                                self.fail("relay startup failed: " + detail[-2000:])
                            try:
                                with socket.create_connection(
                                    ("127.0.0.1", worker_proxy.RELAY_PORT), timeout=0.1
                                ):
                                    break
                            except OSError as exc:
                                if time.monotonic() >= deadline:
                                    relay.terminate()
                                    try:
                                        _stdout, stderr = relay.communicate(timeout=1)
                                    except subprocess.TimeoutExpired:
                                        relay.kill()
                                        _stdout, stderr = relay.communicate(timeout=1)
                                    detail = stderr.decode("utf-8", "replace")
                                    self.fail(
                                        "relay readiness failed: "
                                        f"{exc}; stderr={detail[-2000:]}"
                                    )
                                time.sleep(0.01)

                        relay_url = (
                            f"http://127.0.0.1:{worker_proxy.RELAY_PORT}"
                            f"{LOCK['fixed_proxy']['path']}"
                        )
                        for label, url, headers, status in (
                            (
                                "authority",
                                relay_url,
                                {"Authorization": "Bearer caller"},
                                403,
                            ),
                            (
                                "path",
                                f"http://127.0.0.1:{worker_proxy.RELAY_PORT}/attacker",
                                {},
                                404,
                            ),
                        ):
                            hostile = urllib.request.Request(
                                url, data=b"{}", method="POST", headers=headers
                            )
                            with self.subTest(label=label), self.assertRaises(
                                urllib.error.HTTPError
                            ) as rejected:
                                urllib.request.urlopen(hostile, timeout=2)
                            self.assertEqual(rejected.exception.code, status)

                        def simulated_runsc(*args, input_bytes=None, **_kwargs):
                            worker_input = input_bytes or b""
                            worker_argv = repr(args).encode()
                            for marker in binding.secret_markers:
                                self.assertNotIn(marker, worker_argv)
                                self.assertNotIn(marker, worker_input)
                            self.assertNotIn(RUN_TOKEN.encode(), worker_argv)
                            self.assertNotIn(RUN_TOKEN.encode(), worker_input)
                            completed = subprocess.run(
                                [
                                    sys.executable,
                                    "-c",
                                    worker_proxy._PROXY_CLIENT_PROGRAM,
                                    args[-1],
                                ],
                                input=worker_input,
                                capture_output=True,
                                timeout=5,
                                check=False,
                            )
                            return subprocess.CompletedProcess(
                                args,
                                completed.returncode,
                                completed.stdout,
                                completed.stderr,
                            )

                        with mock.patch(
                            "autofv.worker_proxy._ensure_proxy_relay",
                            return_value=("simulated-network", "127.0.0.1"),
                        ), mock.patch(
                            "autofv.worker_proxy._docker", side_effect=simulated_runsc
                        ), mock.patch.object(
                            provider_service,
                            "dispatch",
                            wraps=provider_service.dispatch,
                        ) as trusted_dispatch:
                            response, receipt = worker_proxy.proxy_round(run, request)
                    finally:
                        if relay.poll() is None:
                            relay.terminate()
                            try:
                                relay.communicate(timeout=1)
                            except subprocess.TimeoutExpired:
                                relay.kill()
                                relay.communicate(timeout=1)

                self.assertEqual(response["request_id"], request["request_id"])
                self.assertEqual(receipt["status"], "ok")
                self.assertEqual(trusted_dispatch.call_count, 1)
                self.assertEqual(len(upstream_requests), 1)
                self.assertEqual(
                    upstream_requests[0]["authorization"],
                    "Bearer provider-service-canary",
                )
                self.assertEqual(
                    upstream_requests[0]["body"]["messages"], messages
                )
                provider_service.release(run)
        finally:
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=1)

if __name__ == "__main__":
    unittest.main()
