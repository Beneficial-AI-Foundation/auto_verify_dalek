from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import experiment, provider_config, provider_service, provider_transport, worker, worker_proxy


ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "docker/autofv/toolchain-lock.json").read_bytes())
RUN_TOKEN = "provider-config-run-token"
MODEL_ID = "fixture-model-v1"


def _sha(value) -> str:
    return hashlib.sha256(experiment.canonical_json_bytes(value)).hexdigest()


def _tools() -> list[dict]:
    return [{
        "name": "read_allowed",
        "description": "Read one allowlisted file.",
        "input_schema": {"type": "object", "additionalProperties": False},
    }]


def _environment(
    root: Path,
    *,
    overrides: dict[str, str] | None = None,
    extra_lines: tuple[str, ...] = (),
    mode: int = 0o600,
) -> Path:
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    values = {
        "AUTOFV_PROVIDER_ENDPOINT": "https://provider.invalid/v1/chat/completions",
        "AUTOFV_PROVIDER_MODEL": MODEL_ID,
        "AUTOFV_PROVIDER_API_KEY": "provider-config-canary",
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.000000",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "1.000000",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "4.000000",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(key).decode(),
    }
    values.update(overrides or {})
    path = root / "providers.env"
    path.write_text(
        "".join([*(f"{name}={value}\n" for name, value in values.items()), *(f"{line}\n" for line in extra_lines)])
    )
    path.chmod(mode)
    return path


def _run(root: Path) -> dict:
    return {
        "run_id": "provider-config-run-001",
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "lock": copy.deepcopy(LOCK),
        "fixed_proxy_sha256": _sha(LOCK["fixed_proxy"]),
        "events": [],
    }


class _InertServer:
    server_port = 19084

    def serve_forever(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def server_close(self) -> None:
        return None


def _configure(run: dict, **kwargs):
    with mock.patch.dict(
        os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
    ), mock.patch("autofv.provider_service._serve", return_value=_InertServer()):
        return worker_proxy.configure_provider(run, **kwargs)


class ProviderFirewallTests(unittest.TestCase):
    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            provider_service.release(
                {"provider_binding_sha256": binding.public["binding_sha256"]}
            )

    def test_provider_env_example_is_value_free_and_exact(self) -> None:
        assignments = [
            line
            for line in (ROOT / ".env.example").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(assignments, [
            "AUTOFV_PROVIDER_ENDPOINT=",
            "AUTOFV_PROVIDER_MODEL=",
            "AUTOFV_PROVIDER_API_KEY=",
            "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION=",
            "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION=",
            "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION=",
            "AUTOFV_RECEIPT_SIGNING_KEY_B64=",
        ])

    def test_provider_environment_sources_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {}, clear=True
        ):
            root = Path(temporary)
            (root / ".git").mkdir()
            _environment(root).rename(root / ".env")
            binding = _configure(
                _run(root), tool_schemas=_tools(), project_root=root, config_home=root / "unused"
            )
            self.assertEqual(binding["environment_source"]["kind"], "development")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {}, clear=True
        ):
            root = Path(temporary)
            config = root / "config/autofv"
            config.mkdir(parents=True)
            _environment(config)
            binding = _configure(
                _run(root),
                tool_schemas=_tools(),
                project_root=root / "installed",
                config_home=root / "config",
            )
            self.assertEqual(binding["environment_source"]["kind"], "installed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = _environment(root)
            with mock.patch.dict(os.environ, {"AUTOFV_PROVIDER_ENV": str(path)}):
                binding = _configure(_run(root), tool_schemas=_tools())
            self.assertEqual(binding["environment_source"]["kind"], "explicit")

    def test_provider_environment_rejects_unsafe_files_and_values(self) -> None:
        hostile = (
            {"mode": 0o644},
            {"extra_lines": ("AUTOFV_PROVIDER_MODEL=duplicate",)},
            {"extra_lines": ("AUTOFV_UNKNOWN=value",)},
            {"extra_lines": ("export AUTOFV_UNKNOWN=value",)},
            {"overrides": {"AUTOFV_PROVIDER_ENDPOINT": "http://example.com/v1/chat/completions"}},
            {"overrides": {"AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.00x"}},
        )
        for options in hostile:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run = _run(root)
                with self.assertRaises(worker.WorkerError):
                    _configure(
                        run, env_path=_environment(root, **options), tool_schemas=_tools()
                    )
                self.assertNotIn("provider_binding", run)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link = root / "linked.env"
            link.symlink_to(_environment(root))
            with self.assertRaises(worker.WorkerError):
                _configure(_run(root), env_path=link, tool_schemas=_tools())

    def test_binding_is_write_once_and_transport_rejects_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = _environment(root)
            run = _run(root)
            with mock.patch("autofv.provider_config.os.open", wraps=os.open) as opened:
                _configure(run, env_path=path, tool_schemas=_tools())
            self.assertTrue(opened.call_args.args[1] & getattr(os, "O_NOFOLLOW", 0))
            self.assertTrue(opened.call_args.args[1] & getattr(os, "O_NONBLOCK", 0))
            path.write_text(
                path.read_text().replace("provider-config-canary", "replacement-canary")
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(worker.WorkerError, "already configured"):
                _configure(run, env_path=path, tool_schemas=_tools())

        response = mock.Mock(status=200)
        connection = mock.Mock()
        connection.sock = None
        connection.getresponse.return_value = response
        request = urllib.request.Request(
            "https://provider.invalid/v1/chat/completions", method="POST"
        )
        with mock.patch(
            "autofv.provider_deadline.http.client.HTTPSConnection",
            return_value=connection,
        ) as connect, mock.patch(
            "autofv.provider_transport.urllib.request.build_opener"
        ) as ambient_opener:
            with provider_transport._open_upstream(request, timeout=30):
                pass
        connect.assert_called_once_with("provider.invalid", None, timeout=mock.ANY)
        connection.request.assert_called_once_with(
            "POST", "/v1/chat/completions", body=None, headers={}
        )
        ambient_opener.assert_not_called()

    def test_absolute_deadline_closes_blocked_connect_and_header_reads(self) -> None:
        class BlockingConnection:
            sock = None

            def __init__(self, _host, _port, *, timeout):
                self.timeout = timeout
                self.closed = threading.Event()

            def connect(self):
                if stage == "connect":
                    self.closed.wait(1)
                    raise OSError("connection closed")

            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                self.closed.wait(1)
                raise OSError("connection closed")

            def close(self):
                self.closed.set()

        request = urllib.request.Request(
            "http://127.0.0.1:19085/v1/chat/completions", method="POST"
        )
        for stage in ("connect", "headers"):
            with self.subTest(stage=stage), mock.patch(
                "autofv.provider_deadline.http.client.HTTPConnection",
                BlockingConnection,
            ):
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    provider_transport._open_upstream(
                        request,
                        timeout=0.05,
                        deadline_monotonic_ns=time.monotonic_ns() + 50_000_000,
                    )
                self.assertLess(time.monotonic() - started, 0.5)

    def test_delayed_connect_cannot_transmit_after_deadline(self) -> None:
        release_connect = threading.Event()
        transmitted = threading.Event()
        socket_closed = threading.Event()

        class DelayedSocket:
            def settimeout(self, _timeout):
                return None

            def shutdown(self, _how):
                socket_closed.set()

            def close(self):
                socket_closed.set()

        class DelayedConnection:
            def __init__(self, _host, _port, *, timeout):
                self.timeout = timeout
                self.sock = None

            def connect(self):
                release_connect.wait(1)
                self.sock = DelayedSocket()

            def request(self, *_args, **_kwargs):
                if self.sock is None:
                    self.connect()
                transmitted.set()

            def getresponse(self):
                return mock.Mock(status=200)

            def close(self):
                if self.sock is not None:
                    self.sock.close()

        release_timer = threading.Timer(0.1, release_connect.set)
        release_timer.start()
        request = urllib.request.Request(
            "http://127.0.0.1:19085/v1/chat/completions", method="POST"
        )
        try:
            with mock.patch(
                "autofv.provider_deadline.http.client.HTTPConnection",
                DelayedConnection,
            ), self.assertRaises(TimeoutError):
                provider_transport._open_upstream(
                    request,
                    timeout=0.05,
                    deadline_monotonic_ns=time.monotonic_ns() + 50_000_000,
                )
        finally:
            release_connect.set()
            release_timer.cancel()
            release_timer.join(timeout=0.2)
        self.assertTrue(socket_closed.wait(0.5))
        self.assertFalse(transmitted.is_set())

    def test_connection_close_success_and_error_reads_keep_deadline_socket(self) -> None:
        class DetachedSocket:
            def __init__(self):
                self.closed = threading.Event()

            def settimeout(self, _timeout):
                return None

            def shutdown(self, _how):
                self.closed.set()

            def close(self):
                self.closed.set()

        class SlowChunkReply:
            def __init__(self, status, detached):
                self.status = status
                self.fp = mock.Mock(_sock=detached)
                self.detached = detached

            def read1(self, _size):
                self.detached.closed.wait(0.6)
                if self.detached.closed.is_set():
                    raise OSError("detached response socket closed")
                return b""

            def close(self):
                self.detached.close()

        class ConnectionClose:
            def __init__(self, _host, _port, *, timeout):
                self.timeout = timeout
                self.detached = DetachedSocket()
                self.sock = self.detached
                self.status = 200

            def connect(self):
                return None

            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                response = SlowChunkReply(self.status, self.detached)
                self.sock = None
                return response

            def close(self):
                return None

        request = urllib.request.Request(
            "http://127.0.0.1:19085/v1/chat/completions", method="POST"
        )
        for status in (200, 429):
            connection = ConnectionClose("127.0.0.1", 19085, timeout=1)
            connection.status = status
            deadline = time.monotonic_ns() + 50_000_000
            started = time.monotonic()
            with self.subTest(status=status), mock.patch(
                "autofv.provider_deadline.http.client.HTTPConnection",
                return_value=connection,
            ), self.assertRaisesRegex(worker.WorkerError, "timeout"):
                with provider_transport._open_upstream(
                    request,
                    timeout=0.05,
                    deadline_monotonic_ns=deadline,
                ) as reply:
                    provider_transport._read_upstream(reply, deadline)
            self.assertLess(time.monotonic() - started, 0.3)

    def test_failed_service_start_removes_public_and_private_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = _run(root)
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ), mock.patch(
                "autofv.provider_service._serve", side_effect=OSError("bind denied")
            ), self.assertRaisesRegex(worker.WorkerError, "service unavailable"):
                worker_proxy.configure_provider(
                    run, env_path=_environment(root), tool_schemas=_tools()
                )
            self.assertNotIn("provider_binding", run)
            self.assertNotIn("provider-config-canary", repr(run))

    def test_provider_firewall_ignores_ambient_proxy_authority(self) -> None:
        pinned = "http://10.0.2.2:19083"
        run = {"proxy_base": pinned}
        network = "autofv-provider-network"
        relay = "autofv-provider-relay"

        def docker(*args, **_kwargs):
            if args[:2] == ("network", "inspect"):
                value = [{"Id": "a" * 64}]
            else:
                value = [{
                    "NetworkSettings": {
                        "Networks": {
                            network: {"IPAddress": "172.28.0.2"},
                            "bridge": {"IPAddress": "172.17.0.3"},
                        }
                    }
                }]
            return subprocess.CompletedProcess(args, 0, json.dumps(value).encode(), b"")

        with (
            mock.patch.dict(
                os.environ,
                {"AUTOFV_PROXY_BASE": "https://attacker.invalid/proxy"},
                clear=False,
            ),
            mock.patch("autofv.worker_proxy.provider_transport.is_configured", return_value=True),
            mock.patch("autofv.worker_proxy._docker", side_effect=docker),
            mock.patch("autofv.worker_proxy._firewall_snapshot", return_value=[]),
            mock.patch(
                "autofv.worker_proxy._proxy_endpoint",
                return_value=("10.0.2.2", 19083),
            ) as endpoint,
        ):
            result = worker_proxy._configure_proxy_firewall(run, network, relay)

        endpoint.assert_called_once_with(pinned)
        self.assertEqual(result["base"], pinned)


if __name__ == "__main__":
    unittest.main()
