from __future__ import annotations

import base64
import copy
import hashlib
import http.server
import json
import os
import io
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
from decimal import Decimal
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import (
    experiment,
    model,
    provider_config,
    provider_messages,
    provider_service,
    provider_transport,
    worker,
    worker_artifacts,
    worker_proxy,
)


ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "docker/autofv/toolchain-lock.json").read_bytes())
RUN_TOKEN = "provider-receipt-run-token"
MODEL_ID = "fixture-model-v1"


def _sha(value) -> str:
    return hashlib.sha256(experiment.canonical_json_bytes(value)).hexdigest()


def _run(root: Path) -> dict:
    return {
        "run_id": "provider-receipt-run-001",
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "volume": "provider-receipt-volume",
        "base_commit": "1" * 40,
        "lock": copy.deepcopy(LOCK),
        "fixed_proxy_sha256": _sha(LOCK["fixed_proxy"]),
        "events": [],
    }


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
        {"role": "user", "content": "Inspect the requested declaration."},
    ]


def _environment(
    root: Path,
    api_key: str,
    *,
    endpoint: str = "https://provider.invalid/v1/chat/completions",
) -> Path:
    signing_key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    values = {
        "AUTOFV_PROVIDER_ENDPOINT": endpoint,
        "AUTOFV_PROVIDER_MODEL": MODEL_ID,
        "AUTOFV_PROVIDER_API_KEY": api_key,
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.000000",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "1.000000",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "4.000000",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(signing_key).decode(),
    }
    path = root / "providers.env"
    path.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
    path.chmod(0o600)
    return path


def _request(messages: list[dict]) -> dict:
    return {
        "schema": "autofv-model-request/v1",
        "run_id": "provider-receipt-run-001",
        "sequence": 1,
        "batch_id": None,
        "request_id": "provider-receipt-request-001",
        "role": "scout",
        "model_id": MODEL_ID,
        "input_hashes": [worker_proxy.provider_messages_sha256(messages)],
        "prompt_sha256": "2" * 64,
    }


class _Reply:
    status = 200

    def __init__(self, value: dict):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return experiment.canonical_json_bytes(self.value)


class _RawReply(_Reply):
    def __init__(self, raw: bytes):
        self.raw = raw

    def read(self, _limit: int) -> bytes:
        return self.raw


class _WrongBodyReply(_Reply):
    def read(self, _limit: int):
        return "not-bytes"


class _InertServer:
    server_port = 19082

    def serve_forever(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def server_close(self) -> None:
        return None


def _reply(arguments: str, *, cost: object = 0.00038) -> dict:
    return {
        "id": "provider-response-001",
        "model": MODEL_ID,
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call-001",
                    "type": "function",
                    "function": {"name": "read_allowed", "arguments": arguments},
                }],
            },
        }],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 40,
            "total_tokens": 160,
            "prompt_tokens_details": {"cached_tokens": 20},
            "cost": cost,
            "cost_details": {"upstream_inference_cost": cost},
        },
    }


def _empty_tar() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w"):
        pass
    return stream.getvalue()


class ProviderReceiptTests(unittest.TestCase):
    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            run = {"provider_binding_sha256": binding.public["binding_sha256"]}
            provider_config.release_provider(run)

    def test_preflight_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "provider-preflight.fifo"
            os.mkfifo(fifo)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from autofv.provider_receipts import validate_preflight; "
                        "validate_preflight(__import__('sys').argv[1])"
                    ),
                    str(fifo),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT)},
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("provider preflight is missing or unsafe", completed.stderr)

    def test_canonical_journal_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "provider-journal.json"
            os.mkfifo(fifo)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        "from autofv.provider_receipts import _read_canonical; "
                        "_read_canonical(Path(__import__('sys').argv[1]), 'provider journal')"
                    ),
                    str(fifo),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT)},
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("provider journal is missing or unsafe", completed.stderr)

    def _configured(
        self,
        root: Path,
        api_key: str = "provider-canary-secret",
        *,
        endpoint: str = "https://provider.invalid/v1/chat/completions",
    ):
        run = _run(root)
        with mock.patch.dict(
            os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
        ), mock.patch("autofv.provider_service._serve", return_value=_InertServer()):
            worker_proxy.configure_provider(
                run,
                env_path=_environment(root, api_key, endpoint=endpoint),
                tool_schemas=_tools(),
            )
        messages = _messages()
        request = _request(messages)
        worker_proxy.stage_provider_messages(run, request, messages)
        return run, request

    def test_decoded_tool_arguments_and_normalized_exchange_are_secret_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            escaped = "".join(f"\\u{ord(character):04x}" for character in "provider-canary-secret")
            arguments = json.dumps({"path": json.dumps({"nested": escaped})})
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply(arguments)),
            ):
                with self.assertRaisesRegex(worker.WorkerError, "credential material"):
                    provider_transport.provider_round(run, request)

            journal_root = Path(run["evidence_dir"]) / "provider-journal"
            self.assertFalse(journal_root.exists())

    def test_provider_billed_cost_is_preserved_separately_from_calculated_estimate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')),
            ):
                response, receipt = provider_transport.provider_round(run, request)

            self.assertEqual(receipt["cost"]["basis"], "provider_billed")
            self.assertEqual(receipt["cost"]["amount"], "0.000380")
            self.assertEqual(
                receipt["provider"]["billing"]["provider_reported"],
                {
                    "amount": "0.00038",
                    "currency": "USD",
                    "amount_contract": "exact-decimal-usd-max-6",
                    "details": {"upstream_inference_cost": "0.00038"},
                },
            )
            self.assertEqual(
                receipt["provider"]["billing"]["calculated_estimate"],
                {"amount": "0.000380", "currency": "USD"},
            )
            self.assertEqual(
                worker_proxy.validate_provider_receipt(
                    receipt,
                    run=run,
                    run_id=request["run_id"],
                    sequence=1,
                    request_id=request["request_id"],
                    model_id=MODEL_ID,
                    request_sha256=_sha(request),
                    response_sha256=_sha(response),
                    seen_receipt_sha256=frozenset(),
                ),
                Decimal("0.000380"),
            )
            self.assertGreaterEqual(
                worker_proxy.provider_reservation_usd(run, request, _messages()),
                Decimal(receipt["cost"]["amount"]),
            )

    def test_provider_billing_must_match_the_pinned_pricing_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(
                    _reply('{"path":"Diamond/Left.lean"}', cost=0.012345)
                ),
            ):
                with self.assertRaisesRegex(
                    worker.WorkerError, "does not match pinned pricing"
                ):
                    provider_transport.provider_round(run, request)

    def test_provider_billing_rejects_unsupported_exact_precision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            raw = experiment.canonical_json_bytes(
                _reply('{"path":"Diamond/Left.lean"}')
            ).replace(b'"cost":0.00038', b'"cost":0.0003800', 1)
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_RawReply(raw),
            ):
                with self.assertRaisesRegex(
                    worker.WorkerError, "precision"
                ):
                    provider_transport.provider_round(run, request)

    def test_http_error_body_uses_bounded_scanner_and_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            provider_transport.discard_messages(run, request["request_id"])
            with mock.patch.object(
                provider_messages.time, "monotonic_ns", return_value=1_000_000_000
            ):
                worker_proxy.stage_provider_messages(
                    run, request, _messages(), timeout_seconds=1
                )
            error = urllib.error.HTTPError(
                "https://provider.invalid/v1/chat/completions",
                429,
                "limited",
                {},
                io.BytesIO(b'{"error":"rate limited"}'),
            )
            with (
                mock.patch(
                    "autofv.provider_transport._open_upstream", side_effect=error
                ),
                mock.patch.object(
                    provider_transport.time,
                    "monotonic_ns",
                    side_effect=(1_100_000_000, 2_100_000_000),
                ),
            ):
                with self.assertRaisesRegex(worker.WorkerError, "timeout"):
                    provider_transport.provider_round(run, request)

    def test_http_error_body_is_scanned_and_classified_without_leaking(self) -> None:
        cases = {
            "classified": (b'{"error":"limited"}', "rate_limited"),
            "secret": (
                base64.b64encode(b"provider-canary-secret"),
                "credential material",
            ),
        }
        for label, (raw, expected) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                run, request = self._configured(Path(temporary))
                error = urllib.error.HTTPError(
                    "https://provider.invalid/v1/chat/completions",
                    429,
                    "limited",
                    {},
                    io.BytesIO(raw),
                )
                with mock.patch(
                    "autofv.provider_transport._open_upstream", side_effect=error
                ), self.assertRaises(worker.WorkerError) as raised:
                    provider_transport.provider_round(run, request)
                if label == "classified":
                    self.assertEqual(raised.exception.classification, expected)
                else:
                    self.assertIn(expected, str(raised.exception))

    def test_real_slow_headers_and_error_body_obey_one_deadline(self) -> None:
        class SlowProvider(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                system = json.loads(self.rfile.read(length))["messages"][0]["content"]
                sequence = 2 if system.endswith("2") else 1
                raw = b'{"error":"bounded"}'
                self.send_response(200 if sequence == 1 else 429)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    chunk_header = (
                        f"{len(raw):x};probe=".encode("ascii")
                        + b"x" * 64
                        + b"\r\n"
                    )
                    for octet in chunk_header:
                        self.connection.sendall(bytes((octet,)))
                        time.sleep(0.02)
                    self.connection.sendall(raw + b"\r\n0\r\n\r\n")
                except OSError:
                    pass

            def log_message(self, *_args) -> None:
                return

        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowProvider)
        except PermissionError as exc:
            self.skipTest(f"managed sandbox forbids loopback bind: {exc}")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                endpoint = (
                    f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
                )
                run, request = self._configured(root, endpoint=endpoint)
                for sequence in (1, 2):
                    current = copy.deepcopy(request)
                    current["sequence"] = sequence
                    current["request_id"] = f"slow-provider-{sequence}"
                    messages = [
                        {"role": "system", "content": f"sequence {sequence}"},
                        {"role": "user", "content": "bounded timeout"},
                    ]
                    current["input_hashes"] = [
                        worker_proxy.provider_messages_sha256(messages)
                    ]
                    worker_proxy.stage_provider_messages(
                        run, current, messages, timeout_seconds=0.05
                    )
                    with self.subTest(sequence=sequence), self.assertRaisesRegex(
                        worker.WorkerError, "timeout"
                    ):
                        started = time.monotonic()
                        provider_transport.provider_round(run, current)
                    self.assertLess(time.monotonic() - started, 0.3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_one_absolute_deadline_covers_headers_and_the_complete_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            provider_transport.discard_messages(run, request["request_id"])
            with mock.patch.object(
                provider_messages.time, "monotonic_ns", return_value=1_000_000_000
            ):
                worker_proxy.stage_provider_messages(
                    run, request, _messages(), timeout_seconds=1
                )
            with (
                mock.patch(
                    "autofv.provider_transport._open_upstream",
                    return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')),
                ),
                mock.patch.object(
                    provider_messages.time,
                    "monotonic_ns",
                    return_value=1_100_000_000,
                ),
                mock.patch.object(
                    provider_transport.time,
                    "monotonic_ns",
                    side_effect=(
                        1_200_000_000,
                        1_300_000_000,
                        1_400_000_000,
                        2_100_000_000,
                    ),
                ),
            ):
                with self.assertRaisesRegex(worker.WorkerError, "timeout"):
                    provider_transport.provider_round(run, request)

    def test_model_timeout_includes_elapsed_uncommitted_wall_time(self) -> None:
        state = {
            "config": {"max_wall_seconds": Decimal("10")},
            "wall_seconds_used": Decimal("3"),
            "wall_started_monotonic_ns": 1_000_000_000,
            "finalization_reserve_seconds": Decimal("1"),
        }
        with mock.patch.object(
            model.time, "monotonic_ns", return_value=3_000_000_000
        ):
            self.assertEqual(model._provider_timeout_seconds(state), 4.0)

    def test_malformed_nested_usage_numbers_unicode_and_arguments_are_classified(self) -> None:
        base = _reply('{"path":"Diamond/Left.lean"}')
        missing_cached = copy.deepcopy(base)
        missing_cached["usage"]["prompt_tokens_details"] = {}
        float_arguments = copy.deepcopy(base)
        float_arguments["choices"][0]["message"]["tool_calls"][0]["function"][
            "arguments"
        ] = '{"line":1.5}'
        wrong_function_name = copy.deepcopy(base)
        wrong_function_name["choices"][0]["message"]["tool_calls"][0]["function"][
            "name"
        ] = {}
        deep = copy.deepcopy(base)
        nested = {}
        cursor = nested
        for _ in range(20):
            cursor["next"] = {}
            cursor = cursor["next"]
        deep["usage"]["cost_details"] = nested
        cases = {
            "missing-cached-detail": _Reply(missing_cached),
            "decoded-float-arguments": _Reply(float_arguments),
            "wrong-function-name-type": _Reply(wrong_function_name),
            "excessive-depth": _Reply(deep),
            "lone-surrogate": _RawReply(
                experiment.canonical_json_bytes(base).replace(
                    b'"provider-response-001"', b'"\\ud800"'
                )
            ),
            "numeric-overflow": _RawReply(
                experiment.canonical_json_bytes(base).replace(
                    b'"prompt_tokens":120', b'"prompt_tokens":10000000000000000'
                )
            ),
            "decimal-exponent-overflow": _RawReply(
                experiment.canonical_json_bytes(base).replace(
                    b'"cost":0.00038', b'"cost":1e999999', 1
                )
            ),
            "decimal-precision-overflow": _RawReply(
                experiment.canonical_json_bytes(base).replace(
                    b'"cost":0.00038',
                    b'"cost":0.123456789012345678901234567890123',
                    1,
                )
            ),
            "wrong-body-type": _WrongBodyReply(base),
        }
        for label, reply in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                run, request = self._configured(Path(temporary))
                with mock.patch(
                    "autofv.provider_transport._open_upstream", return_value=reply
                ):
                    with self.assertRaises(worker.WorkerError):
                        provider_transport.provider_round(run, request)
                provider_config.release_provider(run)

    def test_malformed_dispatch_text_and_hash_types_are_classified(self) -> None:
        cases = {
            "request-id-unicode": ("request_id", "\ud800"),
            "role-object": ("role", {}),
            "batch-array": ("batch_id", []),
            "hash-object": ("input_hashes", [{}]),
        }
        for label, (field, value) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                run, request = self._configured(Path(temporary))
                hostile = copy.deepcopy(request)
                hostile[field] = value
                with self.assertRaises(worker.WorkerError):
                    worker_proxy.stage_provider_messages(run, hostile, _messages())
                provider_config.release_provider(run)

        with tempfile.TemporaryDirectory() as temporary:
            run, request = self._configured(Path(temporary))
            hostile_messages = _messages()
            hostile_messages[0]["role"] = {}
            with self.assertRaisesRegex(worker.WorkerError, "role"):
                worker_proxy.stage_provider_messages(
                    run, request, hostile_messages
                )

    def test_secret_scan_keeps_structure_and_decode_bounds_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, _staged_request = self._configured(Path(temporary))
            binding = provider_config.provider_binding(run)
            nested: dict = {}
            cursor = nested
            for _ in range(10):
                cursor["next"] = {}
                cursor = cursor["next"]
            cursor["value"] = base64.b64encode(b"provider-canary-secret").decode()
            with self.assertRaisesRegex(worker.WorkerError, "credential material"):
                provider_messages.scan_response(nested, binding)

            encoded = b"harmless"
            for _ in range(6):
                encoded = base64.b64encode(encoded)
            with self.assertRaisesRegex(worker.WorkerError, "decode bound"):
                provider_messages.scan_response({"value": encoded.decode()}, binding)

            hostile_messages = [
                {"role": "system", "content": "bounded"},
                {
                    "role": "user",
                    "content": base64.b64encode(
                        b"provider-canary-secret"
                    ).decode(),
                },
            ]
            hostile_request = _request(hostile_messages)
            with self.assertRaisesRegex(worker.WorkerError, "credential material"):
                worker_proxy.stage_provider_messages(
                    run, hostile_request, hostile_messages
                )

    def test_provider_secrets_never_enter_worker_scan_arguments_or_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run, _request = self._configured(Path(temporary))
            binding = provider_config.provider_binding(run)
            observed: list[tuple[tuple[object, ...], bytes | None]] = []
            roots = [
                {
                    "root": root,
                    "surface": surface,
                    "files": 0,
                    "bytes": 0,
                    "manifest_sha256": hashlib.sha256(b"").hexdigest(),
                }
                for root, surface in (
                    ("/volume/work", "filesystem"),
                    ("/volume/accepted", "filesystem"),
                    ("/volume/autofv-control", "filesystem"),
                    ("/volume/logs", "log"),
                    ("/volume/evidence", "transcript"),
                    ("/volume/lanes", "state"),
                )
            ]
            directory_entry = json.dumps(
                [".ignored", "directory"], ensure_ascii=True
            ).encode()
            roots[0]["manifest_sha256"] = hashlib.sha256(
                directory_entry + b"\n"
            ).hexdigest()
            volume_stream = io.BytesIO()
            with tarfile.open(fileobj=volume_stream, mode="w") as archive:
                for name in (
                    "work",
                    "work/.ignored",
                    "accepted",
                    "autofv-control",
                    "logs",
                    "evidence",
                    "lanes",
                ):
                    entry = tarfile.TarInfo(name)
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)

            def docker(*args, input_bytes=None, **_kwargs):
                observed.append((args, input_bytes))
                if "tar" in args:
                    return subprocess.CompletedProcess(
                        args, 0, volume_stream.getvalue(), b""
                    )
                value = {
                    "schema": "autofv-worker-filesystem-scan/v1",
                    "roots": roots,
                    "hit_surfaces": [],
                    "clean": True,
                }
                return subprocess.CompletedProcess(
                    args, 0, experiment.canonical_json_bytes(value), b""
                )

            with (
                mock.patch.object(
                    worker_artifacts, "_worker_environment_artifacts", return_value={}
                ),
                mock.patch.object(worker_artifacts, "_docker", side_effect=docker),
                mock.patch.object(worker_artifacts, "_host_artifacts", return_value={}),
            ):
                scan = worker_artifacts.scan_retained_state(
                    run,
                    {"accepted/commit.txt": b"clean"},
                    trusted_markers=binding.secret_markers,
                )

            self.assertTrue(scan["clean"])
            self.assertEqual(
                scan["trusted_worker_filesystem"]["schema"],
                "autofv-trusted-worker-volume-scan/v1",
            )
            for args, input_bytes in observed:
                worker_bytes = repr(args).encode() + (input_bytes or b"")
                for marker in binding.secret_markers:
                    self.assertNotIn(marker, worker_bytes)

    def test_trusted_volume_scan_covers_ignored_logs_evidence_and_lanes(self) -> None:
        secret = b"provider-canary-secret"
        cases = (
            ("work/project/.ignored/provider.txt", secret),
            ("logs/provider.log", secret),
            ("evidence/provider.json", secret),
            ("lanes/scout/provider.json", secret),
            ("logs/provider-canary-secret", None),
        )
        for hostile_path, contents in cases:
            with self.subTest(path=hostile_path), tempfile.TemporaryDirectory() as temporary:
                run, _request = self._configured(Path(temporary))
                root_name, relative = hostile_path.split("/", 1)
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    for name in (
                        "work",
                        "accepted",
                        "autofv-control",
                        "logs",
                        "evidence",
                        "lanes",
                    ):
                        directory = tarfile.TarInfo(name)
                        directory.type = tarfile.DIRTYPE
                        archive.addfile(directory)
                    entry = tarfile.TarInfo(hostile_path)
                    if contents is None:
                        entry.type = tarfile.DIRTYPE
                        archive.addfile(entry)
                    else:
                        entry.size = len(contents)
                        archive.addfile(entry, io.BytesIO(contents))
                roots = []
                for name, surface in worker_artifacts._VOLUME_ROOTS:
                    entries = []
                    if name == root_name:
                        value = (
                            [relative, "directory"]
                            if contents is None
                            else [
                                relative,
                                len(contents),
                                hashlib.sha256(contents).hexdigest(),
                            ]
                        )
                        entries.append(json.dumps(value, ensure_ascii=True).encode())
                    manifest = hashlib.sha256()
                    for encoded in sorted(entries):
                        manifest.update(encoded + b"\n")
                    roots.append(
                        {
                            "root": f"/volume/{name}",
                            "surface": surface,
                            "files": int(bool(entries) and contents is not None),
                            "bytes": len(contents) if contents is not None and entries else 0,
                            "manifest_sha256": manifest.hexdigest(),
                        }
                    )
                worker_scan = {
                    "schema": "autofv-worker-filesystem-scan/v1",
                    "roots": roots,
                    "hit_surfaces": [],
                    "clean": True,
                    "scan_sha256": "0" * 64,
                }
                observed: list[tuple[tuple[object, ...], bytes | None]] = []

                def docker(*args, input_bytes=None, **_kwargs):
                    observed.append((args, input_bytes))
                    return subprocess.CompletedProcess(
                        args, 0, stream.getvalue(), b""
                    )

                with (
                    mock.patch.object(
                        worker_artifacts,
                        "_worker_environment_artifacts",
                        return_value={},
                    ),
                    mock.patch.object(
                        worker_artifacts,
                        "_scan_worker_volume",
                        return_value=worker_scan,
                    ),
                    mock.patch.object(worker_artifacts, "_docker", side_effect=docker),
                ):
                    with self.assertRaisesRegex(worker.WorkerError, "forbidden material"):
                        worker_artifacts.scan_retained_state(run, {})
                for args, input_bytes in observed:
                    worker_bytes = repr(args).encode() + (input_bytes or b"")
                    self.assertNotIn(secret, worker_bytes)

    def test_export_scan_attestation_revalidates_after_secret_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, _request = self._configured(root)
            run.update(
                {
                    "image_digest": LOCK["image"]["image_digest"],
                    "control_bundle_sha256": LOCK["controller_delivery"]["bundle_sha256"],
                    "native_decide_policy_sha256": LOCK["native_decide_policy_sha256"],
                    "worker_inventory_sha256": "3" * 64,
                }
            )
            empty_tar = _empty_tar()
            accepted_commit = "4" * 40
            artifacts = {
                "accepted/tree.tar": empty_tar,
                "accepted/repository.bundle": b"bundle",
                "accepted/commit.txt": (accepted_commit + "\n").encode(),
                "working/changes.patch": b"",
                "working/untracked.tar": empty_tar,
            }
            run["accepted"] = {
                "accepted_commit": accepted_commit,
                "accepted_tree_sha256": hashlib.sha256(empty_tar).hexdigest(),
            }
            markers = (
                *worker_artifacts._retained_markers(run),
                *provider_config.secret_markers(run),
            )
            export_scan = worker_artifacts.scan_artifacts(artifacts, markers)
            scan_body = {
                "schema": "autofv-retained-state-scan/v1",
                "run_id": run["run_id"],
                "scanned_surfaces": list(worker_artifacts.SCANNED_SURFACES),
                "marker_count": len(worker_artifacts._forbidden_markers(markers)),
                "environment_sha256": {},
                "worker_filesystem": {"hit_surfaces": []},
                "controller_state_sha256": "5" * 64,
                "host_artifact_sha256": {},
                "export": export_scan,
                "clean": True,
            }
            scan = {**scan_body, "scan_sha256": _sha(scan_body)}
            with mock.patch.object(
                worker_artifacts, "_export_artifacts", return_value=artifacts
            ), mock.patch.object(
                worker_artifacts, "scan_retained_state", return_value=scan
            ):
                receipt = worker_artifacts.export_run(run)

            self.assertIn("provider_scan_receipt_sha256", receipt)
            provider_service.release(run)
            run["worker_disposed"] = True
            self.assertEqual(worker_artifacts.export_run(run), receipt)

    def test_preflight_rejects_authenticated_identity_and_billing_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, request = self._configured(root)
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')),
            ):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            path = root / "evidence/provider-preflight.json"
            valid = worker_proxy.validate_provider_preflight(path, run=run)
            self.assertEqual(valid["provider_binding"], run["provider_binding"])

            mutations = {
                "signature": lambda value: value["receipt"]["auth"].update(
                    {"signature": "A" * 88}
                ),
                "endpoint": lambda value: value["receipt"]["provider"].update(
                    {"endpoint_sha256": "0" * 64}
                ),
                "billing": lambda value: value["receipt"]["provider"]["billing"].update(
                    {"basis": "calculated_from_pinned_pricing"}
                ),
                "secret": lambda value: value["provider_binding"].update(
                    {"api_key": "must-not-be-retained"}
                ),
            }
            for label, mutate in mutations.items():
                hostile = copy.deepcopy(valid)
                mutate(hostile)
                body = {
                    key: item
                    for key, item in hostile.items()
                    if key != "preflight_sha256"
                }
                hostile["preflight_sha256"] = _sha(body)
                hostile_path = root / f"hostile-{label}.json"
                hostile_path.write_bytes(
                    experiment.canonical_json_bytes(hostile) + b"\n"
                )
                with self.subTest(label=label), self.assertRaises(worker.WorkerError):
                    worker_proxy.validate_provider_preflight(hostile_path, run=run)


if __name__ == "__main__":
    unittest.main()
