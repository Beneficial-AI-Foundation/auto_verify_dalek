from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import (
    experiment,
    model,
    provider_config,
    provider_service,
    provider_transport,
    worker,
    worker_artifacts,
    worker_proxy,
)
from tests.test_provider_service import _install_trusted_authorization_fixture


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "docker" / "autofv" / "toolchain-lock.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "model-proxy" / "diamond-responses.json"
RUN_ID = "fixture-diamond-run-0001"
MODEL_ID = "fixture-model-v1"
RUN_TOKEN = "provider-test-run-token"
_CONFIGURED_RUNS: list[dict[str, Any]] = []


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(experiment.canonical_json_bytes(value)).hexdigest()


def _strict_json(raw: bytes) -> Any:
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)


def _provider_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "read_allowed",
            "description": "Read one allowlisted file.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        }
    ]


def _openai_tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }
        for tool in _provider_tools()
    ]


def _provider_env(
    root: Path,
    *,
    overrides: dict[str, str] | None = None,
    extra_lines: tuple[str, ...] = (),
    mode: int = 0o600,
) -> Path:
    private_raw = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    values = {
        "AUTOFV_PROVIDER_ENDPOINT": "https://provider.invalid/v1/chat/completions",
        "AUTOFV_PROVIDER_MODEL": MODEL_ID,
        "AUTOFV_PROVIDER_API_KEY": "provider-canary-secret",
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.000000",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "1.000000",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "4.000000",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(private_raw).decode(),
    }
    values.update(overrides or {})
    path = root / "providers.env"
    lines = [*(f"{name}={value}" for name, value in values.items()), *extra_lines]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _provider_run(root: Path, lock: dict[str, Any], base_commit: str) -> dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "volume": "provider-test-volume",
        "base_commit": base_commit,
        "lock": copy.deepcopy(lock),
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": lock["controller_delivery"]["bundle_sha256"],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "worker_inventory_sha256": "1" * 64,
        "fixed_proxy_sha256": _canonical_sha256(lock["fixed_proxy"]),
        "events": [],
    }


def _provider_reply() -> dict[str, Any]:
    return {
        "id": "response-local-001",
        "model": MODEL_ID,
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call-local-001",
                            "type": "function",
                            "function": {
                                "name": "read_allowed",
                                "arguments": '{"path":"Diamond/Left.lean"}',
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 40,
            "total_tokens": 160,
            "prompt_tokens_details": {"cached_tokens": 20},
        },
    }


class _ProviderReply:
    status = 200

    def __init__(self, value: Any):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return experiment.canonical_json_bytes(self.value)


class _InertServer:
    server_port = 19080

    def serve_forever(self):
        return None

    def shutdown(self):
        return None

    def server_close(self):
        return None


def _configure_provider(run: dict[str, Any], **options: Any) -> dict[str, Any]:
    with mock.patch.dict(
        os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
    ), mock.patch("autofv.provider_service._serve", return_value=_InertServer()):
        binding = worker_proxy.configure_provider(run, **options)
    _CONFIGURED_RUNS.append(run)
    return binding


def _configured_provider(
    root: Path, lock: dict[str, Any], base_commit: str
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    run = _provider_run(root, lock, base_commit)
    _configure_provider(
        run, env_path=_provider_env(root), tool_schemas=_provider_tools()
    )
    _install_trusted_authorization_fixture(run, root)
    messages = _provider_messages()
    request = copy.deepcopy(_strict_json(FIXTURE_PATH.read_bytes())["entries"][0]["request"])
    request["input_hashes"] = sorted(
        {*request["input_hashes"], worker_proxy.provider_messages_sha256(messages)}
    )
    return run, request, messages


def _provider_messages() -> list[dict[str, Any]]:
    return [
        {
            "role": "system",
            "content": "Act only as scout. A result is a candidate, not acceptance.",
        },
        {
            "role": "user",
            "content": "Untrusted declaration and contract context for Diamond.left_spec",
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-prior-001",
                    "type": "function",
                    "function": {
                        "name": "read_allowed",
                        "arguments": '{"path":"Diamond/Left.lean"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call-prior-001",
            "content": "bounded tool result: declaration source",
        },
    ]


class ProviderTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _strict_json(FIXTURE_PATH.read_bytes())
        self.lock = _strict_json(LOCK_PATH.read_bytes())

    def tearDown(self) -> None:
        while _CONFIGURED_RUNS:
            provider_service.release(_CONFIGURED_RUNS.pop())

    @property
    def base_commit(self) -> str:
        return self.fixture["git"]["base_commit"]

    def test_startup_bound_provider_translates_one_tool_call_and_signs_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, request, messages = _configured_provider(root, self.lock, self.base_commit)
            worker_proxy.stage_provider_messages(run, request, messages)
            observed = {}

            def open_upstream(request, *, timeout, deadline_monotonic_ns=None):
                observed["request"] = request
                observed["timeout"] = timeout
                observed["deadline_monotonic_ns"] = deadline_monotonic_ns
                return _ProviderReply(_provider_reply())

            def sealed_client(*_args, input_bytes, check):
                self.assertFalse(check)
                self.assertNotIn(b"provider-canary-secret", input_bytes)
                dispatched = _strict_json(input_bytes)
                response, receipt = provider_service.dispatch(
                    run, dispatched, run_token=RUN_TOKEN
                )
                return subprocess.CompletedProcess(
                    (),
                    0,
                    stdout=experiment.canonical_json_bytes(
                        {"response": response, "receipt": receipt}
                    ),
                    stderr=b"",
                )

            def sealed_relay(candidate):
                worker_proxy._bind_proxy_client_identity(
                    candidate, os.environ["AUTOFV_RUN_TOKEN"]
                )
                worker_proxy._record_proxy_policy(candidate)
                return "sealed-network", "10.0.0.8"

            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}
            ), mock.patch(
                "autofv.provider_transport._open_upstream", side_effect=open_upstream
            ), mock.patch(
                "autofv.worker_proxy._ensure_proxy_relay",
                side_effect=sealed_relay,
            ) as relay, mock.patch(
                "autofv.worker_proxy._runtime_argv",
                return_value=("sealed-runsc-client",),
            ), mock.patch(
                "autofv.worker_proxy._docker", side_effect=sealed_client
            ) as client:
                response, receipt = worker_proxy.proxy_round(run, request)

            relay.assert_called_once_with(run)
            client.assert_called_once()

            self.assertEqual(
                response["payload"],
                {
                    "schema": "autofv-lane-tool-call/v1",
                    "name": "read_allowed",
                    "arguments": {"path": "Diamond/Left.lean"},
                },
            )
            self.assertEqual(receipt["provider"]["response_id"], "response-local-001")
            self.assertEqual(receipt["provider"]["usage"]["cached_input_tokens"], 20)
            self.assertEqual(
                receipt["cost"],
                {
                    "amount": "0.000380",
                    "currency": "USD",
                    "basis": "calculated_from_pinned_pricing",
                },
            )
            self.assertEqual(run["cost_classification"], "provider_authenticated")
            policy = run["proxy_policy_receipt"]
            schema = "autofv-provider-proxy-receipt/v1"
            self.assertEqual(policy["provider_receipt_schema"], schema)
            self.assertEqual(policy["receipt_schema_sha256"], _canonical_sha256(schema))
            self.assertNotIn("provider-canary-secret", repr(run))
            self.assertGreater(observed["timeout"], 0)
            self.assertLessEqual(observed["timeout"], 30)
            self.assertEqual(
                observed["request"].get_header("Authorization"),
                "Bearer provider-canary-secret",
            )
            upstream = _strict_json(observed["request"].data)
            self.assertEqual(upstream["messages"], messages)
            self.assertEqual(upstream["model"], MODEL_ID)
            self.assertEqual(upstream["tools"], _openai_tools())
            self.assertEqual(upstream["max_tokens"], 4096)
            self.assertNotIn("provider.invalid", repr(upstream["messages"]))
            self.assertNotIn("provider-canary-secret", repr(upstream))

            state = {
                "run": run,
                "config": {"model": MODEL_ID},
                "receipts": [],
                "pending_model_exchanges": {},
            }
            _, accepted, amount = model._validate_model_exchange(
                state, request, response, receipt, enforce_sequence=True
            )
            self.assertEqual(accepted, receipt)
            self.assertEqual(amount, Decimal("0.000380"))
            retained = b"".join(
                path.read_bytes()
                for path in (root / "evidence").rglob("*")
                if path.is_file()
            )
            for canary in (
                b"provider-canary-secret",
                b"Untrusted declaration and contract context",
                b"bounded tool result",
            ):
                self.assertNotIn(canary, retained)
            worker_proxy.stage_provider_messages(run, request, messages)
            worker_proxy.discard_provider_messages(run, request["request_id"])

    def test_provider_rejects_authority_drift_before_any_upstream_call(self) -> None:
        mutations = (
            lambda request, _run: request.update({"authorization": "caller-selected"}),
            lambda request, _run: request.update({"model_id": "caller-model"}),
            lambda _request, run: run["lock"]["fixed_proxy"].update({"method": "GET"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as tmp:
                run, request, _ = _configured_provider(Path(tmp), self.lock, self.base_commit)
                mutate(request, run)
                opener = mock.Mock(side_effect=AssertionError("upstream called"))
                with mock.patch(
                    "autofv.provider_transport._open_upstream", opener
                ), self.assertRaises(provider_transport.ProviderError):
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)
                opener.assert_not_called()

    def test_provider_fails_closed_on_response_drift_timeout_and_duplicates(self) -> None:
        malformed = []
        wrong_model = _provider_reply()
        wrong_model["model"] = "provider-model-drift"
        malformed.append(wrong_model)
        wrong_tool = _provider_reply()
        wrong_tool["choices"][0]["message"]["tool_calls"] = []
        malformed.append(wrong_tool)
        wrong_usage = _provider_reply()
        wrong_usage["usage"]["total_tokens"] = 999
        malformed.append(wrong_usage)
        unreserved_usage = _provider_reply()
        unreserved_usage["usage"].update(
            {"prompt_tokens": 1_000_000, "total_tokens": 1_000_040}
        )
        malformed.append(unreserved_usage)
        for provider_reply in malformed:
            with self.subTest(reply=provider_reply), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                run, request, messages = _configured_provider(root, self.lock, self.base_commit)
                worker_proxy.stage_provider_messages(run, request, messages)
                with mock.patch(
                    "autofv.provider_transport._open_upstream",
                    return_value=_ProviderReply(provider_reply),
                ), self.assertRaisesRegex(
                    provider_transport.ProviderError, "provider"
                ) as error:
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)
                self.assertEqual(error.exception.classification, "malformed_response")
                worker_proxy.stage_provider_messages(run, request, messages)
                worker_proxy.discard_provider_messages(run, request["request_id"])
                retained = b"".join(
                    path.read_bytes()
                    for path in (root / "evidence").rglob("*")
                    if path.is_file()
                )
                self.assertNotIn(b"provider-canary-secret", retained)
                self.assertNotIn(b"Untrusted declaration and contract context", retained)

        with tempfile.TemporaryDirectory() as tmp:
            run, request, messages = _configured_provider(Path(tmp), self.lock, self.base_commit)
            worker_proxy.stage_provider_messages(run, request, messages)
            with mock.patch(
                "autofv.provider_transport._open_upstream", side_effect=TimeoutError
            ), self.assertRaisesRegex(provider_transport.ProviderError, "timeout"):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            worker_proxy.stage_provider_messages(run, request, messages)
            worker_proxy.discard_provider_messages(run, request["request_id"])

        with tempfile.TemporaryDirectory() as tmp:
            run, request, messages = _configured_provider(Path(tmp), self.lock, self.base_commit)
            opener = mock.Mock(return_value=_ProviderReply(_provider_reply()))
            worker_proxy.stage_provider_messages(run, request, messages)
            with mock.patch("autofv.provider_transport._open_upstream", opener):
                first = provider_service.dispatch(run, request, run_token=RUN_TOKEN)
                worker_proxy.stage_provider_messages(run, request, messages)
                replay = provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            self.assertEqual(first, replay)
            self.assertEqual(opener.call_count, 1)

    def test_provider_normalizes_bounded_chat_metadata_and_scans_encoded_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_raw = bytes(range(32))
            env_path = _provider_env(
                root,
                overrides={
                    "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(
                        private_raw
                    ).decode()
                },
            )
            run = _provider_run(root, self.lock, self.base_commit)
            _configure_provider(
                run, env_path=env_path, tool_schemas=_provider_tools()
            )
            _install_trusted_authorization_fixture(run, root)
            messages = _provider_messages()
            request = copy.deepcopy(self.fixture["entries"][0]["request"])
            request["input_hashes"] = sorted(
                {*request["input_hashes"], worker_proxy.provider_messages_sha256(messages)}
            )
            worker_proxy.stage_provider_messages(run, request, messages)
            realistic = _provider_reply()
            realistic.update(
                {
                    "object": "chat.completion",
                    "created": 1_700_000_000,
                    "system_fingerprint": None,
                    "service_tier": "default",
                    "provider": "local-test",
                }
            )
            realistic["choices"][0].update({"index": 0, "logprobs": None})
            realistic["choices"][0]["message"].update(
                {
                    "content": None,
                    "refusal": None,
                    "annotations": [],
                    "reasoning_details": [],
                }
            )
            realistic["usage"].update(
                {
                    "completion_tokens_details": {"reasoning_tokens": 4},
                    "cost": 0.00038,
                    "is_byok": True,
                }
            )
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_ProviderReply(realistic),
            ):
                response, _ = provider_service.dispatch(
                    run, request, run_token=RUN_TOKEN
                )
            self.assertEqual(response["kind"], "tool_call")

            hostile_payloads = (
                {"nested": base64.b64encode(b'"provider-canary-secret"').decode()},
                {"nested": json.dumps({"key": private_raw.hex()})},
            )
            for index, payload in enumerate(hostile_payloads, 2):
                hostile = _provider_reply()
                hostile["metadata"] = payload
                hostile_request = copy.deepcopy(request)
                hostile_request["sequence"] = index
                hostile_request["request_id"] = f"provider-hostile-{index}"
                worker_proxy.stage_provider_messages(run, hostile_request, messages)
                with mock.patch(
                    "autofv.provider_transport._open_upstream",
                    return_value=_ProviderReply(hostile),
                ), self.assertRaisesRegex(
                    provider_transport.ProviderError, "credential material"
                ):
                    provider_service.dispatch(
                        run, hostile_request, run_token=RUN_TOKEN
                    )
            deep: dict[str, Any] = {}
            cursor = deep
            for _ in range(14):
                cursor["nested"] = {}
                cursor = cursor["nested"]
            malformed = (_provider_reply(), _provider_reply())
            malformed[0]["created"] = 10**20
            malformed[1]["metadata"] = deep
            for index, value in enumerate(malformed, 4):
                malformed_request = copy.deepcopy(request)
                malformed_request.update(
                    {"sequence": index, "request_id": f"provider-malformed-{index}"}
                )
                worker_proxy.stage_provider_messages(run, malformed_request, messages)
                with mock.patch(
                    "autofv.provider_transport._open_upstream",
                    return_value=_ProviderReply(value),
                ), self.assertRaises(provider_transport.ProviderError) as error:
                    provider_service.dispatch(
                        run, malformed_request, run_token=RUN_TOKEN
                    )
                self.assertEqual(error.exception.classification, "malformed_response")

            error_request = copy.deepcopy(request)
            error_request.update({"sequence": 6, "request_id": "provider-error-secret-006"})
            worker_proxy.stage_provider_messages(run, error_request, messages)
            error_reply = _ProviderReply({"encoded": hostile_payloads[0]})
            error_reply.status = 500
            with mock.patch(
                "autofv.provider_transport._open_upstream", return_value=error_reply
            ), self.assertRaisesRegex(
                provider_transport.ProviderError, "credential material"
            ):
                provider_service.dispatch(run, error_request, run_token=RUN_TOKEN)
            self.assertNotIn("provider-canary-secret", repr(run))

    def test_live_provider_requires_hash_bound_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run, request, messages = _configured_provider(Path(tmp), self.lock, self.base_commit)
            opener = mock.Mock(side_effect=AssertionError("upstream called"))
            with mock.patch(
                "autofv.provider_transport._open_upstream", opener
            ), self.assertRaisesRegex(provider_transport.ProviderError, "staged"):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            opener.assert_not_called()
            unbound = copy.deepcopy(request)
            unbound["input_hashes"].remove(worker_proxy.provider_messages_sha256(messages))
            with self.assertRaisesRegex(worker.WorkerError, "not bound"):
                worker_proxy.stage_provider_messages(run, unbound, messages)
            worker_proxy.stage_provider_messages(run, request, messages)
            changed = copy.deepcopy(request)
            changed["batch_id"] = "caller-mutated-after-staging"
            with self.assertRaisesRegex(
                provider_transport.ProviderError, "staged request identity"
            ):
                provider_service.dispatch(run, changed, run_token=RUN_TOKEN)
            worker_proxy.discard_provider_messages(run, request["request_id"])

    def test_model_seam_binds_ephemeral_messages_to_replay_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run, original, messages = _configured_provider(Path(tmp), self.lock, self.base_commit)
            state = {
                "run": run,
                "config": {
                    "model": MODEL_ID,
                    "max_cost_usd": Decimal("1.000000"),
                    "max_wall_seconds": 5,
                },
                "run_round": model.agentproc.run_round,
                "receipts": [],
                "cost": Decimal("0.000000"),
                "pending_model_exchanges": {},
                "model_exchanges": {},
                "checkpoint_enabled": False,
            }
            timeouts = []

            def open_provider(_request, *, timeout, deadline_monotonic_ns=None):
                timeouts.append(timeout)
                self.assertIsInstance(deadline_monotonic_ns, int)
                return _ProviderReply(_provider_reply())

            opener = mock.Mock(side_effect=open_provider)
            input_hashes = self.fixture["entries"][0]["request"]["input_hashes"]
            with mock.patch(
                "autofv.provider_transport._open_upstream", opener
            ), mock.patch(
                "autofv.worker.proxy_round",
                side_effect=lambda candidate_run, candidate_request: provider_service.dispatch(
                    candidate_run, candidate_request, run_token=RUN_TOKEN
                ),
            ):
                first = model._model_request(
                    state,
                    request_id=original["request_id"],
                    role=original["role"],
                    input_hashes=input_hashes,
                    messages=messages,
                )
                replay = model._model_request(
                    state,
                    request_id=original["request_id"],
                    role=original["role"],
                    input_hashes=input_hashes,
                    messages=messages,
                )
                changed = copy.deepcopy(messages)
                changed[1]["content"] += " changed"
                with self.assertRaisesRegex(
                    experiment.ContractError, "resumed model request changed"
                ):
                    model._model_request(
                        state,
                        request_id=original["request_id"],
                        role=original["role"],
                        input_hashes=input_hashes,
                        messages=changed,
                    )
            self.assertEqual(first, replay)
            self.assertEqual(opener.call_count, 1)
            self.assertEqual(len(timeouts), 1)
            self.assertGreater(timeouts[0], 0)
            self.assertLessEqual(timeouts[0], 5)
            stored = state["model_exchanges"][original["request_id"]]["request"]
            self.assertIn(worker_proxy.provider_messages_sha256(messages), stored["input_hashes"])
            self.assertNotIn(messages[1]["content"], repr(run))
            self.assertNotIn("messages", repr(state["model_exchanges"]))

    def test_provider_reserves_concurrent_worst_case_cost_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run, original, messages = _configured_provider(
                Path(tmp), self.lock, self.base_commit
            )
            reservation = worker_proxy.provider_reservation_usd(
                run, original, messages
            )
            state = {
                "run": run,
                "config": {
                    "model": MODEL_ID,
                    "max_cost_usd": reservation * Decimal("1.5"),
                    "max_wall_seconds": 300,
                },
                "run_round": model.agentproc.run_round,
                "receipts": [],
                "cost": Decimal("0.000000"),
                "pending_model_exchanges": {},
                "model_exchanges": {},
                "checkpoint_enabled": False,
            }
            requests = [
                {
                    "request_id": f"provider-parallel-{index}",
                    "role": original["role"],
                    "input_hashes": original["input_hashes"],
                    "messages": messages,
                }
                for index in (1, 2)
            ]
            with mock.patch(
                "autofv.worker.proxy_round",
                side_effect=AssertionError("paid dispatch started"),
            ) as dispatch, self.assertRaises(experiment.BudgetExhausted):
                model._parallel_model_requests(state, requests)
            dispatch.assert_not_called()
            self.assertEqual(state["pending_model_exchanges"], {})
            run.pop("provider_binding")
            with mock.patch(
                "autofv.worker.proxy_round",
                side_effect=AssertionError("provider resume fell through"),
            ) as dispatch, self.assertRaisesRegex(
                experiment.ContractError, "provider binding"
            ):
                model._model_request(
                    state,
                    request_id=original["request_id"],
                    role=original["role"],
                    input_hashes=self.fixture["entries"][0]["request"]["input_hashes"],
                    messages=messages,
                )
            dispatch.assert_not_called()

    def test_cancelled_completed_provider_call_reconciles_without_repayment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run, original, messages = _configured_provider(
                Path(tmp), self.lock, self.base_commit
            )
            state = {
                "run": run,
                "config": {
                    "model": MODEL_ID,
                    "max_cost_usd": Decimal("1.000000"),
                    "max_wall_seconds": 30,
                },
                "run_round": model.agentproc.run_round,
                "receipts": [],
                "cost": Decimal("0.000000"),
                "pending_model_exchanges": {},
                "model_exchanges": {},
                "checkpoint_enabled": False,
            }
            upstream = mock.Mock(return_value=_ProviderReply(_provider_reply()))
            cancelled = True

            def dispatch(candidate_run, candidate_request):
                nonlocal cancelled
                result = provider_service.dispatch(
                    candidate_run, candidate_request, run_token=RUN_TOKEN
                )
                if cancelled:
                    cancelled = False
                    raise asyncio.CancelledError
                return result

            arguments = {
                "request_id": original["request_id"],
                "role": original["role"],
                "input_hashes": self.fixture["entries"][0]["request"]["input_hashes"],
                "messages": messages,
            }
            with mock.patch(
                "autofv.provider_transport._open_upstream", upstream
            ), mock.patch("autofv.worker.proxy_round", side_effect=dispatch):
                with self.assertRaises(asyncio.CancelledError):
                    model._model_request(state, **arguments)
                pending = state["pending_model_exchanges"][original["request_id"]]
                self.assertEqual(pending["request"], original)
                self.assertEqual(pending["dispatch_state"], "ambiguous")
                self.assertGreater(Decimal(pending["reservation_usd"]), 0)
                model._model_request(state, **arguments)
            self.assertEqual(upstream.call_count, 1)
            self.assertEqual(len(state["receipts"]), 1)
