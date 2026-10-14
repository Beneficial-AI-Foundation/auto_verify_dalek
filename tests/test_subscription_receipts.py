"""Synthetic controller observations: no credentials, network, or model calls."""
from __future__ import annotations

import copy
import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import provider_config, runtime_profile, subscription_journal, subscription_receipts
from autofv.contracts import canonical_json_bytes


def sha(value):
    return provider_config.canonical_sha256(value)


def fixture(root: Path, *, invocations: int = 8, run_id: str = "synthetic-pi-run"):
    key = Ed25519PrivateKey.generate()
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    runtime = {"schema": "autofv-pi-runtime-identity/v1", "protocol_version": 1,
               "node_sha256": "1" * 64, "bridge_sha256": "2" * 64,
               "package_lock_sha256": "3" * 64, "packages": runtime_profile.PI_PACKAGES}
    profile = runtime_profile.profile()
    endpoint = "https://api.openai.com/v1/responses"
    tools = [{"type": "function", "function": {"name": "read_allowed", "description": "Read",
             "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                            "required": ["path"], "additionalProperties": False}}}]
    now = time.time_ns() // 1_000_000
    body = {
        "schema": "autofv-provider-binding/v3", "run_id": run_id,
        "proxy_id": "fixture-proxy", "route_id": "fixture-route",
        "fixed_proxy_sha256": "4" * 64, "client_identity_sha256": "5" * 64,
        "endpoint": endpoint, "endpoint_sha256": hashlib.sha256(endpoint.encode()).hexdigest(),
        "model_id": runtime_profile.PI_MODEL, "parameters": profile["parameters"],
        "tool_schema_sha256": sha(tools), "capability_sha256": sha({"profile": profile, "runtime": runtime}),
        "receipt_authentication": {"algorithm": "Ed25519", "key_id": "synthetic-fixture-key",
            "public_key_der_sha256": hashlib.sha256(der).hexdigest(),
            "public_key_pem": key.public_key().public_bytes(serialization.Encoding.PEM,
                 serialization.PublicFormat.SubjectPublicKeyInfo).decode()},
        "role_profile": profile, "role_profile_sha256": sha(profile),
        "source_packet_sha256": "6" * 64, "runtime_identity": runtime,
        "runtime_identity_sha256": sha(runtime),
        "grant": {"schema": "autofv-pi-run-grant/v1", "config_sha256": "a"*64, "approval_id": "synthetic-no-live-authority",
                  "account_binding_sha256": "7" * 64, "original_started_epoch_ms": now - 1000,
                  "original_deadline_epoch_ms": now + 60000, "max_invocations": invocations,
                  "acknowledgements": {"no_server_output_cap": True, "unknown_subscription_cost": True,
                                        "best_effort_remote_abort": True},
                  "qualification": {"isolation_sha256": "8" * 64,
                                    "callback_cancellation_sha256": "9" * 64,
                                    "entitlement_sha256": "a" * 64}},
    }
    public = {**body, "binding_sha256": sha(body)}
    binding = provider_config.ProviderBinding(public=public, endpoint=endpoint, api_key=bytearray(),
        client_token=bytearray(), model_id=runtime_profile.PI_MODEL, route_path="/fixture", pricing={},
        tools=tools, signing_key=key, secret_markers=())
    run = {"run_id": public["run_id"], "run_root": str(root), "evidence_dir": str(root / "evidence"),
           "provider_binding": public, "provider_binding_sha256": public["binding_sha256"]}
    return run, binding


def request(binding, *, sequence=1, role="specifier", conversation="0000000000000001" + "0" * 48, messages=None):
    messages = messages or [{"role": "system", "content": "Synthetic role."},
                            {"role": "user", "content": "Read a synthetic source."}]
    digest = sha(messages)
    value = {"schema": "autofv-model-request/v2", "run_id": binding.public["run_id"],
             "sequence": sequence, "batch_id": None, "request_id": f"lane-{conversation[:16]}-{sequence:03d}",
             "role": role, "model_id": binding.model_id, "conversation_id": conversation,
             "history_sha256": digest, "prompt_sha256": "b" * 64,
             "input_hashes": sorted({digest, binding.public["role_profile_sha256"],
                                     binding.public["source_packet_sha256"],
                                     binding.public["runtime_identity_sha256"]})}
    return value, messages


def terminal(binding, req):
    tool_call = {"name": "read_allowed", "arguments": {"path": "Synthetic/Main.lean"}}
    payload = {"schema": "autofv-lane-tool-call/v1", **tool_call}
    response = {key: req[key] for key in ("run_id", "sequence", "batch_id", "request_id", "role", "model_id")}
    response.update(schema="autofv-model-response/v1", kind="tool_call", assigned_path=None,
                    base_commit="c" * 40, statement_fingerprints=[], payload=payload, payload_sha256=sha(payload))
    continuation = {
        "schema": "autofv-pi-continuation/v1", "request": {
            **{key: req[key] for key in ("run_id", "conversation_id", "request_id", "sequence", "role", "model_id", "history_sha256")},
            "profile_sha256": binding.public["role_profile_sha256"]},
        "canonical_tool_id": req["request_id"] + "-tool", "tool_call": tool_call,
        "native": {"tool_call_id": "call_native_1", "response_id": "resp_synthetic_1",
                   "content": [{"type": "thinking", "thinkingSignature": canonical_json_bytes({"id": "rs_fixture", "type": "reasoning", "summary": [], "encrypted_content": "opaque-native-fixture"}).decode()},
                               {"type": "toolCall"}]} }
    raw = {"input": 10, "output": 20, "cacheRead": 30, "cacheWrite": 40, "totalTokens": 100, "reasoning": 12}
    return response, raw, continuation, {"provider_response_id": "resp_synthetic_1", "termination": "toolUse"}


def accepted_state(req, response, receipt):
    return {"receipts": [receipt], "model_exchanges": {req["request_id"]: {
                "request": req, "response": response, "receipt": receipt, "call_kind": "explicit"}},
            "pending_model_exchanges": {}}


class SubscriptionUsageTests(unittest.TestCase):
    def test_disjoint_input_and_reasoning_subset(self):
        self.assertEqual(subscription_receipts.normalize_usage({"input": 10, "output": 20, "cacheRead": 30,
            "cacheWrite": 40, "totalTokens": 100, "reasoning": 12}), {
                "input_tokens": 80, "output_tokens": 20, "cached_input_tokens": 30,
                "cache_write_tokens": 40, "reasoning_tokens": 12, "total_tokens": 100})

    def test_unreported_reasoning_is_unknown(self):
        self.assertIsNone(subscription_receipts.normalize_usage({"input": 0, "output": 0,
            "cacheRead": 0, "cacheWrite": 0, "totalTokens": 0})["reasoning_tokens"])

    def test_missing_failed_usage_not_zero(self):
        for usage in (None, {}, {"input": 0}):
            with self.subTest(usage=usage), self.assertRaises(provider_config.ProviderConfigError):
                subscription_receipts.normalize_usage(usage)

    def test_catalog_price_or_invalid_categories_rejected(self):
        base = {"input": 10, "output": 20, "cacheRead": 30, "cacheWrite": 40, "totalTokens": 100}
        for key, value in (("cost", {"total": 0}), ("reasoning", 21), ("reasoning", None),
                           ("totalTokens", 90), ("input", True), ("output", -1), ("cacheRead", 1.5)):
            with self.subTest(key=key, value=value), self.assertRaises(provider_config.ProviderConfigError):
                subscription_receipts.normalize_usage({**base, key: value})

    def test_signed_attestation_is_unknown_cost_and_binds_every_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, binding = fixture(Path(temporary))
            req, _ = request(binding)
            response, raw, continuation, metadata = terminal(binding, req)
            receipt = subscription_receipts.build_receipt(binding, req, response, raw, continuation, **metadata)
            self.assertIsNone(receipt["cost"]["amount"])
            self.assertTrue(receipt["dispatch_accounting_complete"])
            self.assertFalse(receipt["monetary_cost_known"])
            self.assertIsNone(receipt["provider"]["observed_effort"])
            for key, value in (("role", "prover"), ("conversation_id", "different"),
                               ("history_sha256", "f" * 64), ("continuation_sha256", "e" * 64),
                               ("raw_usage", {**raw, "reasoning": 13}), ("cost", {"amount": "0.000000", "currency": "USD", "basis": "subscription_cost_unknown"})):
                changed = {**receipt, key: value}
                changed["receipt_sha256"] = sha({k: v for k, v in changed.items() if k != "receipt_sha256"})
                with self.subTest(key=key), self.assertRaises(provider_config.ProviderConfigError):
                    subscription_receipts.validate_receipt(changed, binding=binding.public,
                        run_id=req["run_id"], sequence=req["sequence"], request_id=req["request_id"],
                        model_id=req["model_id"], request_sha256=sha(req), response_sha256=sha(response),
                        seen_receipt_sha256=set(), request=req, continuation=continuation)

    def test_duplicate_receipt_and_response_id_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, binding = fixture(Path(temporary))
            req, _ = request(binding)
            response, raw, continuation, metadata = terminal(binding, req)
            receipt = subscription_receipts.build_receipt(binding, req, response, raw, continuation, **metadata)
            with self.assertRaisesRegex(provider_config.ProviderConfigError, "duplicate"):
                subscription_receipts.validate_receipt(receipt, binding=binding.public,
                    run_id=req["run_id"], sequence=req["sequence"], request_id=req["request_id"],
                    model_id=req["model_id"], request_sha256=sha(req), response_sha256=sha(response),
                    seen_receipt_sha256={receipt["receipt_sha256"]})
            with self.assertRaisesRegex(provider_config.ProviderConfigError, "response identity"):
                subscription_receipts.build_receipt(binding, req, response, raw, continuation,
                                                    provider_response_id="different")


if __name__ == "__main__":
    unittest.main()
