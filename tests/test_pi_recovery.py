"""No uncertain resend, renewal, per-role grant, or unauthenticated replay."""
from __future__ import annotations

import copy
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from autofv import provider_config, subscription_journal, subscription_receipts
from autofv.contracts import canonical_json_bytes
from tests.test_subscription_receipts import fixture, request, terminal, accepted_state, sha


class SubscriptionJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run, self.binding = fixture(self.root, invocations=2)
        self.req, self.messages = request(self.binding)
        subscription_journal.initialize(self.run, self.binding)

    def generate(self, admission, continuations):
        self.assertEqual(admission["request_sha256"], sha(self.req))
        self.assertEqual(continuations, [])
        return terminal(self.binding, self.req)

    def dispatch(self, generate=None):
        return subscription_journal.dispatch(self.run, self.binding, self.req, self.messages, generate or self.generate)

    def test_dispatch_durable_before_generation_and_complete_atomic(self):
        def generate(admission, continuations):
            recovery = subscription_journal.validate_recovery_artifacts(self.run, {}, binding=self.binding.public)
            record = recovery["journal"][self.req["request_id"]]
            self.assertEqual(record["status"], "dispatched")
            self.assertIsNone(record["receipt"])
            return self.generate(admission, continuations)
        response, receipt = self.dispatch(generate)
        recovery = subscription_journal.validate_recovery_artifacts(self.run, {}, binding=self.binding.public)
        record = recovery["journal"][self.req["request_id"]]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["response"], response)
        self.assertEqual(record["receipt"], receipt)
        self.assertEqual(sha(record["continuation"]), receipt["continuation_sha256"])

    def test_complete_replay_no_callback_even_after_original_deadline(self):
        first = self.dispatch()
        later = self.binding.public["grant"]["original_deadline_epoch_ms"] * 1_000_000 + 1
        with mock.patch("autofv.subscription_journal.time.time_ns", return_value=later):
            self.assertEqual(first, self.dispatch(mock.Mock(side_effect=AssertionError("resent"))))
        subscription_journal.validate_completed(self.run, self.req, *first)

    def test_restart_replays_completed_with_same_budget(self):
        first = self.dispatch()
        restarted = copy.deepcopy(self.run)
        subscription_journal.initialize(restarted, self.binding)
        self.assertEqual(subscription_journal.dispatch(restarted, self.binding, self.req, self.messages,
            mock.Mock(side_effect=AssertionError("resent"))), first)
        self.assertEqual(len(restarted["subscription_journal"]["records"]), 1)

    def test_any_generation_error_blocks_all_roles_and_restarts(self):
        with self.assertRaises(TimeoutError):
            self.dispatch(mock.Mock(side_effect=TimeoutError("synthetic")))
        restarted = copy.deepcopy(self.run)
        req2, messages = request(self.binding, sequence=2, role="prover", conversation="0000000000000002" + "0" * 48)
        callback = mock.Mock()
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "unresolved"):
            subscription_journal.dispatch(restarted, self.binding, req2, messages, callback)
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "ambiguous"):
            self.dispatch(callback)
        callback.assert_not_called()
        reduced = subscription_receipts.reduce_incomplete_accounting(self.run, {}, binding=self.binding.public)
        self.assertFalse(reduced["dispatch_accounting_complete"])
        self.assertFalse(reduced["monetary_cost_known"])
        self.assertIsNone(reduced["cost"])
        self.assertIsNone(reduced["unresolved_requests"][0]["usage"])
        self.assertEqual(reduced["invocations_used"], 1)

    def test_run_wide_ceiling_across_three_fresh_roles(self):
        self.dispatch()
        req2, messages2 = request(self.binding, sequence=2, role="prover", conversation="0000000000000002" + "0" * 48)
        subscription_journal.dispatch(self.run, self.binding, req2, messages2,
                                     lambda *_: terminal(self.binding, req2))
        req3, messages3 = request(self.binding, sequence=3, role="spec_reviewer", conversation="0000000000000003" + "0" * 48)
        callback = mock.Mock()
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "ceiling"):
            subscription_journal.dispatch(self.run, self.binding, req3, messages3, callback)
        callback.assert_not_called()

    def test_deadline_is_original_and_no_dispatch_when_expired(self):
        later = self.binding.public["grant"]["original_deadline_epoch_ms"] * 1_000_000
        with mock.patch("autofv.subscription_journal.time.time_ns", return_value=later):
            with self.assertRaisesRegex(provider_config.ProviderConfigError, "deadline"):
                self.dispatch(mock.Mock(side_effect=AssertionError("called")))
        self.assertEqual(self.run["subscription_journal"]["records"], [])

    def test_failure_persisting_completed_record_never_resends(self):
        original = subscription_journal._write
        def write(path, value):
            if path.parent.name == "provider-private" and value["records"][-1]["status"] == "completed":
                raise OSError("synthetic disk full")
            original(path, value)
        with mock.patch.object(subscription_journal, "_write", side_effect=write):
            with self.assertRaises(OSError):
                self.dispatch()
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "ambiguous"):
            self.dispatch(mock.Mock(side_effect=AssertionError("resent")))

    def test_failure_before_durable_dispatch_never_calls_generator(self):
        original = subscription_journal._write
        callback = mock.Mock()
        def write(path, value):
            if path.parent.name == "provider-private" and value["records"]:
                raise OSError("synthetic disk failure before dispatch")
            original(path, value)
        with mock.patch.object(subscription_journal, "_write", side_effect=write):
            with self.assertRaises(OSError):
                self.dispatch(callback)
        callback.assert_not_called()
        self.assertEqual(subscription_journal.validate_recovery_artifacts(self.run, {},
            binding=self.binding.public)["journal"], {})
        self.dispatch()

    def test_private_completion_repairs_stale_public_only_with_pinned_authority(self):
        original = subscription_journal._write
        def write(path, value):
            if path.parent.name == "evidence" and value["records"][-1]["status"] == "completed":
                raise OSError("synthetic public publication failure")
            original(path, value)
        with mock.patch.object(subscription_journal, "_write", side_effect=write):
            with self.assertRaises(OSError):
                self.dispatch()
        with self.assertRaises(provider_config.ProviderConfigError):
            subscription_journal.validate_recovery_artifacts(self.run, {}, binding=self.binding.public)
        restored = subscription_journal.validate_recovery_artifacts(self.run, {}, binding=self.binding)
        self.assertEqual(restored["journal"][self.req["request_id"]]["status"], "completed")
        self.assertEqual(subscription_journal.completed_exchange(self.run, self.binding, self.req, self.messages),
                         (restored["journal"][self.req["request_id"]]["response"],
                          restored["journal"][self.req["request_id"]]["receipt"]))

    def test_one_active_generation_shared_across_roles(self):
        entered = threading.Event()
        release = threading.Event()
        second_entered = threading.Event()
        failures = []
        req2, messages2 = request(self.binding, sequence=2, role="prover", conversation="2" * 64)
        def first(admission, continuations):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test gate timed out")
            return self.generate(admission, continuations)
        def second(*_):
            second_entered.set()
            return terminal(self.binding, req2)
        def invoke(callback):
            try:
                callback()
            except BaseException as error:
                failures.append(error)
        one = threading.Thread(target=invoke, args=(lambda: self.dispatch(first),))
        two = threading.Thread(target=invoke, args=(lambda: subscription_journal.dispatch(
            self.run, self.binding, req2, messages2, second),))
        one.start()
        self.assertTrue(entered.wait(5))
        two.start()
        self.assertFalse(second_entered.wait(0.05))
        release.set()
        one.join(5)
        two.join(5)
        self.assertFalse(one.is_alive() or two.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(second_entered.is_set())

    def test_failure_publishing_completion_recovers_without_generation(self):
        original = subscription_journal._write
        def write(path, value):
            if path.parent.name == "evidence" and value["records"][-1]["status"] == "completed":
                raise OSError("synthetic public publication failure")
            original(path, value)
        with mock.patch.object(subscription_journal, "_write", side_effect=write):
            with self.assertRaises(OSError):
                self.dispatch()
        response, receipt = self.dispatch(mock.Mock(side_effect=AssertionError("resent")))
        subscription_journal.validate_completed(self.run, self.req, response, receipt)

    def test_missing_or_tampered_private_continuation_stops_checkpoint_replay(self):
        response, receipt = self.dispatch()
        path = self.root / "provider-private" / "subscription-journal.json"
        record = subscription_journal._read(path)
        record["records"][0]["continuation"]["native"]["tool_call_id"] = "tampered"
        subscription_journal._write(path, record)
        with self.assertRaises(provider_config.ProviderConfigError):
            subscription_journal.validate_completed(self.run, self.req, response, receipt)
        path.unlink()
        with self.assertRaises(provider_config.ProviderConfigError):
            subscription_journal.initialize(self.run, self.binding)

    def test_signed_public_audit_needs_no_private_continuation(self):
        response, receipt = self.dispatch()
        state = accepted_state(self.req, response, receipt)
        private = self.root / "provider-private" / "subscription-journal.json"
        private.unlink()
        reduced = subscription_receipts.reduce_accounting(self.run, state, binding=self.binding.public, require_private=False)
        self.assertTrue(reduced["dispatch_accounting_complete"])
        self.assertFalse(reduced["monetary_cost_known"])
        self.assertIsNone(reduced["cost"])
        self.assertEqual(reduced["tokens"], {"input": 80, "output": 20, "total": 100})
        self.assertNotIn(b"opaque-native-fixture", (self.root / "evidence" / "subscription-journal.json").read_bytes())

    def test_reducer_rejects_fabricated_zero_cost_or_missing_exchange(self):
        response, receipt = self.dispatch()
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "missing"):
            subscription_receipts.reduce_accounting(self.run, {}, binding=self.binding.public)
        changed = copy.deepcopy(receipt)
        changed["cost"]["amount"] = "0.000000"
        with self.assertRaises(provider_config.ProviderConfigError):
            subscription_receipts.reduce_accounting(self.run, accepted_state(self.req, response, changed),
                                                    binding=self.binding.public)

    def test_matching_continuation_then_changed_history_rejected_before_callback(self):
        self.dispatch()
        cont = terminal(self.binding, self.req)[2]
        messages = self.messages + [{"role": "assistant", "content": "", "tool_calls": [{
            "id": cont["canonical_tool_id"], "type": "function", "function": {
                "name": cont["tool_call"]["name"],
                "arguments": canonical_json_bytes(cont["tool_call"]["arguments"]).decode()}}]},
            {"role": "tool", "tool_call_id": cont["canonical_tool_id"], "content": "synthetic tool result"}]
        altered = copy.deepcopy(messages)
        altered[1]["content"] = "changed frozen instruction"
        wrong, altered = request(self.binding, sequence=2, messages=altered)
        callback = mock.Mock()
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "history"):
            subscription_journal.dispatch(self.run, self.binding, wrong, altered, callback)
        callback.assert_not_called()
        req2, messages = request(self.binding, sequence=2, messages=messages)
        def generation(admission, continuations):
            self.assertEqual(continuations, [cont])
            return terminal(self.binding, req2)
        subscription_journal.dispatch(self.run, self.binding, req2, messages, generation)

    def test_symlink_lock_and_world_readable_private_dir_rejected(self):
        lock = self.root / "provider-private" / "subscription-journal.lock"
        lock.unlink()
        lock.symlink_to(self.root / "unrelated")
        with self.assertRaises(provider_config.ProviderConfigError):
            self.dispatch()
        lock.unlink()
        lock.parent.chmod(0o755)
        with self.assertRaisesRegex(provider_config.ProviderConfigError, "permissions"):
            self.dispatch()


if __name__ == "__main__":
    unittest.main()
