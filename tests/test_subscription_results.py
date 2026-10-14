"""Retained v3 accounting is auditable without promoting observations to bills."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from autofv import evidence, provider_config, result_audit, results, subscription_journal, worker_proxy
from autofv.contracts import canonical_json_bytes
from tests.test_results_evidence import _complete_attempt
from tests.test_subscription_receipts import fixture, request, terminal, accepted_state, sha


def attempt(root):
    run, state = _complete_attempt(root)
    _, binding = fixture(root, run_id=run["run_id"])
    route = run["lock"]["fixed_proxy"]
    binding.public.update(proxy_id=route["proxy_id"], route_id=route["route_id"], fixed_proxy_sha256=sha(route))
    binding.public["binding_sha256"] = sha({key: value for key, value in binding.public.items() if key != "binding_sha256"})
    run.update(provider_binding=binding.public, provider_binding_sha256=binding.public["binding_sha256"],
               fixed_proxy_sha256=sha(route), proxy_client_identity_sha256=binding.public["client_identity_sha256"],
               proxy_base="http://127.0.0.1:19082", cost_classification="subscription_cost_unknown")
    run.pop("proxy_policy_sha256", None)
    policy = worker_proxy._record_proxy_policy(run)
    egress = copy.deepcopy(run["egress_receipt"])
    egress.update(fixed_proxy_sha256=run["fixed_proxy_sha256"], proxy_policy_sha256=policy["policy_sha256"])
    egress["evidence_sha256"] = sha({key: value for key, value in egress.items() if key != "evidence_sha256"})
    run["egress_receipt"] = egress
    (root / "evidence" / "egress.json").write_bytes(canonical_json_bytes(egress) + b"\n")
    subscription_journal.initialize(run, binding)
    req, messages = request(binding)
    response, receipt = subscription_journal.dispatch(run, binding, req, messages, lambda *_: terminal(binding, req))
    state.update(accepted_state(req, response, receipt), cost=None, fvs_evidence={})
    state["config"].update(schema="autofv-run/v3", model=binding.model_id)
    for name in results.PERSISTED_SOURCE_ITEMS:
        (root / results.FILE_LOCATIONS[name]).unlink(missing_ok=True)
    results.persist_l0_sources(run, state)
    return run, state, binding


class SubscriptionResultTests(unittest.TestCase):
    def test_result_v3_retains_null_money_and_independent_dispatch_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, state, binding = attempt(root)
            result, _ = results.render_attempt(run, state, outcome="unverified", reason="synthetic_fixture")
            self.assertEqual(result["schema"], "autofv-result/v3")
            self.assertEqual(result["accounting_schema"], "autofv-subscription-accounting/v1")
            self.assertIsNone(result["cost_usd"])
            self.assertTrue(result["dispatch_accounting_complete"])
            self.assertFalse(result["monetary_cost_known"])
            self.assertFalse(result["accounting_bounded"])
            self.assertFalse(result["reported_spend_known"])
            self.assertEqual(result["invocations_used"], 1)
            self.assertNotIn(b"opaque-native-fixture", canonical_json_bytes(result))
            model_evidence = list(state["model_exchanges"].values())
            result_audit._validate_accounting(result, model_evidence, root)
            # Ordinary retained audit needs neither auth storage nor native state.
            (root / "provider-private" / "subscription-journal.json").unlink()
            result_audit._validate_accounting(result, model_evidence, root)
            for key, value in (("cost_usd", "0.000000"), ("monetary_cost_known", True),
                               ("dispatch_accounting_complete", False), ("invocations_used", 0),
                               ("runtime_identity_sha256", "e" * 64), ("schema", "autofv-result/v1")):
                with self.subTest(key=key), self.assertRaises(result_audit.AuditError):
                    result_audit._validate_accounting({**result, key: value}, model_evidence, root)

    def test_unknown_failed_dispatch_prevents_completed_accounting_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, state, binding = attempt(root)
            req, messages = request(binding, sequence=2, role="prover", conversation="2" * 64)
            def fail(*_):
                raise TimeoutError("synthetic upstream uncertainty")
            with self.assertRaises(TimeoutError):
                subscription_journal.dispatch(run, binding, req, messages, fail)
            for name in results.PERSISTED_SOURCE_ITEMS:
                (root / results.FILE_LOCATIONS[name]).unlink(missing_ok=True)
            results.persist_l0_sources(run, state)
            result, _ = results.render_attempt(run, state, outcome="infrastructure_failed", reason="provider_timeout")
            self.assertFalse(result["accounting_complete"])
            self.assertFalse(result["dispatch_accounting_complete"])
            self.assertFalse(result["monetary_cost_known"])
            self.assertFalse(result["scored"])
            self.assertIsNone(result["cost_usd"])
            self.assertEqual(len(result["unresolved_provider_requests"]), 1)
            result_audit._validate_accounting(result, list(state["model_exchanges"].values()), root)


if __name__ == "__main__":
    unittest.main()
