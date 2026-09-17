import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import (
    axiom_audit,
    evidence,
    experiment,
    model,
    provider_config,
    provider_service,
    provider_transport,
    results,
    verifier,
    worker,
    worker_proxy,
)
from tests.test_provider_receipts import (
    RUN_TOKEN,
    _environment,
    _messages,
    _Reply,
    _reply,
    _tools,
)
from tests.test_provider_service import _install_trusted_authorization_fixture


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"
MODEL_PROXY_FIXTURE = (
    ROOT / "tests" / "fixtures" / "model-proxy" / "diamond-responses.json"
)


def _sha(value):
    raw = experiment.canonical_json_bytes(value)
    return hashlib.sha256(raw).hexdigest()


def _receipt(body, digest_field):
    return {**body, digest_field: _sha(body)}


def _semantic_review(state, *, status="approved"):
    graph = state.get("graph", {})
    frozen = set(graph.get("frozen_targets", []))
    targets = state.get("target_states", {})
    final = {
        target["contract_fingerprint"]
        for node, target in targets.items()
        if node not in frozen
        and isinstance(target, dict)
        and target.get("status") == "accepted"
        and isinstance(target.get("contract_fingerprint"), str)
    }
    contracts = state.get("contracts", {})
    supplied_specs = set(graph.get("supplied_specs", {}).values())
    final.update(
        record["model_fingerprint"]
        for name, record in contracts.get("frozen", {}).items()
        if name not in supplied_specs
        and isinstance(record, dict)
        and isinstance(record.get("model_fingerprint"), str)
    )
    inventory = set(contracts.get("invalidated_fingerprints", [])) | final
    for revision in contracts.get("revision_lineage", []):
        if isinstance(revision, dict):
            inventory.update(
                value
                for value in (
                    revision.get("old_fingerprint"),
                    revision.get("new_fingerprint"),
                )
                if isinstance(value, str)
            )
    if not inventory:
        inventory = {
            record["model_fingerprint"]
            for record in contracts.get("frozen", {}).values()
            if isinstance(record, dict)
            and isinstance(record.get("model_fingerprint"), str)
        }
        final = set(inventory)
    body = {
        "schema": "contract-semantic-review/v1",
        "status": status,
        "accepted_commit": state["accepted"]["accepted_commit"],
        "fingerprints": [
            {
                "fingerprint": fingerprint,
                "decision": (
                    "approved" if status == "approved" and fingerprint in final
                    else "withheld"
                ),
            }
            for fingerprint in sorted(inventory)
        ],
    }
    return _receipt(body, "review_sha256")


def _complete_attempt(
    root: Path,
    *,
    attempt_id: str = "attempt-complete",
    run_id: str = "result-evidence-run",
):
    lock = experiment.load_toolchain_lock()
    assumptions = verifier.compiler_assumptions(lock)
    checks = {
        name: True
        for name in (
            "bundle",
            "runtime_identity",
            "reference_integrity",
            "exact_commit",
            "exact_tree",
            "fresh_cache",
            "clean_build",
            "target_closure",
            "statements",
            "scope",
            "holes",
            "trust",
            "native_decide",
            "kernel_axioms",
            "meaning",
        )
    }
    meaning = {
        "reference_integrity": True,
        "statement_equivalence": True,
        "non_vacuity": True,
        "broken_implementation_rejected": True,
    }
    inventory = sorted(
        [
            {
                "declaration": "Diamond.left_spec",
                "origin": "accepted_spec",
                "type_sha256": "a" * 64,
                "semantic_dependencies": [],
                "dependencies": [],
                "axioms": [],
                "native_decide_uses": [],
            },
            {
                "declaration": "AutoFVVerifier.hidden_0",
                "origin": "hidden_reference",
                "type_sha256": "b" * 64,
                "semantic_dependencies": [],
                "dependencies": [],
                "axioms": [],
                "native_decide_uses": [],
            },
            {
                "declaration": "AutoFVVerifier.meaning_0",
                "origin": "meaning_check",
                "type_sha256": "c" * 64,
                "semantic_dependencies": [],
                "dependencies": [],
                "axioms": [],
                "native_decide_uses": [],
            },
        ],
        key=lambda item: (item["declaration"], item["origin"]),
    )
    report_body = {
        "schema": "autofv-verifier-report/v1",
        "run_id": run_id,
        "invocation_id": "verifier-fixture-001",
        "agent_worker_id": "lima:agent:aaa",
        "verifier_worker_id": "lima:verifier:bbb",
        "snapshot_sha256": "4" * 64,
        "manifest_sha256": "5" * 64,
        "probe_rust_sha256": "1" * 64,
        "probe_aeneas_sha256": "2" * 64,
        "graph_sha256": "3" * 64,
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": "6" * 64,
        "native_decide_policy_sha256": lock[
            "native_decide_policy_sha256"
        ],
        "axiom_scope_sha256": axiom_audit.inventory_scope_sha256(inventory),
        "axiom_inventory_sha256": axiom_audit.inventory_identity_sha256(
            inventory
        ),
        "toolchain_lock_sha256": _sha(lock),
        "accepted_commit": "a" * 40,
        "accepted_tree_sha256": "b" * 64,
        "bundle_sha256": "c" * 64,
        "reference_sha256": "d" * 64,
        "verdict": "PASS",
        "evidence_level": "L4",
        "checks": checks,
        "failures": [],
        "meaning": meaning,
        "sorry_count_before": 1,
        "sorry_count_after": 0,
        "native_decide_uses": [],
        "accepted_native_decide_uses": [],
        "hidden_native_decide_uses": [],
        "compiler_assumptions": assumptions,
        "axiom_inventory": inventory,
    }
    report = _receipt(report_body, "report_sha256")
    graph = {
        "frozen_targets": ["probe:Diamond.top"],
        "supplied_specs": {"probe:Diamond.top": "probe:Diamond.top_spec"},
        "selected_nodes": [
            "probe:Diamond.left",
            "probe:Diamond.right",
            "probe:Diamond.top",
        ],
        "probe_rust_sha256": "1" * 64,
        "probe_aeneas_sha256": "2" * 64,
        "graph_sha256": "3" * 64,
    }
    worker_inventory = _receipt(
        {
            "schema": "autofv-worker-inventory/v1",
            "run_id": run_id,
            "platform": "linux",
        },
        "inventory_sha256",
    )
    scored_container = _receipt(
        {
            "schema": "autofv-scored-container/v1",
            "run_id": run_id,
            "volume": "fixture-volume",
            "runtime": "runsc-hardened",
        },
        "inspection_sha256",
    )
    proxy_policy = _receipt(
        {
            "schema": "autofv-fixed-proxy-policy/v1",
            "run_id": run_id,
            "route_id": "fixed-inference-v1",
        },
        "policy_sha256",
    )
    upstream_policy = _receipt(
        {
            "schema": "autofv-upstream-egress-policy/v1",
            "run_id": run_id,
            "enforcer": "macos-seatbelt-network-outbound",
        },
        "policy_sha256",
    )
    upstream_policy_sha256 = upstream_policy["policy_sha256"]
    egress_policy = _receipt(
        {
            "schema": "autofv-egress-policy/v1",
            "enforcer": evidence.NETWORK_ENFORCER,
            "upstream_policy_sha256": upstream_policy_sha256,
        },
        "policy_sha256",
    )
    egress = _receipt(
        {
            "schema": "autofv-egress-evidence/v1",
            "run_id": run_id,
            "policy": egress_policy,
            "upstream_policy": upstream_policy,
            "fixed_proxy_sha256": "7" * 64,
            "proxy_policy_sha256": proxy_policy["policy_sha256"],
            "upstream_denied": [],
            "worker_denied": [],
            "container_denied": [],
            "fixed_proxy": {"status": "ok"},
        },
        "evidence_sha256",
    )
    artifact_scan = _receipt(
        {
            "schema": "autofv-retained-state-scan/v1",
            "run_id": run_id,
            "clean": True,
        },
        "scan_sha256",
    )
    export_receipt = _receipt(
        {
            "schema": "autofv-export/v1",
            "run_id": run_id,
            "scan_sha256": artifact_scan["scan_sha256"],
            "verified_before_disposal": True,
        },
        "manifest_sha256",
    )
    disposal_receipt = _receipt(
        {
            "schema": "autofv-disposal/v1",
            "run_id": run_id,
            "export_manifest_sha256": export_receipt["manifest_sha256"],
            "worker_absent": True,
            "run_resources_absent": True,
        },
        "disposal_sha256",
    )
    run = {
        "attempt_id": attempt_id,
        "attempt_ledger": str(root.parent / "attempts.jsonl"),
        "run_id": run_id,
        "run_root": str(root),
        "evidence_dir": str(root / "evidence"),
        "volume": "fixture-volume",
        "execution_tier": "sealed_runsc",
        "cost_classification": "synthetic_fixture",
        "agent_worker_id": "lima:agent:aaa",
        "snapshot_sha256": "4" * 64,
        "manifest_sha256": "5" * 64,
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": "6" * 64,
        "native_decide_policy": "allow_audited",
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "fixed_proxy_sha256": "7" * 64,
        "proxy_policy_sha256": proxy_policy["policy_sha256"],
        "proxy_policy_receipt": proxy_policy,
        "upstream_policy_sha256": upstream_policy_sha256,
        "egress_policy_sha256": egress_policy["policy_sha256"],
        "egress_receipt": egress,
        "worker_inventory_sha256": worker_inventory["inventory_sha256"],
        "worker_inventory": worker_inventory,
        "scored_container_receipt": scored_container,
        "manifest": json.loads((TARGET / "autofv.json").read_text()),
        "lock": lock,
        "accepted": {
            "accepted_commit": "a" * 40,
            "accepted_tree_sha256": "b" * 64,
            "checks": ["configured_build"],
        },
        "artifact_scan_receipt": artifact_scan,
        "export_receipt": export_receipt,
        "disposal_receipt": disposal_receipt,
        "events": [
            "target_copied",
            "control_bundle_verified",
            "runsc_started",
            "scored_container_inspected",
            "targets_frozen",
            "fixed_proxy_policy_bound",
            "egress_matrix_passed",
            "proxy:proof-left-001",
            "candidate_accepted:proof-left-001",
            "clean_verifier:PASS",
            "artifacts_exported",
            "worker_disposed",
        ],
    }
    state = {
        "run": run,
        "manifest": run["manifest"],
        "config": {
            "model": "fixture-model-v1",
            "max_wall_seconds": 300,
            "max_cost_usd": Decimal("1.000000"),
        },
        "graph": graph,
        "contracts": {
            "frozen": {
                "Diamond.left_spec": {
                    "status": "frozen",
                    "model_fingerprint": "a" * 64,
                },
                "Diamond.right_spec": {
                    "status": "frozen",
                    "model_fingerprint": "b" * 64,
                },
            }
        },
        "accepted": run["accepted"],
        "accepted_nodes": graph["selected_nodes"],
        "candidate_receipts": [{"status": "accepted"}],
        "accepted_sequence": [{"sequence": 1}],
        "receipts": [
            {
                "receipt_sha256": "f" * 64,
                "usage": {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14},
                "cost": {"amount": "0.010000", "currency": "USD"},
            }
        ],
        "model_exchanges": {
            "proof-left-001": {
                "request": {
                    "request_id": "proof-left-001",
                    "prompt_sha256": "c" * 64,
                }
            }
        },
        "receipt_rejections": [],
        "cost": Decimal("0.010000"),
        "wall_seconds_used": Decimal("12.500000"),
        "finalization_reserve_seconds": Decimal("5.000000"),
        "verifier_report": report,
        "native_decide_uses": [],
    }
    state["contract_semantic_review"] = _semantic_review(state)
    files = {
        "evidence/worker-inventory.json": worker_inventory,
        "evidence/scored-container.json": scored_container,
        "evidence/fixed-proxy-policy.json": proxy_policy,
        "evidence/egress.json": egress,
        "export/artifact-scan.json": artifact_scan,
        "evidence/verifier.json": report,
        "export/manifest.json": export_receipt,
        "disposal.json": disposal_receipt,
    }
    for relative, value in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")
    results.persist_l0_sources(run, state)
    return run, state


def _generic_attempt(root: Path, *, attempt_id: str = "attempt-generic"):
    fixture = json.loads(MODEL_PROXY_FIXTURE.read_text())
    run, state = _complete_attempt(
        root, attempt_id=attempt_id, run_id=fixture["run_id"]
    )
    left, right, top = state["graph"]["selected_nodes"]
    old_fingerprint = "8" * 64
    new_fingerprint = "9" * 64
    state["target_states"] = {
        node: {
            "phase": "proof",
            "status": "accepted",
            "attempt_count": 1,
            "contract_revision": 1 if node == left else 0,
            "contract_fingerprint": (
                new_fingerprint if node == left else chr(97 + index) * 64
            ),
            "statement_sha256": chr(100 + index) * 64,
            "block_chain": None,
        }
        for index, node in enumerate((left, right, top))
    }
    state["contracts"].update(
        {
            "invalidated_fingerprints": [old_fingerprint],
            "revision_lineage": [
                {
                    "node": left,
                    "revision": 1,
                    "old_fingerprint": old_fingerprint,
                    "new_fingerprint": new_fingerprint,
                }
            ],
        }
    )
    state["invalidated_consumers"] = [top]
    state["block_chains"] = {}
    exchange = fixture["entries"][0]
    request_id = exchange["request"]["request_id"]
    state["receipts"] = [copy.deepcopy(exchange["receipt"])]
    state["model_exchanges"] = {
        request_id: {
            name: copy.deepcopy(exchange[name])
            for name in ("request", "response", "receipt")
        }
    }
    state["receipt_rejections"] = [{"request_id": request_id}]
    state["cost"] = Decimal(exchange["receipt"]["cost"]["amount"])
    state["tool_calls"] = ["read_allowed", "lean_check", "submit_candidate"]
    state["compaction_calls"] = ["proof-left-compaction-001"]
    state["timing_seconds"] = {
        "provider": Decimal("1.250000"),
        "queue": Decimal("0.125000"),
        "lean": Decimal("2.500000"),
        "build": Decimal("3.750000"),
    }
    state["estimated_accounting"] = {
        "tokens": {"input": 20, "output": 8, "total": 28},
        "cost_usd": "0.020000",
    }
    state["contract_semantic_review"] = _semantic_review(state)
    run["cost_classification"] = run["lock"]["fixed_proxy"][
        "cost_classification"
    ]
    for name in results.PERSISTED_SOURCE_ITEMS:
        (root / results.FILE_LOCATIONS[name]).unlink(missing_ok=True)
    results.persist_l0_sources(run, state)
    return run, state


def _provider_attempt(root: Path, *, provider_reports_cost: bool = False):
    run, state = _generic_attempt(root, attempt_id="attempt-provider")
    run["fixed_proxy_sha256"] = provider_config.canonical_sha256(
        run["lock"]["fixed_proxy"]
    )
    environment = _environment(root, "provider-result-secret")
    with mock.patch.dict(os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False):
        provider_config.configure_provider(
            run, env_path=environment, tool_schemas=_tools()
        )
    if "base_commit" not in run:
        run["base_commit"] = run["accepted"]["accepted_commit"]
    _install_trusted_authorization_fixture(run, root)
    run["proxy_base"] = "http://127.0.0.1:19082"
    run.pop("proxy_policy_sha256", None)
    run.pop("proxy_policy_receipt", None)
    policy = worker_proxy._record_proxy_policy(run)
    egress = copy.deepcopy(run["egress_receipt"])
    egress["fixed_proxy_sha256"] = run["fixed_proxy_sha256"]
    egress["proxy_policy_sha256"] = policy["policy_sha256"]
    egress.pop("evidence_sha256")
    egress = _receipt(egress, "evidence_sha256")
    run["egress_receipt"] = egress
    (root / "evidence" / "egress.json").write_bytes(
        experiment.canonical_json_bytes(egress) + b"\n"
    )

    messages = _messages()
    request = model._model_envelope(
        state,
        request_id="provider-result-request-001",
        role="scout",
        input_hashes=[worker_proxy.provider_messages_sha256(messages)],
    )
    worker_proxy.stage_provider_messages(run, request, messages)
    provider_reply = _reply('{"path":"Diamond/Left.lean"}')
    if not provider_reports_cost:
        provider_reply["usage"].pop("cost")
        provider_reply["usage"].pop("cost_details")
    with mock.patch(
        "autofv.provider_transport._open_upstream",
        return_value=_Reply(provider_reply),
    ):
        response, receipt = provider_service.dispatch(
            run, request, run_token=RUN_TOKEN
        )
    state["receipts"] = [receipt]
    state["model_exchanges"] = {
        request["request_id"]: {
            "request": request,
            "response": response,
            "receipt": receipt,
            "call_kind": "explicit",
        }
    }
    state["receipt_rejections"] = []
    state["pending_model_exchanges"] = {}
    state["cost"] = Decimal(receipt["cost"]["amount"])
    for name in results.PERSISTED_SOURCE_ITEMS:
        (root / results.FILE_LOCATIONS[name]).unlink(missing_ok=True)
    results.persist_l0_sources(run, state)
    return run, state


class ResultEvidenceTests(unittest.TestCase):
    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            provider_config.release_provider(
                {"provider_binding_sha256": binding.public["binding_sha256"]}
            )

    def test_complete_l0_and_l4_are_required_for_a_recovery_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            linked = {
                item["name"]: item
                for item in receipt["items"]
                if item["location"] is not None
            }
            for item in linked.values():
                raw = (Path(run["run_root"]) / item["location"]).read_bytes()
                self.assertEqual(
                    item["sha256"], hashlib.sha256(raw).hexdigest()
                )
                self.assertEqual(item["size"], len(raw))

        self.assertEqual(
            {item["name"] for item in receipt["items"]},
            set(results.REQUIRED_L0_ITEMS),
        )
        self.assertTrue(receipt["complete"])
        self.assertEqual(
            set(linked),
            set(results.REQUIRED_L0_ITEMS),
        )
        self.assertEqual(result["evidence_level"], "L4")
        self.assertTrue(result["scored"])
        self.assertEqual(result["missing_evidence"], [])
        self.assertEqual(result["claim"]["status"], "supported")
        self.assertEqual(
            result["claim"]["recovered_specifications"],
            ["Diamond.left_spec", "Diamond.right_spec"],
        )
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["native_decide_uses"], [])
        self.assertEqual(
            result["sets"],
            {
                "T": {"ids": ["probe:Diamond.top"], "size": 1},
                "S": {"ids": ["probe:Diamond.top"], "size": 1},
                "W": {"ids": [], "size": 0},
                "recovered_internal_specs": {
                    "ids": ["Diamond.left_spec", "Diamond.right_spec"],
                    "size": 2,
                },
            },
        )
        self.assertEqual(result["model_attempts"], 1)
        self.assertEqual(result["model_retries"], 0)
        self.assertEqual(result["prompt_sha256"], ["c" * 64])
        self.assertEqual(result["sorry_counts"], {"before": 1, "after": 0})
        self.assertEqual(result["accepted_commit"], "a" * 40)
        self.assertEqual(result["accepted_tree_sha256"], "b" * 64)
        self.assertEqual(
            result["toolchain_lock_sha256"],
            _sha(state["run"]["lock"]),
        )
        self.assertEqual(
            result["compiler_assumptions"],
            state["verifier_report"]["compiler_assumptions"],
        )
        self.assertIn("cryptographic_security", result["exclusions"])
        self.assertEqual(results.validate_l0(receipt), receipt)

    def test_legacy_synthetic_result_defaults_new_accounting_fields_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _generic_attempt(root)
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            for name in (
                "accounting_complete",
                "unresolved_provider_requests",
                "unknown_provider_spend",
            ):
                result.pop(name)
            review_path = root / "contract-semantic-review.json"
            review_path.write_bytes(
                experiment.canonical_json_bytes(state["contract_semantic_review"])
                + b"\n"
            )
            results.persist_attempt(run, result, receipt)

            audited = results.validate_full_audit(root / "result.json", review_path)
            self.assertEqual(audited["cost_classification"], "synthetic_fixture")
            self.assertNotIn("accounting_complete", audited)

    def test_generic_complete_result_retains_progress_timing_and_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

            required = {
                "target_states",
                "verified_counts",
                "block_chains",
                "contract_history",
                "calls",
                "timing_seconds",
                "accounting",
            }
            self.assertEqual(required - result.keys(), set())
            self.assertEqual(result["target_states"], state["target_states"])
            self.assertEqual(
                result["verified_counts"],
                {"targets": 1, "declarations": 3, "closure": 3},
            )
            self.assertEqual(result["block_chains"], {})
            self.assertEqual(
                result["contract_history"],
                {
                    "revision_lineage": state["contracts"]["revision_lineage"],
                    "invalidated_fingerprints": state["contracts"][
                        "invalidated_fingerprints"
                    ],
                    "invalidated_consumers": state["invalidated_consumers"],
                    "final_fingerprints": ["a" * 64, "b" * 64],
                },
            )
            self.assertEqual(
                result["calls"],
                {"model": 2, "tool": 3, "retry": 1, "compaction": 1},
            )
            self.assertEqual(
                result["timing_seconds"],
                {
                    "provider": "1.250000",
                    "queue": "0.125000",
                    "lean": "2.500000",
                    "build": "3.750000",
                    "wall": "12.500000",
                },
            )
            self.assertEqual(
                result["accounting"],
                {
                    "provider_authenticated": {
                        "requests": 0,
                        "tokens": {"input": 0, "output": 0, "total": 0},
                        "cost_usd": "0.000000",
                    },
                    "synthetic": {
                        "requests": 1,
                        "tokens": {"input": 120, "output": 40, "total": 160},
                        "cost_usd": "0.001600",
                    },
                    "estimated": state["estimated_accounting"],
                },
            )
            self.assertEqual(result["cost_classification"], "synthetic_fixture")
            self.assertEqual(result["cost_usd"], "0.001600")
            self.assertEqual(result["outcome"], "success")
            self.assertEqual(result["termination_reason"], "all_targets_verified")
            self.assertNotEqual(result["outcome"], result["termination_reason"])
            self.assertEqual(result["snapshot_sha256"], "4" * 64)
            self.assertEqual(result["manifest_sha256"], "5" * 64)
            self.assertEqual(result["probe_rust_sha256"], "1" * 64)
            self.assertEqual(result["probe_aeneas_sha256"], "2" * 64)
            self.assertEqual(result["graph_sha256"], "3" * 64)
            self.assertEqual(result["accepted_commit"], "a" * 40)

            results.persist_attempt(run, result, receipt)
            different = copy.deepcopy(result)
            different["accounting"]["estimated"]["cost_usd"] = "9.000000"
            with self.assertRaisesRegex(results.ResultError, "replacement refused"):
                results.persist_attempt(run, different, receipt)

            relabeled = copy.deepcopy(run)
            relabeled["cost_classification"] = "provider_authenticated"
            relabeled_result, _ = results.render_attempt(
                relabeled,
                state,
                outcome="success",
                reason="all_targets_verified",
            )
            self.assertEqual(
                relabeled_result["cost_classification"], "synthetic_fixture"
            )

            for mutation in ("missing_exchange", "tampered_signature"):
                hostile = copy.deepcopy(state)
                if mutation == "missing_exchange":
                    hostile["model_exchanges"] = {}
                else:
                    hostile["receipts"][0]["auth"]["signature"] = "AAAA"
                    stored = next(iter(hostile["model_exchanges"].values()))
                    stored["receipt"]["auth"]["signature"] = "AAAA"
                with self.subTest(mutation=mutation), self.assertRaises(
                    results.ResultError
                ):
                    results.render_attempt(
                        run,
                        hostile,
                        outcome="success",
                        reason="all_targets_verified",
                    )

    def test_provider_result_persists_truthful_accounting_and_audits_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _provider_attempt(root)
            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            review_path = root / "contract-semantic-review.json"
            review_path.write_bytes(
                experiment.canonical_json_bytes(state["contract_semantic_review"])
                + b"\n"
            )
            results.persist_attempt(run, result, receipt)
            provider_config.release_provider(run)

            audited = results.validate_full_audit(root / "result.json", review_path)
            self.assertEqual(audited["cost_classification"], "provider_authenticated")
            self.assertEqual(
                audited["provider_binding_sha256"],
                audited["provider_binding"]["binding_sha256"],
            )
            self.assertEqual(audited["accounting"]["synthetic"]["requests"], 0)
            self.assertEqual(
                audited["accounting"]["provider_authenticated"],
                {
                    "requests": 1,
                    "tokens": {"input": 120, "output": 40, "total": 160},
                    "cost_usd": "0.000000",
                },
            )
            self.assertEqual(
                audited["accounting"]["estimated"],
                {
                    "requests": 1,
                    "tokens": {"input": 120, "output": 40, "total": 160},
                    "cost_usd": "0.000380",
                },
            )
            self.assertEqual(
                audited["verified_counts"],
                {"targets": 1, "declarations": 3, "closure": 3},
            )

            result_path = root / "result.json"
            policy_path = root / "evidence" / "fixed-proxy-policy.json"
            preflight_path = root / "evidence" / "provider-preflight.json"
            journal_path = next((root / "evidence" / "provider-journal").iterdir())
            originals = {
                result_path: result_path.read_bytes(),
                policy_path: policy_path.read_bytes(),
                preflight_path: preflight_path.read_bytes(),
                journal_path: journal_path.read_bytes(),
            }

            def missing_policy() -> None:
                policy_path.unlink()

            def missing_preflight() -> None:
                preflight_path.unlink()

            def missing_journal() -> None:
                journal_path.unlink()

            def tampered_policy() -> None:
                value = json.loads(policy_path.read_bytes())
                value["route_id"] = "attacker-route"
                policy_path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")

            def tampered_signature() -> None:
                value = json.loads(preflight_path.read_bytes())
                value["receipt"]["auth"]["signature"] = "AAAA"
                body = {
                    key: item
                    for key, item in value.items()
                    if key != "preflight_sha256"
                }
                value["preflight_sha256"] = _sha(body)
                preflight_path.write_bytes(
                    experiment.canonical_json_bytes(value) + b"\n"
                )

            def tampered_preflight() -> None:
                value = json.loads(preflight_path.read_bytes())
                value["response"]["content"] = "attacker-content"
                body = {
                    key: item
                    for key, item in value.items()
                    if key != "preflight_sha256"
                }
                value["preflight_sha256"] = _sha(body)
                preflight_path.write_bytes(
                    experiment.canonical_json_bytes(value) + b"\n"
                )

            def tampered_journal() -> None:
                value = json.loads(journal_path.read_bytes())
                value["response"]["content"] = "attacker-content"
                signed = {
                    key: item for key, item in value.items() if key != "record_sha256"
                }
                value["record_sha256"] = _sha(signed)
                journal_path.write_bytes(
                    experiment.canonical_json_bytes(value) + b"\n"
                )

            def missing_binding() -> None:
                value = json.loads(result_path.read_bytes())
                value.pop("provider_binding")
                result_path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")

            def tampered_binding() -> None:
                value = json.loads(result_path.read_bytes())
                value["provider_binding"]["model_id"] = "attacker-model"
                result_path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")

            def tampered_digest() -> None:
                value = json.loads(result_path.read_bytes())
                value["provider_preflight_sha256"] = "0" * 64
                result_path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")

            attacks = {
                "missing-policy": missing_policy,
                "missing-preflight": missing_preflight,
                "missing-journal": missing_journal,
                "tampered-policy": tampered_policy,
                "tampered-preflight": tampered_preflight,
                "tampered-journal": tampered_journal,
                "tampered-signature": tampered_signature,
                "missing-binding": missing_binding,
                "tampered-binding": tampered_binding,
                "tampered-digest": tampered_digest,
            }
            for name, attack in attacks.items():
                with self.subTest(attack=name):
                    for path, raw in originals.items():
                        path.write_bytes(raw)
                    attack()
                    with self.assertRaises(results.ResultError):
                        results.validate_full_audit(result_path, review_path)

    def test_completed_provider_result_renders_after_private_binding_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _provider_attempt(root)
            review_path = root / "contract-semantic-review.json"
            review_path.write_bytes(
                experiment.canonical_json_bytes(state["contract_semantic_review"])
                + b"\n"
            )
            provider_config.release_provider(run)

            with mock.patch.object(
                provider_config,
                "provider_binding",
                side_effect=AssertionError("private provider state consulted"),
            ):
                result, receipt = results.render_attempt(
                    run,
                    state,
                    outcome="success",
                    reason="all_targets_verified",
                )
            results.persist_attempt(run, result, receipt)

            audited = results.validate_full_audit(
                root / "result.json", review_path
            )
            self.assertEqual(
                audited["provider_binding_sha256"],
                run["provider_binding_sha256"],
            )
            self.assertEqual(audited["proxy_requests"], 1)

    def test_finalization_reconciles_provider_before_release_then_audits_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _provider_attempt(root)
            run["worker_disposed"] = False
            run["base_commit"] = run["accepted"]["accepted_commit"]
            (root / "contract-semantic-review.json").write_bytes(
                experiment.canonical_json_bytes(state["contract_semantic_review"])
                + b"\n"
            )
            events: list[str] = []
            reconcile = results.reconcile_provider_finalization

            def observed_reconcile(*args, **kwargs):
                events.append("reconciled")
                return reconcile(*args, **kwargs)

            def dispose(candidate, *, interrupted):
                self.assertFalse(interrupted)
                self.assertIsNotNone(candidate.get("provider_preflight_sha256"))
                events.append("released")
                provider_service.release(candidate)
                candidate["worker_disposed"] = True
                return candidate["disposal_receipt"]

            with mock.patch.object(
                results,
                "reconcile_provider_finalization",
                side_effect=observed_reconcile,
            ), mock.patch.object(
                worker, "dispose_run", side_effect=dispose
            ), mock.patch.object(results, "materialize_accepted"):
                result = experiment._finish_attempt(
                    run,
                    state,
                    outcome="success",
                    reason="all_targets_verified",
                )

            self.assertEqual(events, ["reconciled", "released"])
            with self.assertRaises(provider_config.ProviderConfigError):
                provider_config.provider_binding(run)
            audited = results.validate_full_audit(
                root / "result.json", root / "contract-semantic-review.json"
            )
            self.assertEqual(audited["outcome"], result["outcome"])
            self.assertEqual(audited["proxy_requests"], 1)

    def test_provider_result_rejects_a_dropped_completed_paid_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _provider_attempt(Path(tmp) / "run")
            messages = _messages()
            request = model._model_envelope(
                state,
                request_id="provider-result-request-002",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
            )
            worker_proxy.stage_provider_messages(run, request, messages)
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply('{"path":"Diamond/Right.lean"}')),
            ):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)

            with self.assertRaisesRegex(results.ResultError, "journal"):
                results.render_attempt(
                    run,
                    state,
                    outcome="success",
                    reason="all_targets_verified",
                )

    def test_ambiguous_provider_call_persists_unscored_partial_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _provider_attempt(root)
            messages = _messages()
            request = model._model_envelope(
                state,
                request_id="provider-result-request-002",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
            )
            worker_proxy.stage_provider_messages(run, request, messages)
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                side_effect=RuntimeError("simulated crash after dispatch"),
            ), self.assertRaisesRegex(RuntimeError, "after dispatch"):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "call_kind": "explicit",
                    "reservation_usd": "0.032880",
                    "dispatch_state": "ambiguous",
                }
            }

            with self.assertRaises(results.ResultError):
                results.render_attempt(
                    run, state, outcome="success", reason="all_targets_verified"
                )
            result, receipt = results.render_attempt(
                run,
                state,
                outcome="infrastructure_failed",
                reason="worker_failed",
            )
            results.persist_attempt(run, result, receipt)

            self.assertFalse(result["scored"])
            self.assertIsNone(result["evidence_level"])
            self.assertFalse(result["accounting_complete"])
            self.assertTrue(result["unknown_provider_spend"])
            self.assertEqual(result["claim"]["status"], "withheld")
            self.assertEqual(
                result["verified_counts"],
                {"targets": 0, "declarations": 0, "closure": 0},
            )
            self.assertEqual(
                result["accounting"]["estimated"]["cost_usd"], "0.000380"
            )
            self.assertEqual(
                result["unresolved_provider_requests"],
                [
                    {
                        "request_id": request["request_id"],
                        "sequence": request["sequence"],
                        "status": "ambiguous",
                        "reservation_usd": "0.032880",
                        "request_sha256": provider_config.canonical_sha256(request),
                        "record_sha256": run["provider_journal"][request["request_id"]],
                    }
                ],
            )
            self.assertTrue((root / "result.json").is_file())

    def test_first_provider_call_ambiguity_persists_without_a_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            run, state = _provider_attempt(root)
            for path in (root / "evidence" / "provider-journal").iterdir():
                path.unlink()
            (root / "evidence" / "provider-preflight.json").unlink()
            run["provider_journal"] = {}
            run.pop("provider_preflight_sha256")
            state["receipts"] = []
            state["model_exchanges"] = {}
            state["pending_model_exchanges"] = {}
            state["cost"] = Decimal("0.000000")
            messages = _messages()
            request = model._model_envelope(
                state,
                request_id="provider-first-ambiguous-001",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
            )
            worker_proxy.stage_provider_messages(run, request, messages)
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                side_effect=RuntimeError("simulated first dispatch crash"),
            ), self.assertRaisesRegex(RuntimeError, "first dispatch"):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "call_kind": "explicit",
                    "reservation_usd": "0.032880",
                    "dispatch_state": "ambiguous",
                }
            }

            results.reconcile_provider_finalization(
                run, state, outcome="infrastructure_failed"
            )
            provider_service.release(run)
            with mock.patch.object(
                provider_config,
                "provider_binding",
                side_effect=AssertionError("private provider state consulted"),
            ):
                result, receipt = results.render_attempt(
                    run,
                    state,
                    outcome="infrastructure_failed",
                    reason="worker_failed",
                )
            results.persist_attempt(run, result, receipt)

            self.assertFalse(result["scored"])
            self.assertFalse(result["accounting_complete"])
            self.assertTrue(result["unknown_provider_spend"])
            self.assertEqual(
                result["accounting"]["provider_authenticated"]["requests"], 0
            )
            self.assertEqual(result["accounting"]["estimated"]["requests"], 0)
            self.assertIsNone(result["provider_preflight_sha256"])
            self.assertEqual(
                result["unresolved_provider_requests"][0]["request_id"],
                request["request_id"],
            )
            self.assertTrue((root / "result.json").is_file())

    def test_signed_completed_pending_call_is_known_in_unscored_subtotal(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _provider_attempt(Path(tmp) / "run")
            request_id, exchange = next(iter(state["model_exchanges"].items()))
            state["model_exchanges"] = {}
            state["receipts"] = []
            state["pending_model_exchanges"] = {
                request_id: {
                    **exchange,
                    "reservation_usd": exchange["receipt"]["cost"]["amount"],
                    "dispatch_state": "completed",
                }
            }

            result, _receipt = results.render_attempt(
                run,
                state,
                outcome="infrastructure_failed",
                reason="worker_failed",
            )

            self.assertFalse(result["scored"])
            self.assertFalse(result["accounting_complete"])
            self.assertFalse(result["unknown_provider_spend"])
            self.assertEqual(result["unresolved_provider_requests"], [])
            self.assertEqual(
                result["accounting"]["estimated"]["requests"], 1
            )
            self.assertEqual(result["proxy_requests"], 1)

    def test_provider_reported_cost_stays_in_the_billed_bucket(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _provider_attempt(
                Path(tmp) / "run", provider_reports_cost=True
            )
            result, _ = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            self.assertEqual(
                result["accounting"]["provider_authenticated"],
                {
                    "requests": 1,
                    "tokens": {"input": 120, "output": 40, "total": 160},
                    "cost_usd": "0.000380",
                },
            )
            self.assertEqual(
                result["accounting"]["estimated"],
                {
                    "requests": 0,
                    "tokens": {"input": 0, "output": 0, "total": 0},
                    "cost_usd": "0.000000",
                },
            )

    def test_generic_partial_result_retains_blocked_and_invalidated_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _generic_attempt(Path(tmp) / "run")
            left, right, top = state["graph"]["selected_nodes"]
            state["target_states"][left].update(
                {"status": "failed", "block_chain": [left]}
            )
            state["target_states"][top].update(
                {"status": "blocked", "block_chain": [top, left]}
            )
            state["block_chains"] = {top: [top, left]}
            state["accepted_nodes"] = [right]
            state.pop("verifier_report")

            result, _ = results.render_attempt(
                run,
                state,
                outcome="budget_exhausted",
                reason="wall_budget_exhausted",
            )

            required = {
                "target_states",
                "verified_counts",
                "block_chains",
                "contract_history",
                "calls",
                "timing_seconds",
                "accounting",
            }
            self.assertEqual(required - result.keys(), set())
            self.assertEqual(result["target_states"], state["target_states"])
            self.assertEqual(result["block_chains"], {top: [top, left]})
            self.assertEqual(
                result["verified_counts"],
                {"targets": 0, "declarations": 0, "closure": 0},
            )
            self.assertEqual(
                result["contract_history"]["revision_lineage"],
                state["contracts"]["revision_lineage"],
            )
            self.assertEqual(result["calls"]["compaction"], 1)
            self.assertEqual(result["timing_seconds"]["wall"], "12.500000")
            self.assertEqual(
                result["accounting"]["synthetic"]["cost_usd"],
                "0.001600",
            )
            self.assertEqual(result["accepted_commit"], "a" * 40)
            self.assertEqual(result["outcome"], "budget_exhausted")
            self.assertEqual(
                result["termination_reason"], "wall_budget_exhausted"
            )

    def test_missing_or_incomplete_evidence_is_unscored_and_withholds_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            _, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
        damaged = copy.deepcopy(receipt)
        damaged["items"] = [
            item for item in damaged["items"] if item["name"] != "disposal"
        ]
        assessment = results.assess_evidence(damaged, state["verifier_report"])
        claim = results.render_claim(
            assessment,
            run,
            state,
            outcome="success",
        )

        self.assertIsNone(assessment["level"])
        self.assertFalse(assessment["scored"])
        self.assertIn("disposal", assessment["missing"])
        self.assertEqual(claim["status"], "withheld")
        self.assertEqual(claim["recovered_specifications"], [])

    def test_file_backed_evidence_does_not_fall_back_through_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            verifier_path = Path(run["run_root"]) / "evidence/verifier.json"
            outside = Path(tmp) / "outside-verifier.json"
            outside.write_bytes(verifier_path.read_bytes())
            verifier_path.unlink()
            verifier_path.symlink_to(outside)

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        item = next(
            item for item in receipt["items"] if item["name"] == "verifier"
        )
        self.assertEqual(item["status"], "missing")
        self.assertEqual(item["location"], "evidence/verifier.json")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_verifier_file_must_match_the_report_that_is_graded(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            (Path(run["run_root"]) / "evidence/verifier.json").write_text("{}\n")

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        item = next(
            item for item in receipt["items"] if item["name"] == "verifier"
        )
        self.assertEqual(item["status"], "missing")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_proxy_policy_without_upstream_egress_evidence_is_unscored(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            run.pop("egress_receipt")

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        network = next(
            item for item in receipt["items"] if item["name"] == "network"
        )
        self.assertEqual(network["status"], "missing")
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_result_identities_are_derived_from_bound_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            run["worker_inventory_sha256"] = "0" * 64
            run["egress_policy_sha256"] = "9" * 64

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )

        missing = {
            item["name"]
            for item in receipt["items"]
            if item["status"] == "missing"
        }
        self.assertEqual(missing, {"runtime", "network"})
        self.assertIsNone(result["worker_inventory_sha256"])
        self.assertIsNone(result["egress_policy_sha256"])
        self.assertFalse(result["scored"])
        self.assertEqual(result["claim"]["status"], "withheld")

    def test_l3_and_conflicting_duplicate_evidence_withhold_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            lower = copy.deepcopy(state["verifier_report"])
            lower["evidence_level"] = "L3"
            lower["checks"]["meaning"] = False
            lower["meaning"] = {}
            lower.pop("report_sha256")
            lower = _receipt(lower, "report_sha256")
            state["verifier_report"] = lower
            root = Path(run["run_root"])
            (root / "evidence/verifier.json").write_bytes(
                experiment.canonical_json_bytes(lower) + b"\n"
            )
            (root / "evidence/l0/replay.json").write_bytes(
                experiment.canonical_json_bytes(lower) + b"\n"
            )
            build = {
                "accepted_checks": run["accepted"]["checks"],
                "verifier_checks": lower["checks"],
            }
            (root / "evidence/l0/build.json").write_bytes(
                experiment.canonical_json_bytes(build) + b"\n"
            )

            result, receipt = results.render_attempt(
                run, state, outcome="success", reason="all_targets_verified"
            )
            identical = copy.deepcopy(receipt)
            identical["items"].append(copy.deepcopy(identical["items"][0]))
            identical.pop("receipt_sha256")
            identical = _receipt(identical, "receipt_sha256")
            identical_assessment = results.assess_evidence(identical, lower)
            conflicting = copy.deepcopy(identical)
            conflicting["items"][-1]["sha256"] = "0" * 64
            conflicting.pop("receipt_sha256")
            conflicting = _receipt(conflicting, "receipt_sha256")
            conflicting_assessment = results.assess_evidence(conflicting, lower)

        self.assertEqual(result["evidence_level"], "L3")
        self.assertEqual(result["claim"]["status"], "withheld")
        self.assertEqual(identical_assessment["level"], "L3")
        self.assertFalse(conflicting_assessment["scored"])
        self.assertIn("input", conflicting_assessment["missing"])

    def test_attempt_ledger_appends_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            first_run, first_state = _complete_attempt(
                base / "first", attempt_id="attempt-first"
            )
            first, first_l0 = results.render_attempt(
                first_run,
                first_state,
                outcome="verification_failed",
                reason="clean_verifier_failed",
            )
            results.persist_attempt(first_run, first, first_l0)

            second_run, second_state = _complete_attempt(
                base / "second", attempt_id="attempt-second"
            )
            second, second_l0 = results.render_attempt(
                second_run,
                second_state,
                outcome="success",
                reason="all_targets_verified",
            )
            results.persist_attempt(second_run, second, second_l0)

            ledger = Path(first_run["attempt_ledger"])
            records = [json.loads(line) for line in ledger.read_text().splitlines()]
            self.assertEqual(
                [record["attempt_id"] for record in records],
                ["attempt-first", "attempt-second"],
            )
            replaced = {**first, "termination_reason": "rewritten"}
            with self.assertRaises(results.ResultError):
                results.persist_attempt(first_run, replaced, first_l0)
            self.assertEqual(len(ledger.read_text().splitlines()), 2)

    def test_final_result_and_l0_are_scanned_before_the_attempt_is_appended(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, state = _complete_attempt(Path(tmp) / "run")
            state["termination_detail"] = "synthetic-final-result-secret"
            run["artifact_scan_markers"] = ["synthetic-final-result-secret"]
            result, receipt = results.render_attempt(
                run,
                state,
                outcome="infrastructure_failed",
                reason="controller_failed",
            )

            with self.assertRaisesRegex(
                worker.WorkerError, "forbidden material"
            ):
                results.persist_attempt(run, result, receipt)

            self.assertFalse(Path(run["run_root"], "result.json").exists())
            self.assertFalse(Path(run["attempt_ledger"]).exists())

    def test_invalid_config_is_persisted_before_worker_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "run.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "autofv-run/v1",
                        "model": "fixture-model-v1",
                        "max_wall_seconds": 60,
                        "max_cost_usd": 1,
                        "unexpected": True,
                    }
                )
            )
            ledger = base / "attempts.jsonl"
            with (
                mock.patch.dict(os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                result = experiment.run_experiment(TARGET, config)

            prepare.assert_not_called()
            self.assertEqual(result["outcome"], "invalid_config")
            self.assertEqual(result["termination_reason"], "run_config_invalid")
            run_root = Path(result["run_root"])
            self.assertTrue((run_root / "result.json").is_file())
            self.assertTrue((run_root / "evidence" / "l0.json").is_file())
            self.assertEqual(len(ledger.read_text().splitlines()), 1)
            self.assertFalse(result["scored"])

    def test_invalid_ledger_and_preparation_interrupt_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fallback = base / "fallback.jsonl"
            with (
                mock.patch.object(results, "DEFAULT_ATTEMPT_LEDGER", fallback),
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": "relative.jsonl"}
                ),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                invalid = experiment.run_experiment(TARGET, TARGET / "run.json")
            prepare.assert_not_called()
            self.assertEqual(invalid["outcome"], "invalid_config")
            self.assertEqual(
                invalid["termination_reason"], "attempt_ledger_invalid"
            )
            self.assertEqual(len(fallback.read_text().splitlines()), 1)

            ledger = base / "interrupts.jsonl"
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(
                    worker, "prepare_run", side_effect=KeyboardInterrupt
                ),
            ):
                interrupted = experiment.run_experiment(
                    TARGET, TARGET / "run.json"
                )
            self.assertEqual(interrupted["outcome"], "infrastructure_failed")
            self.assertEqual(interrupted["termination_reason"], "interrupted")
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_invalid_target_has_explicit_empty_counts_and_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run") as prepare,
            ):
                result = experiment.run_experiment(
                    base / "missing-target", TARGET / "run.json"
                )

            prepare.assert_not_called()
            self.assertEqual(result["outcome"], "invalid_target")
            self.assertEqual(result["termination_reason"], "target_invalid")
            self.assertEqual(result["targets_total"], 0)
            self.assertEqual(result["internal_specs_accepted"], 0)
            self.assertEqual(result["internal_proofs_accepted"], 0)
            self.assertIsNone(result["snapshot_sha256"])
            self.assertIsNone(result["accepted_commit"])
            self.assertEqual(result["native_decide_uses"], [])
            self.assertFalse(result["scored"])
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_terminal_checkpoint_failure_still_persists_a_typed_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = {
                "attempt_id": "attempt-finalization",
                "attempt_ledger": str(root / "attempts.jsonl"),
                "run_id": "finalization-run",
                "run_root": str(root),
                "evidence_dir": str(root / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "lock": experiment.load_toolchain_lock(),
                "events": [],
            }
            state = {
                "run": run,
                "config": {},
                "receipts": [],
                "checkpoint_enabled": True,
            }
            with (
                mock.patch.object(
                    experiment,
                    "_checkpoint_if_enabled",
                    side_effect=(None, OSError("checkpoint unavailable")),
                ),
                mock.patch.object(results, "persist_attempt") as persist,
            ):
                result = experiment._finish_attempt(
                    run,
                    state,
                    outcome="success",
                    reason="all_targets_verified",
                )

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(result["termination_reason"], "finalization_failed")
            persist.assert_called_once()

    def test_unrecoverable_final_renderer_failure_gets_an_emergency_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            prepared = {
                "run_id": "renderer-failure-run",
                "run_root": str(base / "original"),
                "evidence_dir": str(base / "original" / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "events": ["validated"],
            }
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment,
                    "_finish_attempt",
                    side_effect=results.ResultError("renderer failed"),
                ),
            ):
                result = experiment.run_experiment(TARGET, TARGET / "run.json")

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(result["termination_reason"], "finalization_failed")
            self.assertIn("renderer failed", result["termination_detail"])
            self.assertTrue(Path(result["run_root"], "result.json").is_file())
            self.assertEqual(len(ledger.read_text().splitlines()), 1)

    def test_durable_finalization_failure_reuses_the_allocated_attempt_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "durable-renderer-failure-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "execution_tier": "simulation",
                "cost_classification": "synthetic_fixture",
                "events": ["validated"],
            }
            allocated_roots = []

            class FixedDatetime:
                @classmethod
                def now(cls, tz):
                    return datetime(2026, 9, 14, tzinfo=timezone.utc)

            def fail_finalization(run, *_args, **_kwargs):
                allocated_roots.append(Path(run["run_root"]))
                raise results.ResultError("renderer failed")

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(results, "datetime", FixedDatetime),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment, "_finish_attempt", side_effect=fail_finalization
                ),
            ):
                try:
                    result = experiment.run_experiment(
                        TARGET,
                        TARGET / "run.json",
                        output_root=base / "attempts",
                    )
                except results.ResultError as exc:
                    self.fail(
                        "emergency result was not persisted in the allocated "
                        f"attempt root: {exc}"
                    )

            self.assertEqual(result["termination_reason"], "finalization_failed")
            self.assertEqual(Path(result["run_root"]), allocated_roots[0])
            self.assertTrue((allocated_roots[0] / "result.json").is_file())

    def test_durable_binding_failure_force_destroys_the_prepared_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "binding-failure-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "volume": "autofv-binding-failure",
                "execution_tier": "sealed_runsc",
                "cost_classification": "provider_backed",
                "events": ["validated"],
            }
            moments = iter(
                (
                    datetime(2026, 9, 14, 0, 0, 0, tzinfo=timezone.utc),
                    datetime(2026, 9, 14, 0, 0, 1, tzinfo=timezone.utc),
                )
            )

            class AdvancingDatetime:
                @classmethod
                def now(cls, tz):
                    return next(moments)

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(results, "datetime", AdvancingDatetime),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    results,
                    "bind_prepared_run",
                    side_effect=results.ResultError("binding failed"),
                ),
                mock.patch.object(worker, "force_destroy_worker") as destroy,
            ):
                result = experiment.run_experiment(
                    TARGET,
                    TARGET / "run.json",
                    output_root=base / "attempts",
                )

            self.assertEqual(result["termination_reason"], "attempt_allocation_failed")
            destroy.assert_called_once_with(prepared)
            attempt_roots = [path.resolve() for path in (base / "attempts").iterdir()]
            self.assertEqual(attempt_roots, [Path(result["run_root"]).resolve()])

    def test_durable_binding_removes_the_worker_staging_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ledger = base / "attempts.jsonl"
            staging = base / "staging"
            (staging / "evidence").mkdir(parents=True)
            prepared = {
                "run_id": "successful-binding-run",
                "run_root": str(staging),
                "evidence_dir": str(staging / "evidence"),
                "volume": "autofv-successful-binding",
                "execution_tier": "sealed_runsc",
                "cost_classification": "provider_backed",
                "base_commit": "a" * 40,
                "egress_receipt": {"status": "allowed"},
                "events": ["validated"],
            }

            def finish_without_worker_calls(run, *_args, **_kwargs):
                return {"outcome": "success", "run_root": run["run_root"]}

            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_ATTEMPT_LEDGER": str(ledger)}
                ),
                mock.patch.object(worker, "prepare_run", return_value=prepared),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(
                    experiment,
                    "_finish_attempt",
                    side_effect=finish_without_worker_calls,
                ),
            ):
                result = experiment.run_experiment(
                    TARGET,
                    TARGET / "run.json",
                    output_root=base / "attempts",
                )

            self.assertEqual(result["outcome"], "success")
            self.assertNotEqual(Path(result["run_root"]), staging)
            self.assertFalse(staging.exists())


if __name__ == "__main__":
    unittest.main()
