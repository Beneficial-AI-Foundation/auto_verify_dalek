import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import experiment, verifier
from tests.test_clean_verifier import (
    REFERENCE,
    TARGET,
    _canonical,
    _invocation,
    _members,
    _observed,
    _preparation_manifest,
    _sha256,
    _state,
    _terminal_state,
)
from tests.test_counterexample_terminal import CounterexampleFixture


def _prepared_report(*, incomplete=False):
    state = _terminal_state(incomplete=incomplete)
    bundle = verifier.build_bundle(_members(state))
    invocation = _invocation(bundle, state)
    manifest = _preparation_manifest(state)
    invocation["snapshot_sha256"] = manifest["tree_sha256"]
    observed = _observed(state)
    observed["snapshot_sha256"] = invocation["snapshot_sha256"]
    report = verifier.terminal_verifier.verify_terminal_bundle(
        bundle,
        invocation,
        preparation_manifest=manifest,
        reference_bytes=REFERENCE.read_bytes(),
        run_checks=lambda *_: observed,
    )
    run = {
        "run_id": invocation["run_id"],
        "agent_worker_id": invocation["agent_worker_id"],
        "snapshot_sha256": invocation["snapshot_sha256"],
        "preparation_manifest": manifest,
    }
    expected = {
        key: invocation[key]
        for key in (
            "invocation_id",
            "snapshot_sha256",
            "manifest_sha256",
            "probe_rust_sha256",
            "probe_aeneas_sha256",
            "graph_sha256",
            "image_digest",
            "control_bundle_sha256",
            "native_decide_policy_sha256",
            "axiom_scope_sha256",
            "toolchain_lock_sha256",
            "accepted_commit",
            "accepted_tree_sha256",
            "reference_sha256",
        )
    }
    expected["axiom_inventory_sha256"] = report["axiom_inventory_sha256"]
    return report, run, expected


class TerminalReportAuthorityTests(unittest.TestCase):
    def test_report_intake_rejects_self_consistent_unauthorized_axioms(self):
        report, run, expected = _prepared_report()
        forged = copy.deepcopy(report)
        for record in forged["axiom_inventory"]:
            record["axioms"] = ["sorryAx"]
        forged["core_report"]["axiom_inventory"] = copy.deepcopy(
            forged["axiom_inventory"]
        )
        for item in (forged["core_report"], forged):
            body = {key: value for key, value in item.items() if key != "report_sha256"}
            item["report_sha256"] = _sha256(_canonical(body))
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(forged, run, expected)

    def test_report_intake_rejects_incomplete_inventory_and_check_set(self):
        report, run, expected = _prepared_report()
        for mutation in (
            "missing_inventory",
            "truncated_trio",
            "substituted_dependency",
            "missing_check",
        ):
            forged = copy.deepcopy(report)
            if mutation == "missing_inventory":
                forged["axiom_inventory"].pop()
                forged["core_report"]["axiom_inventory"] = copy.deepcopy(
                    forged["axiom_inventory"]
                )
            elif mutation == "truncated_trio":
                removed = {
                    "Diamond.right_spec",
                    "AutoFVVerifier.hidden_1",
                    "AutoFVVerifier.meaning_1",
                }
                forged["axiom_inventory"] = [
                    item
                    for item in forged["axiom_inventory"]
                    if item["declaration"] not in removed
                ]
                forged["core_report"]["axiom_inventory"] = copy.deepcopy(
                    forged["axiom_inventory"]
                )
            elif mutation == "substituted_dependency":
                forged["axiom_inventory"][0]["dependencies"][0] = (
                    "Diamond.hostile"
                )
                forged["core_report"]["axiom_inventory"] = copy.deepcopy(
                    forged["axiom_inventory"]
                )
                forged["axiom_inventory_sha256"] = (
                    verifier.axiom_audit.inventory_identity_sha256(
                        forged["axiom_inventory"]
                    )
                )
                forged["core_report"]["axiom_inventory_sha256"] = forged[
                    "axiom_inventory_sha256"
                ]
            else:
                forged["checks"].pop("kernel_axioms")
                forged["core_report"]["checks"].pop("kernel_axioms")
            for item in (forged["core_report"], forged):
                body = {
                    key: value for key, value in item.items()
                    if key != "report_sha256"
                }
                item["report_sha256"] = _sha256(_canonical(body))
            with self.subTest(mutation=mutation), self.assertRaises(
                verifier.VerifierError
            ):
                verifier.validate_report(forged, run, expected)

    def test_report_intake_rejects_native_provenance_substitution(self):
        report, run, expected = _prepared_report()
        unrelated = {
            "spec": "Diamond.left_spec",
            "declaration": "Diamond.unrelated",
            "source_path": "Diamond/Unrelated.lean",
            "source_sha256": "a" * 64,
            "expression_sha256": "b" * 64,
            "origin": "baseline",
        }
        for field in (
            "accepted_native_decide_uses",
            "hidden_native_decide_uses",
            "native_decide_uses",
        ):
            forged = copy.deepcopy(report)
            forged[field] = [unrelated]
            forged["core_report"][field] = [unrelated]
            for item in (forged["core_report"], forged):
                body = {
                    key: value
                    for key, value in item.items()
                    if key != "report_sha256"
                }
                item["report_sha256"] = _sha256(_canonical(body))
            with self.subTest(field=field), self.assertRaises(
                verifier.VerifierError
            ):
                verifier.validate_report(forged, run, expected)

    def test_outer_pass_cannot_wrap_a_failed_or_same_worker_core(self):
        report, run, expected = _prepared_report()
        self.assertEqual(verifier.validate_report(report, run, expected), report)
        incomplete, incomplete_run, incomplete_expected = _prepared_report(
            incomplete=True
        )
        self.assertEqual(incomplete["terminal_status"], "unverified")
        self.assertEqual(
            verifier.validate_report(
                incomplete, incomplete_run, incomplete_expected
            ),
            incomplete,
        )
        for mutation in ("failed_core", "same_worker"):
            forged = copy.deepcopy(report)
            core = forged["core_report"]
            if mutation == "failed_core":
                core["verdict"] = "FAIL"
                core["evidence_level"] = "L0"
                core["failures"] = ["clean_build_failed"]
            else:
                core["verifier_worker_id"] = core["agent_worker_id"]
                forged["verifier_worker_id"] = forged["agent_worker_id"]
            core_body = {key: value for key, value in core.items() if key != "report_sha256"}
            core["report_sha256"] = _sha256(_canonical(core_body))
            outer_body = {
                key: value for key, value in forged.items() if key != "report_sha256"
            }
            forged["report_sha256"] = _sha256(_canonical(outer_body))
            with self.subTest(mutation=mutation), self.assertRaises(verifier.VerifierError):
                verifier.validate_report(forged, run, expected)

        for label, source, source_run, source_expected in (
            ("pass", report, run, expected),
            ("fail", incomplete, incomplete_run, incomplete_expected),
        ):
            forged = copy.deepcopy(source)
            forged["toolchain_lock_sha256"] = "f" * 64
            forged["core_report"]["toolchain_lock_sha256"] = "f" * 64
            core_body = {
                key: value
                for key, value in forged["core_report"].items()
                if key != "report_sha256"
            }
            forged["core_report"]["report_sha256"] = _sha256(
                _canonical(core_body)
            )
            outer_body = {
                key: value for key, value in forged.items() if key != "report_sha256"
            }
            forged["report_sha256"] = _sha256(_canonical(outer_body))
            with self.subTest(toolchain=label), self.assertRaises(
                verifier.VerifierError
            ):
                verifier.validate_report(forged, source_run, source_expected)

    def test_prepared_reference_is_selected_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_root = root / "input"
            run_root = root / "run"
            hidden_root = root / "hidden"
            input_root.mkdir()
            run_root.mkdir()
            hidden_root.mkdir()
            reference_path = hidden_root / "reference.json"
            reference_path.write_bytes(REFERENCE.read_bytes())
            state = _terminal_state()
            manifest = _preparation_manifest(state)
            identity = {
                "schema": "autofv-verifier-reference-binding/v1",
                "reference_path": str(reference_path.resolve()),
                "preparation_manifest_sha256": manifest["manifest_sha256"],
                "reference_sha256": _sha256(reference_path.read_bytes()),
            }
            run = {
                "input_root": str(input_root),
                "run_root": str(run_root),
                "preparation_manifest": manifest,
                "verifier_reference": identity,
            }
            raw = verifier._trusted_reference(run)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), identity["reference_sha256"])
            for field in ("preparation_manifest_sha256", "reference_sha256"):
                hostile = copy.deepcopy(run)
                hostile["verifier_reference"][field] = "f" * 64
                with self.subTest(field=field), self.assertRaises(verifier.VerifierError):
                    verifier._trusted_reference(hostile)

            for label, hostile_path in (
                ("inside_run", run_root / "reference.json"),
                ("inside_input", input_root / "reference.json"),
            ):
                hostile_path.write_bytes(REFERENCE.read_bytes())
                hostile = copy.deepcopy(run)
                hostile["verifier_reference"]["reference_path"] = str(
                    hostile_path.resolve()
                )
                with self.subTest(label=label), self.assertRaises(verifier.VerifierError):
                    verifier._trusted_reference(hostile)
            link = hidden_root / "reference-link.json"
            link.symlink_to(reference_path)
            hostile = copy.deepcopy(run)
            hostile["verifier_reference"]["reference_path"] = str(link)
            with self.assertRaises(verifier.VerifierError):
                verifier._trusted_reference(hostile)

    def test_terminal_invocation_is_durable_and_not_repeated(self):
        graph = _state()["graph"]
        run = {
            "run_id": "run-001",
            "snapshot_sha256": "0" * 64,
            "manifest_sha256": "1" * 64,
            "image_digest": experiment.load_toolchain_lock()["image"][
                "image_digest"
            ],
            "control_bundle_sha256": "2" * 64,
            "native_decide_policy_sha256": experiment.load_toolchain_lock()[
                "native_decide_policy_sha256"
            ],
            "base_commit": "3" * 40,
            "lock": experiment.load_toolchain_lock(),
            "events": [],
        }
        state = {
            "run": run,
            "graph": graph,
            "accepted": {
                "accepted_commit": "4" * 40,
                "accepted_tree_sha256": "5" * 64,
            },
            "accepted_nodes": graph["selected_nodes"],
            "contracts": {"frozen": _state()["frozen_contracts"]},
            "native_decide_uses": [],
            "config": {},
        }
        incomplete = {
            "verdict": "FAIL",
            "terminal_status": "unverified",
            "axiom_inventory_sha256": "9" * 64,
        }
        verify_run = mock.Mock(return_value=incomplete)
        with (
            mock.patch.object(verifier, "verify_run", verify_run),
            mock.patch.object(verifier, "validate_report", return_value=incomplete),
            mock.patch.object(experiment, "_checkpoint_if_enabled"),
        ):
            state.update(experiment._clean_verify(state))
            state.update(experiment._clean_verify(state))
        verify_run.assert_called_once()
        self.assertEqual(
            verify_run.call_args.args[1]["toolchain_lock_sha256"],
            _sha256(_canonical(run["lock"])),
        )
        self.assertIn("clean_verifier:INCOMPLETE", run["events"])

        orphaned = copy.deepcopy(state)
        orphaned.pop("verifier_report")
        with (
            mock.patch.object(verifier, "verify_run") as duplicate,
            self.assertRaisesRegex(verifier.VerifierError, "already invoked"),
        ):
            experiment._clean_verify(orphaned)
        duplicate.assert_not_called()


class CounterexampleAuthorityTests(CounterexampleFixture, unittest.TestCase):
    def test_missing_trusted_obligation_is_unverified_not_false_spec(self):
        state, _, certificate = self._reference_and_certificate()
        state["counterexample_certificate"] = certificate
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state)
        manifest = _preparation_manifest(state)
        invocation["snapshot_sha256"] = manifest["tree_sha256"]
        observed = _observed(state)
        observed["snapshot_sha256"] = invocation["snapshot_sha256"]
        confirm = mock.Mock(return_value=certificate["certificate_sha256"])
        report = verifier.terminal_verifier.verify_terminal_bundle(
            bundle,
            invocation,
            preparation_manifest=manifest,
            reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_: observed,
            confirm_counterexample=confirm,
        )
        self.assertEqual(report["terminal_status"], "unverified")
        self.assertIsNone(report["counterexample_certificate_sha256"])
        confirm.assert_not_called()

    def test_counterexample_confirmation_requires_all_other_targets_accepted(self):
        state, reference, certificate = self._reference_and_certificate()
        false_target = certificate["target"]
        blocked_target = next(node for node in state["target_states"] if node != false_target)
        state["target_states"][blocked_target]["status"] = "blocked"
        state["counterexample_certificate"] = certificate
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state)
        invocation["accepted_commit"] = certificate["accepted_commit"]
        invocation["reference_sha256"] = _sha256(reference)
        manifest = _preparation_manifest(state)
        invocation["snapshot_sha256"] = manifest["tree_sha256"]
        observed = _observed(state)
        observed["snapshot_sha256"] = invocation["snapshot_sha256"]
        checked_states = []
        confirm = mock.Mock(return_value=certificate["certificate_sha256"])

        def run_checks(_members, checked_state, _reference):
            checked_states.append(copy.deepcopy(checked_state))
            return observed

        report = verifier.terminal_verifier.verify_terminal_bundle(
            bundle,
            invocation,
            preparation_manifest=manifest,
            reference_bytes=reference,
            run_checks=run_checks,
            confirm_counterexample=confirm,
        )

        self.assertEqual(report["terminal_status"], "unverified")
        self.assertNotIn("_counterexample_incomplete_accepted", checked_states[0])
        confirm.assert_not_called()

    def test_retained_certificate_requires_exact_counterexample_state(self):
        state, reference, certificate = self._reference_and_certificate()
        state["counterexample_certificate"] = certificate
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state)
        invocation["accepted_commit"] = certificate["accepted_commit"]
        invocation["reference_sha256"] = _sha256(reference)
        manifest = _preparation_manifest(state)
        invocation["snapshot_sha256"] = manifest["tree_sha256"]
        observed = _observed(state)
        observed["snapshot_sha256"] = invocation["snapshot_sha256"]
        report = verifier.terminal_verifier.verify_terminal_bundle(
            bundle,
            invocation,
            preparation_manifest=manifest,
            reference_bytes=reference,
            run_checks=lambda *_: observed,
            confirm_counterexample=lambda *_: certificate["certificate_sha256"],
        )
        run = {
            "run_id": invocation["run_id"],
            "agent_worker_id": invocation["agent_worker_id"],
            "snapshot_sha256": invocation["snapshot_sha256"],
            "preparation_manifest": manifest,
        }
        expected = {
            key: invocation[key]
            for key in (
                "invocation_id",
                "snapshot_sha256",
                "manifest_sha256",
                "probe_rust_sha256",
                "probe_aeneas_sha256",
                "graph_sha256",
                "image_digest",
                "control_bundle_sha256",
                "native_decide_policy_sha256",
                "axiom_scope_sha256",
                "toolchain_lock_sha256",
                "accepted_commit",
                "accepted_tree_sha256",
                "reference_sha256",
            )
        }
        self.assertEqual(verifier.validate_report(report, run, expected), report)

        forged = copy.deepcopy(report)
        other_target = next(
            node
            for node in forged["target_states"]
            if node != certificate["target"]
        )
        forged["target_states"][other_target]["status"] = "blocked"
        forged["target_states_sha256"] = _sha256(
            _canonical(forged["target_states"])
        )
        body = {
            key: value for key, value in forged.items() if key != "report_sha256"
        }
        forged["report_sha256"] = _sha256(_canonical(body))
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(forged, run, expected)


if __name__ == "__main__":
    unittest.main()
