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


class CounterexampleFixture:
    @staticmethod
    def _reference_and_certificate():
        state = _terminal_state(incomplete=True)
        target = "probe:" + next(iter(state["frozen_contracts"])).removesuffix(
            "_spec"
        )
        for record in state["target_states"].values():
            record["status"] = "accepted"
        state["target_states"][target]["status"] = "false_spec"
        inputs = [{"nat": 0}]
        obligation = {
            "target": target,
            "statement_sha256": state["target_states"][target]["statement_sha256"],
            "concrete_inputs": inputs,
            "lean_prefix": (
                "import Diamond.Top\nnamespace AutoFV\n"
                "theorem counterexample : (0 : Nat) ≠ 1 := by\n"
            ),
            "lean_suffix": "\nend AutoFV\n",
        }
        reference = json.loads(REFERENCE.read_text())
        reference["counterexample_obligations"] = [obligation]
        witness = "  decide"
        body = {
            "schema": "autofv-counterexample-certificate/v1",
            "target": target,
            "statement_sha256": obligation["statement_sha256"],
            "accepted_commit": "2" * 40,
            "toolchain_lock_sha256": _sha256(_canonical(experiment.load_toolchain_lock())),
            "concrete_inputs": inputs,
            "lean_witness": witness,
            "diagnostics_sha256": _sha256(b"\0"),
            "artifact_sha256": _sha256(witness.encode()),
            "verification_command": [
                "lake",
                "env",
                "lean",
                "-o",
                ".lake/build/lib/lean/AutoFVCounterexample.olean",
                "AutoFVCounterexample.lean",
            ],
            "native_decide_uses": [],
            "compiler_assumptions": verifier.compiler_assumptions(
                experiment.load_toolchain_lock()
            ),
            "axiom_inventory": [],
            "axiom_audit_sha256": _sha256(
                _canonical(
                    {"theorem": "AutoFV.counterexample", "axioms": []}
                )
            ),
        }
        certificate = {**body, "certificate_sha256": _sha256(_canonical(body))}
        return state, _canonical(reference), certificate


class CounterexampleCertificateTests(CounterexampleFixture, unittest.TestCase):
    def test_only_trusted_target_obligation_can_confirm_false_spec(self):
        module = getattr(verifier, "counterexample", None)
        self.assertIsNotNone(module)
        state, reference, certificate = self._reference_and_certificate()
        obligation = module.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        self.assertIsNotNone(obligation)
        program = module.build_program(certificate, obligation)
        self.assertIn(certificate["lean_witness"].encode(), program)

        for mutation in ("empty", "unrelated", "sorry", "axiom", "wrong_target"):
            hostile = copy.deepcopy(certificate)
            if mutation == "empty":
                hostile["lean_witness"] = ""
            elif mutation == "unrelated":
                hostile["lean_witness"] = "example : True := by trivial"
            elif mutation == "sorry":
                hostile["lean_witness"] = "  sorry"
            elif mutation == "axiom":
                hostile["lean_witness"] = "axiom forged : False"
            else:
                hostile["target"] = "probe:Diamond.wrong"
            hostile["artifact_sha256"] = _sha256(hostile["lean_witness"].encode())
            body = {key: value for key, value in hostile.items() if key != "certificate_sha256"}
            hostile["certificate_sha256"] = _sha256(_canonical(body))
            with self.subTest(mutation=mutation), self.assertRaises(verifier.VerifierError):
                obligation = module.resolve_obligation(
                    reference, hostile, state["target_states"]
                )
                module.build_program(hostile, obligation)

    def test_counterexample_runner_forwards_stdin_and_audits_program(self):
        module = getattr(verifier, "counterexample", None)
        self.assertIsNotNone(module)
        state, reference, certificate = self._reference_and_certificate()
        obligation = module.resolve_obligation(reference, certificate, state["target_states"])
        calls = []
        seeded = {}

        def docker(*argv, **kwargs):
            calls.append((argv, kwargs))
            stdout = (
                b"AUTOFV_REPLAYED:AutoFV.counterexample\n"
                b"AUTOFV_KERNEL_CHECKED:AutoFV.counterexample\n"
                b"AUTOFV_BASELINE_BOUND:\n"
                b"'AutoFV.counterexample' does not depend on any axioms\n"
                if "AutoFVCounterexampleAudit.lean" in argv
                else b"fixture-olean"
                if "cat" in argv and "AutoFVCounterexample.olean" in " ".join(argv)
                else b""
            )
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        def seed_file(_image, seed_volume, path, raw, **_kwargs):
            seeded[(seed_volume, path)] = raw

        confirmed = module.confirm(
            certificate,
            obligation,
            image="fixture-image",
            volume="fixture-volume",
            audit_volume="fixture-audit-volume",
            runtime="runsc-hardened",
            runtime_argv=lambda _image, _volume, *command, **_: ("run", *command),
            docker=docker,
            seed_file=seed_file,
            native_decide_policy_sha256=experiment.load_toolchain_lock()[
                "native_decide_policy_sha256"
            ],
        )
        self.assertEqual(confirmed, certificate["certificate_sha256"])
        commands = [call[0] for call in calls]
        self.assertIn("lake", commands[0])
        self.assertIn("build", commands[0])
        self.assertIn(("fixture-volume", "repo/AutoFVCounterexample.lean"), seeded)
        self.assertEqual(
            seeded[("fixture-volume", "repo/AutoFVCounterexample.lean")],
            module.build_program(certificate, obligation),
        )
        self.assertIn(
            ("fixture-audit-volume", "repo/AutoFVCounterexampleAudit.lean"),
            seeded,
        )
        self.assertEqual(
            seeded[("fixture-audit-volume", f"repo/{module.OLEAN_PATH}")],
            b"fixture-olean",
        )
        audit_commands = [
            command
            for command in commands
            if "AutoFVCounterexampleAudit.lean" in command
        ]
        self.assertEqual(len(audit_commands), 1)
        self.assertLess(
            next(i for i, command in enumerate(commands) if "build" in command),
            next(
                i
                for i, command in enumerate(commands)
                if "AutoFVCounterexample.lean" in command
            ),
        )

    def test_native_decide_uses_are_exhaustive_and_policy_audited(self):
        module = verifier.counterexample
        state, reference, certificate = self._reference_and_certificate()
        obligation = module.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        certificate["lean_witness"] = "  native_decide"
        certificate["artifact_sha256"] = _sha256(
            certificate["lean_witness"].encode()
        )
        certificate["native_decide_uses"] = [
            {
                "spec": certificate["target"],
                "declaration": certificate["target"],
                "source_path": "counterexample-witness.lean",
                "source_sha256": _sha256(certificate["lean_witness"].encode()),
                "expression_sha256": _sha256(b"native_decide"),
                "origin": "agent_introduced",
            }
        ]
        body = {
            key: value
            for key, value in certificate.items()
            if key != "certificate_sha256"
        }
        certificate["certificate_sha256"] = _sha256(_canonical(body))

        def docker(*argv, **_kwargs):
            stdout = (
                b"AUTOFV_REPLAYED:AutoFV.counterexample\n"
                b"AUTOFV_KERNEL_CHECKED:AutoFV.counterexample\n"
                b"AUTOFV_BASELINE_BOUND:\n"
                b"'AutoFV.counterexample' depends on axioms: "
                b"[Lean.ofReduceBool, Lean.trustCompiler]\n"
                if "AutoFVCounterexampleAudit.lean" in argv
                else b"fixture-olean"
                if "cat" in argv and "AutoFVCounterexample.olean" in " ".join(argv)
                else b""
            )
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        certificate["axiom_inventory"] = [
            "Lean.ofReduceBool",
            "Lean.trustCompiler",
        ]
        certificate["axiom_audit_sha256"] = _sha256(
            _canonical(
                {
                    "theorem": "AutoFV.counterexample",
                    "axioms": certificate["axiom_inventory"],
                }
            )
        )
        body = {
            key: value
            for key, value in certificate.items()
            if key != "certificate_sha256"
        }
        certificate["certificate_sha256"] = _sha256(_canonical(body))
        self.assertEqual(
            module.confirm(
                certificate,
                obligation,
                image="fixture-image",
                volume="fixture-volume",
                audit_volume="fixture-audit-volume",
                runtime="runsc-hardened",
                runtime_argv=lambda _image, _volume, *command, **_: (
                    "run",
                    *command,
                ),
                docker=docker,
                seed_file=lambda *_args, **_kwargs: None,
                native_decide_policy_sha256=experiment.load_toolchain_lock()[
                    "native_decide_policy_sha256"
                ],
            ),
            certificate["certificate_sha256"],
        )
        hostile = copy.deepcopy(certificate)
        hostile["native_decide_uses"] = []
        with self.assertRaises(verifier.VerifierError):
            module.confirm(
                hostile,
                obligation,
                image="fixture-image",
                volume="fixture-volume",
                audit_volume="fixture-audit-volume",
                runtime="runsc-hardened",
                runtime_argv=lambda _image, _volume, *command, **_: (
                    "run",
                    *command,
                ),
                docker=docker,
                seed_file=lambda *_args, **_kwargs: None,
                native_decide_policy_sha256=experiment.load_toolchain_lock()[
                    "native_decide_policy_sha256"
                ],
            )
        with (
            mock.patch.object(
                module.contracts,
                "evaluate_native_decide_policy",
                side_effect=module.contracts.ContractError("policy rejected"),
            ),
            self.assertRaises(verifier.VerifierError),
        ):
            module.confirm(
                certificate,
                obligation,
                image="fixture-image",
                volume="fixture-volume",
                audit_volume="fixture-audit-volume",
                runtime="runsc-hardened",
                runtime_argv=lambda _image, _volume, *command, **_: (
                    "run",
                    *command,
                ),
                docker=docker,
                seed_file=lambda *_args, **_kwargs: None,
                native_decide_policy_sha256=experiment.load_toolchain_lock()[
                    "native_decide_policy_sha256"
                ],
            )

    def test_kernel_axiom_audit_rejects_admission_and_custom_axioms(self):
        module = verifier.counterexample
        state, reference, certificate = self._reference_and_certificate()
        obligation = module.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        certificate["lean_witness"] = (
            "  run_tac\n"
            "    let goal ← Lean.Elab.Tactic.getMainGoal\n"
            "    let value ← Lean.Meta.mkSorry (← goal.getType) true\n"
            "    goal.assign value"
        )
        certificate["artifact_sha256"] = _sha256(
            certificate["lean_witness"].encode()
        )
        for axiom in ("sorryAx", "Counterexample.unsafeAxiom"):
            hostile = copy.deepcopy(certificate)
            hostile["axiom_inventory"] = [axiom]
            hostile["axiom_audit_sha256"] = _sha256(
                _canonical(
                    {
                        "theorem": "AutoFV.counterexample",
                        "axioms": [axiom],
                    }
                )
            )
            body = {
                key: value
                for key, value in hostile.items()
                if key != "certificate_sha256"
            }
            hostile["certificate_sha256"] = _sha256(_canonical(body))

            def docker(*argv, **_kwargs):
                stdout = (
                    f"'AutoFV.counterexample' depends on axioms: [{axiom}]\n".encode()
                    if "AutoFVCounterexampleAudit.lean" in argv
                    else b"fixture-olean"
                    if "cat" in argv and "AutoFVCounterexample.olean" in " ".join(argv)
                    else b""
                )
                return subprocess.CompletedProcess(argv, 0, stdout, b"")

            with self.subTest(axiom=axiom), self.assertRaises(
                verifier.VerifierError
            ):
                module.confirm(
                    hostile,
                    obligation,
                    image="fixture-image",
                    volume="fixture-volume",
                    audit_volume="fixture-audit-volume",
                    runtime="runsc-hardened",
                    runtime_argv=lambda _image, _volume, *command, **_: (
                        "run",
                        *command,
                    ),
                    docker=docker,
                    seed_file=lambda *_args, **_kwargs: None,
                    native_decide_policy_sha256=experiment.load_toolchain_lock()[
                        "native_decide_policy_sha256"
                    ],
                )

    def test_kernel_audit_requires_fixed_theorem_and_emitted_olean(self):
        module = verifier.counterexample
        state, reference, certificate = self._reference_and_certificate()
        obligation = module.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        unrelated = copy.deepcopy(obligation)
        unrelated["lean_prefix"] = (
            "import Diamond.Top\nexample : (0 : Nat) ≠ 1 := by\n"
        )
        unrelated["lean_suffix"] = "\n"
        with self.assertRaises(verifier.VerifierError):
            module.build_program(certificate, unrelated)

        def no_olean(*argv, **_kwargs):
            if "test" in argv and "AutoFVCounterexample.olean" in " ".join(argv):
                raise verifier.VerifierError("missing olean")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with self.assertRaises(verifier.VerifierError):
            module.confirm(
                certificate,
                obligation,
                image="fixture-image",
                volume="fixture-volume",
                audit_volume="fixture-audit-volume",
                runtime="runsc-hardened",
                runtime_argv=lambda _image, _volume, *command, **_: (
                    "run",
                    *command,
                ),
                docker=no_olean,
                seed_file=lambda *_args, **_kwargs: None,
                native_decide_policy_sha256=experiment.load_toolchain_lock()[
                    "native_decide_policy_sha256"
                ],
            )

    def test_unfinished_proof_inventory_does_not_block_independent_certificate(self):
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
        unfinished = next(
            record
            for record in observed["axiom_inventory"]
            if record["origin"] == "accepted_spec"
        )
        unfinished["axioms"] = ["sorryAx"]
        confirm = mock.Mock(return_value=certificate["certificate_sha256"])
        checked_states = []

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

        self.assertEqual(report["core_report"]["verdict"], "FAIL")
        self.assertIn("axiom_inventory_invalid", report["core_report"]["failures"])
        self.assertNotIn("clean_worker_failed", report["core_report"]["failures"])
        self.assertEqual(
            next(
                record["axioms"]
                for record in report["core_report"]["axiom_inventory"]
                if record["declaration"] == unfinished["declaration"]
            ),
            ["sorryAx"],
        )
        self.assertEqual(report["terminal_status"], "false_spec")
        self.assertEqual(
            report["counterexample_certificate_sha256"],
            certificate["certificate_sha256"],
        )
        confirm.assert_called_once()
        self.assertEqual(
            checked_states[0]["_counterexample_incomplete_accepted"],
            [unfinished["declaration"]],
        )

        hostile_observed = copy.deepcopy(observed)
        hidden = next(
            record
            for record in hostile_observed["axiom_inventory"]
            if record["origin"] == "hidden_reference"
        )
        hidden["axioms"] = ["sorryAx"]
        rejected_confirm = mock.Mock(
            return_value=certificate["certificate_sha256"]
        )
        with self.assertRaises(verifier.VerifierError):
            verifier.terminal_verifier.verify_terminal_bundle(
                bundle,
                invocation,
                preparation_manifest=manifest,
                reference_bytes=reference,
                run_checks=lambda *_: hostile_observed,
                confirm_counterexample=rejected_confirm,
            )
        rejected_confirm.assert_not_called()

        unrelated_observed = copy.deepcopy(observed)
        unrelated = next(
            record
            for record in unrelated_observed["axiom_inventory"]
            if record["origin"] == "accepted_spec"
            and record["declaration"] != unfinished["declaration"]
        )
        unrelated["axioms"] = ["sorryAx"]
        unrelated_confirm = mock.Mock(
            return_value=certificate["certificate_sha256"]
        )
        with self.assertRaises(verifier.VerifierError):
            verifier.terminal_verifier.verify_terminal_bundle(
                bundle,
                invocation,
                preparation_manifest=manifest,
                reference_bytes=reference,
                run_checks=lambda *_: unrelated_observed,
                confirm_counterexample=unrelated_confirm,
            )
        unrelated_confirm.assert_not_called()

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
        forged["checks"]["kernel_axioms"] = True
        forged["core_report"]["checks"]["kernel_axioms"] = True
        for item in (forged["core_report"], forged):
            body = {
                key: value
                for key, value in item.items()
                if key != "report_sha256"
            }
            item["report_sha256"] = _sha256(_canonical(body))
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(forged, run, expected)

        forged = copy.deepcopy(report)
        hidden = next(
            record
            for record in forged["axiom_inventory"]
            if record["origin"] == "hidden_reference"
        )
        hidden["axioms"] = ["sorryAx"]
        forged["core_report"]["axiom_inventory"] = copy.deepcopy(
            forged["axiom_inventory"]
        )
        for item in (forged["core_report"], forged):
            body = {
                key: value
                for key, value in item.items()
                if key != "report_sha256"
            }
            item["report_sha256"] = _sha256(_canonical(body))
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(forged, run, expected)


if __name__ == "__main__":
    unittest.main()
