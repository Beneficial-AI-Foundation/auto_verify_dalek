import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import axiom_audit, experiment, verifier
from tests.test_clean_verifier import (
    REFERENCE,
    _invocation,
    _members,
    _observed,
    _state,
)
from tests import test_terminal_verifier as terminal_fixtures


class KernelAxiomAuditTests(unittest.TestCase):
    def test_scope_and_observed_inventory_hashes_bind_different_facts(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        inventory = axiom_audit.expected_inventory(state, reference)
        substituted = copy.deepcopy(inventory)
        substituted[0]["dependencies"] = sorted(
            {*substituted[0]["dependencies"], "Lean.hostile"}
        )
        self.assertEqual(
            axiom_audit.inventory_scope_sha256(inventory),
            axiom_audit.inventory_scope_sha256(substituted),
        )
        self.assertNotEqual(
            axiom_audit.inventory_identity_sha256(inventory),
            axiom_audit.inventory_identity_sha256(substituted),
        )

    def test_hidden_native_provenance_is_separate_and_exact(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        reference["leaves"][0]["proof"] = "by native_decide"
        reference["leaves"][0]["proof_sha256"] = hashlib.sha256(
            reference["leaves"][0]["proof"].encode()
        ).hexdigest()
        expected = axiom_audit.expected_inventory(state, reference)
        hidden = next(
            item
            for item in expected
            if item["declaration"] == "AutoFVVerifier.hidden_0"
        )
        hidden["axioms"] = ["Lean.ofReduceBool", "Lean.trustCompiler"]
        accepted_uses, hidden_uses, all_uses = axiom_audit.native_use_provenance(
            expected
        )
        self.assertEqual(accepted_uses, [])
        self.assertEqual(hidden_uses, hidden["native_decide_uses"])
        self.assertEqual(all_uses, hidden_uses)
        axiom_audit.validate_report_inventory(
            expected,
            lock=experiment.load_toolchain_lock(),
            compiler_assumptions=state["compiler_assumptions"],
            require_complete=True,
            expected_scope_sha256=axiom_audit.inventory_scope_sha256(expected),
            expected_identity_sha256=axiom_audit.inventory_identity_sha256(expected),
            accepted_native_decide_uses=accepted_uses,
            hidden_native_decide_uses=hidden_uses,
            required_native_uses=all_uses,
        )

    def test_native_use_union_follows_dependency_attribution_and_tuple_order(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        top = "Diamond.top_spec"
        state["frozen_contracts"][top] = {
            "canon": (
                "theorem Diamond.top_spec (n : Nat) : "
                "Diamond.top n = n * 3 + 1"
            )
        }
        uses = [
            {
                "spec": "Diamond.left_spec",
                "declaration": declaration,
                "source_path": source,
                "source_sha256": character * 64,
                "expression_sha256": expression * 64,
                "origin": "baseline",
            }
            for declaration, source, character, expression in (
                ("Diamond.right", "Diamond/Right.lean", "a", "f"),
                ("Diamond.left", "Diamond/Left.lean", "b", "1"),
            )
        ]
        state["native_decide_uses"] = uses[:1]
        observed_closures = {
            "Diamond.left_spec": ["Diamond.left", "Diamond.left_spec"],
            "Diamond.right_spec": ["Diamond.right", "Diamond.right_spec"],
            top: [
                "Diamond.left",
                "Diamond.left_spec",
                "Diamond.right",
                "Diamond.right_spec",
                top,
            ],
            "AutoFVVerifier.hidden_0": [
                "AutoFVVerifier.hidden_0",
                "Diamond.left",
            ],
            "AutoFVVerifier.meaning_0": [
                "AutoFVVerifier.meaning_0",
                "Diamond.left",
            ],
            "AutoFVVerifier.hidden_1": [
                "AutoFVVerifier.hidden_1",
                "Diamond.right",
            ],
            "AutoFVVerifier.meaning_1": [
                "AutoFVVerifier.meaning_1",
                "Diamond.right",
            ],
        }
        uses[0]["spec"] = "Diamond.left_spec"
        uses[0]["declaration"] = "Diamond.left_spec"
        expected = axiom_audit.expected_inventory(
            state, reference, observed_closures=observed_closures
        )
        consumer = next(
            item
            for item in expected
            if item["declaration"] == top
        )
        self.assertEqual(
            consumer["semantic_dependencies"],
            ["Diamond.left", "Diamond.right", "Diamond.top"],
        )
        self.assertEqual(
            consumer["dependencies"],
            [
                "Diamond.left",
                "Diamond.left_spec",
                "Diamond.right",
                "Diamond.right_spec",
            ],
        )
        self.assertEqual(
            [item["declaration"] for item in consumer["native_decide_uses"]],
            ["Diamond.left_spec"],
        )
        self.assertTrue(
            next(
                item
                for item in expected
                if item["declaration"] == "Diamond.left_spec"
            )["native_decide_uses"]
        )
        self.assertTrue(
            all(
                not item["native_decide_uses"]
                for item in expected
                if item["origin"] in {"hidden_reference", "meaning_check"}
            )
        )
        for record in expected:
            if record["native_decide_uses"]:
                record["axioms"] = ["Lean.ofReduceBool", "Lean.trustCompiler"]
        with mock.patch.object(
            axiom_audit.contracts, "evaluate_native_decide_policy"
        ) as evaluate:
            axiom_audit.validate_inventory(
                expected,
                copy.deepcopy(expected),
                lock=experiment.load_toolchain_lock(),
                compiler_assumptions=state["compiler_assumptions"],
            )
            axiom_audit.validate_report_inventory(
                expected,
                lock=experiment.load_toolchain_lock(),
                compiler_assumptions=state["compiler_assumptions"],
                require_complete=True,
                expected_scope_sha256=(
                    axiom_audit.inventory_scope_sha256(expected)
                ),
                expected_identity_sha256=(
                    axiom_audit.inventory_identity_sha256(expected)
                ),
                accepted_native_decide_uses=state["native_decide_uses"],
                hidden_native_decide_uses=[],
                required_native_uses=state["native_decide_uses"],
            )
        uses = evaluate.call_args.kwargs["native_decide_uses"]
        self.assertEqual(
            [
                (
                    item["spec"],
                    item["declaration"],
                    item["source_path"],
                    item["expression_sha256"],
                )
                for item in uses
            ],
            sorted(
                {
                    (
                        item["spec"],
                        item["declaration"],
                        item["source_path"],
                        item["expression_sha256"],
                    )
                    for item in uses
                }
            ),
        )

    def test_accepted_and_hidden_sorry_axioms_never_pass(self):
        state = _state()
        bundle = verifier.build_bundle(_members(state))
        for origin in ("accepted_spec", "hidden_reference"):
            observed = _observed(state)
            record = next(
                item
                for item in observed["axiom_inventory"]
                if item["origin"] == origin
            )
            record["axioms"] = ["sorryAx"]
            report = verifier.verify_bundle(
                bundle,
                _invocation(bundle, state),
                reference_bytes=REFERENCE.read_bytes(),
                run_checks=lambda *_args, value=observed: copy.deepcopy(value),
            )
            with self.subTest(origin=origin):
                self.assertEqual(report["verdict"], "FAIL")
                self.assertEqual(report["evidence_level"], "L0")
                self.assertIn("axiom_inventory_invalid", report["failures"])

    def test_inventory_parser_requires_every_fixed_declaration(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        expected = axiom_audit.expected_inventory(state, reference)
        output = "\n".join(
            f"'{record['declaration']}' does not depend on any axioms"
            for record in expected
        ).encode()
        self.assertEqual(
            axiom_audit.parse_inventory(output, b"", expected), expected
        )
        with self.assertRaisesRegex(Exception, "incomplete"):
            axiom_audit.parse_inventory(output.splitlines()[0] + b"\n", b"", expected)


if __name__ == "__main__":
    unittest.main()
