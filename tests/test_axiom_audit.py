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
    def test_real_accepted_and_hidden_native_decide_helpers_are_replayed(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        statement = "Demo.value 3 = 3"
        proof = "by native_decide"
        source_text = (
            "namespace Demo\n"
            "def value (input : Nat) : Nat := input\n"
            f"theorem finished : {statement} := by\n"
            "  native_decide\n"
            "end Demo\n"
        )
        reference = {
            "leaves": [
                {
                    "declaration": "Demo.value",
                    "spec": "Demo.finished",
                    "source": "Demo.lean",
                    "statement": statement,
                    "statement_sha256": hashlib.sha256(
                        statement.encode()
                    ).hexdigest(),
                    "proof": proof,
                    "proof_sha256": hashlib.sha256(proof.encode()).hexdigest(),
                }
            ]
        }
        state = {
            "graph": {
                "selected_nodes": ["probe:Demo.finished", "probe:Demo.value"],
                "source_paths": {
                    "probe:Demo.finished": "Demo.lean",
                    "probe:Demo.value": "Demo.lean",
                },
                "term_dependencies": [
                    ["probe:Demo.finished", "probe:Demo.value"]
                ],
                "type_dependencies": [],
            },
            "frozen_contracts": {
                "Demo.finished": {
                    "canon": f"theorem Demo.finished : {statement}"
                }
            },
            "native_decide_uses": [
                {
                    "spec": "Demo.finished",
                    "declaration": "Demo.finished",
                    "source_path": "Demo.lean",
                    "source_sha256": hashlib.sha256(
                        source_text.encode()
                    ).hexdigest(),
                    "expression_sha256": hashlib.sha256(
                        b"native_decide"
                    ).hexdigest(),
                    "origin": "baseline",
                }
            ],
            "compiler_assumptions": verifier.compiler_assumptions(
                experiment.load_toolchain_lock()
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            source = root / "Demo.lean"
            source.write_text(
                "namespace Demo\n"
                "def value (input : Nat) : Nat := input\n"
                f"theorem finished : {statement} := by\n"
                "  sorry\n"
                "end Demo\n"
            )
            baseline = subprocess.run(
                [lean, "-R", ".", "-o", "Demo.olean", source.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(baseline.returncode, 0, baseline.stderr.decode())
            baseline_dir = root / ".autofv-baseline"
            baseline_dir.mkdir()
            shutil.copyfile(root / "Demo.olean", baseline_dir / "Demo.olean")
            bindings = axiom_audit.type_bindings(state, reference)
            expected_source = root / axiom_audit.EXPECTED_SOURCE
            expected_source.write_bytes(
                axiom_audit.expected_program(["Demo"], bindings)
            )
            expected_built = subprocess.run(
                [lean, "-R", ".", "-o", "AutoFVExpected.olean", expected_source.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(
                expected_built.returncode, 0, expected_built.stderr.decode()
            )
            shutil.copyfile(
                root / "AutoFVExpected.olean",
                baseline_dir / "AutoFVExpected.olean",
            )
            source.write_text(source_text)
            reference_source = root / axiom_audit.REFERENCE_SOURCE
            reference_source.write_bytes(axiom_audit.reference_program(reference))
            for path in (source, reference_source):
                compiled = subprocess.run(
                    [lean, "-R", ".", "-o", path.with_suffix(".olean").name, path.name],
                    cwd=root,
                    capture_output=True,
                    env=env,
                )
                self.assertEqual(
                    compiled.returncode,
                    0,
                    (compiled.stdout + compiled.stderr).decode(),
                )
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            shutil.copyfile(root / "Demo.olean", lake_dir / "Demo.olean")
            shutil.copyfile(
                root / axiom_audit.REFERENCE_OLEAN.rsplit("/", 1)[1],
                root / axiom_audit.REFERENCE_OLEAN,
            )
            expected = axiom_audit.expected_inventory(state, reference)
            audit = root / axiom_audit.AUDIT_SOURCE
            audit.write_bytes(
                axiom_audit.audit_program(
                    expected,
                    bindings=bindings,
                    project_modules=["Demo"],
                )
            )
            audited = subprocess.run(
                [lean, "-R", ".", "--run", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(
                audited.returncode,
                0,
                (audited.stdout + audited.stderr).decode(),
            )
            observation_names = axiom_audit._observation_names(expected)
            identities = axiom_audit.parse_kernel_identities(
                audited.stdout,
                audited.stderr,
                observation_names,
            )
            observed = axiom_audit.expected_inventory(
                state,
                reference,
                observed_closures={
                    record["declaration"]: identities[record["declaration"]][
                        "dependencies"
                    ]
                    for record in expected
                },
            )
            inventory = axiom_audit.parse_inventory(
                audited.stdout, audited.stderr, observed
            )
            accepted_uses, hidden_uses, all_uses = (
                axiom_audit.native_use_provenance(inventory)
            )
            self.assertEqual(accepted_uses, state["native_decide_uses"])
            self.assertEqual(len(hidden_uses), 1)
            self.assertEqual(
                all_uses,
                axiom_audit.canonical_native_uses(accepted_uses, hidden_uses),
            )
            self.assertEqual(
                {
                    record["origin"]: record["axioms"]
                    for record in inventory
                    if record["origin"] != "meaning_check"
                },
                {
                    "accepted_spec": [
                        "Lean.ofReduceBool",
                        "Lean.trustCompiler",
                    ],
                    "hidden_reference": [
                        "Lean.ofReduceBool",
                        "Lean.trustCompiler",
                    ],
                },
            )
            self.assertEqual(
                next(
                    record["axioms"]
                    for record in inventory
                    if record["origin"] == "meaning_check"
                ),
                [],
            )
            replayed, checked, baseline_bound = (
                axiom_audit.parse_kernel_replay_provenance(
                    audited.stdout, audited.stderr
                )
            )
            self.assertIn("Demo.value", baseline_bound)
            self.assertIn("Demo.finished", checked)
            project_identities = axiom_audit.parse_project_kernel_identities(
                audited.stdout, audited.stderr, observation_names
            )
            baseline_identities = {
                "Demo.value": project_identities["Demo.value"]
            }
            generated = axiom_audit.proof_generated_project_dependencies(
                project_identities,
                baseline_identities,
                identities,
                expected,
                state,
                checked,
            )
            self.assertTrue(generated)
            axiom_audit.compare_kernel_identities(
                baseline_identities,
                project_identities,
                frozen_types={"Demo.finished"},
                frozen_definitions={"Demo.value"},
                proof_generated=generated,
            )
            hostile_observations = copy.deepcopy(identities)
            hostile_observations["Demo.value"][
                "project_dependencies"
            ] = sorted(
                {
                    *hostile_observations["Demo.value"][
                        "project_dependencies"
                    ],
                    next(iter(generated)),
                }
            )
            with self.assertRaisesRegex(Exception, "identity mismatch"):
                axiom_audit.proof_generated_project_dependencies(
                    project_identities,
                    baseline_identities,
                    hostile_observations,
                    expected,
                    state,
                    checked,
                )
            axiom_audit.validate_report_inventory(
                inventory,
                lock=experiment.load_toolchain_lock(),
                compiler_assumptions=state["compiler_assumptions"],
                require_complete=True,
                expected_scope_sha256=axiom_audit.inventory_scope_sha256(
                    inventory
                ),
                expected_identity_sha256=axiom_audit.inventory_identity_sha256(
                    inventory
                ),
                accepted_native_decide_uses=accepted_uses,
                hidden_native_decide_uses=hidden_uses,
                required_native_uses=all_uses,
            )

    def test_parameterized_type_binding_is_checked_by_lean(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        state = {
            "frozen_contracts": {
                "Demo.parameterized": {
                    "canon": "theorem Demo.parameterized (unused : Nat) : True"
                }
            }
        }
        expected = [
            {
                "declaration": "Demo.parameterized",
                "origin": "accepted_spec",
                "type_sha256": "0" * 64,
                "dependencies": [],
                "axioms": [],
                "native_decide_uses": [],
            }
        ]
        program = axiom_audit.audit_program(
            expected,
            bindings=axiom_audit.type_bindings(state, {"leaves": []}),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            reference = root / axiom_audit.REFERENCE_SOURCE
            reference.write_text(
                "namespace Demo\n"
                "theorem parameterized (unused : Nat) : True := by trivial\n"
                "end Demo\n"
            )
            audit = root / axiom_audit.AUDIT_SOURCE
            audit.write_bytes(program)
            compiled = subprocess.run(
                [
                    lean,
                    "-R",
                    ".",
                    "-o",
                    reference.with_suffix(".olean").name,
                    reference.name,
                ],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            shutil.copyfile(
                root / reference.with_suffix(".olean").name,
                lake_dir / axiom_audit.REFERENCE_OLEAN.rsplit("/", 1)[1],
            )
            bindings = axiom_audit.type_bindings(state, {"leaves": []})
            expected_source = root / axiom_audit.EXPECTED_SOURCE
            expected_source.write_bytes(axiom_audit.expected_program([], bindings))
            expected_built = subprocess.run(
                [lean, "-R", ".", "-o", "AutoFVExpected.olean", expected_source.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(
                expected_built.returncode, 0, expected_built.stderr.decode()
            )
            baseline_dir = root / ".autofv-baseline"
            baseline_dir.mkdir()
            shutil.copyfile(
                root / "AutoFVExpected.olean",
                baseline_dir / "AutoFVExpected.olean",
            )
            checked = subprocess.run(
                [lean, "-R", ".", "--run", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(
                checked.returncode,
                0,
                (checked.stdout + checked.stderr).decode(),
            )
            identity = axiom_audit.parse_kernel_identities(
                checked.stdout,
                checked.stderr,
                ["Demo.parameterized"],
            )["Demo.parameterized"]
            self.assertTrue(identity["type_repr"])
            self.assertIn("Demo.parameterized", identity["dependencies"])

    def test_type_substituted_transferred_declaration_is_rejected(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        expected = axiom_audit.expected_inventory(state, reference)
        program = axiom_audit.audit_program(
            expected,
            bindings=axiom_audit.type_bindings(state, reference),
        )
        expected_program = axiom_audit.expected_program(
            [], axiom_audit.type_bindings(state, reference)
        )
        self.assertIn(b"axiom AutoFVExpectedAccepted0", expected_program)
        self.assertIn(
            b"(`AutoFVExpectedAccepted0, `Diamond.left_spec)",
            program,
        )
        self.assertNotIn(b"exact Diamond.left_spec", program)

        calls = []

        def docker(*argv, **_kwargs):
            calls.append(argv)
            if "cat" in argv:
                return subprocess.CompletedProcess(argv, 0, b"substituted-type-olean", b"")
            if axiom_audit.AUDIT_SOURCE in argv:
                return subprocess.CompletedProcess(argv, 1, b"", b"type mismatch")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with self.assertRaisesRegex(Exception, "kernel axiom audit failed"):
            axiom_audit.audit_artifacts(
                image="fixture-image",
                witness_volume="witness",
                audit_volume="trusted-audit",
                artifacts=[".lake/build/lib/lean/Diamond/Left.olean"],
                expected=expected,
                runtime="runsc-hardened",
                max_artifact_bytes=1024,
                docker=docker,
                runtime_argv=lambda _image, volume, *command, **_: (
                    "run",
                    volume,
                    *command,
                ),
                seed_file=lambda *_args, **_kwargs: None,
            )
        self.assertTrue(any(axiom_audit.AUDIT_SOURCE in call for call in calls))
        self.assertIn(
            b"axiom AutoFVExpectedAccepted0 (n : Nat) : "
            b"Diamond.left n = Nat.succ n",
            expected_program,
        )

    def test_imported_definition_body_and_closure_must_match_baseline(self):
        baseline = {
            "Diamond.left": {
                "type_repr": "Nat -> Nat",
                "value_repr": "fun n => n + 1",
                "dependencies": ["Nat.add"],
            },
            "Diamond.left_spec": {
                "type_repr": "forall n, left n = n + 1",
                "value_repr": "sorryAx",
                "dependencies": ["Diamond.left", "sorryAx"],
            },
        }
        accepted = copy.deepcopy(baseline)
        accepted["Diamond.left_spec"]["value_repr"] = "proof"
        accepted["Diamond.left_spec"]["dependencies"] = ["Diamond.left"]
        axiom_audit.compare_kernel_identities(
            baseline,
            accepted,
            frozen_types={"Diamond.left_spec"},
            frozen_definitions={"Diamond.left"},
        )
        for mutation in ("body", "closure"):
            hostile = copy.deepcopy(accepted)
            if mutation == "body":
                hostile["Diamond.left"]["value_repr"] = "fun n => n + 2"
            else:
                hostile["Diamond.left"]["dependencies"] = ["Nat.mul"]
            with self.subTest(mutation=mutation), self.assertRaises(
                Exception
            ):
                axiom_audit.compare_kernel_identities(
                    baseline,
                    hostile,
                    frozen_types={"Diamond.left_spec"},
                    frozen_definitions={"Diamond.left"},
                )


if __name__ == "__main__":
    unittest.main()
