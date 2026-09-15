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
    def test_generated_auditors_load_candidate_modules_as_inert_data(self):
        expected = [
            {
                "declaration": "Demo.finished",
                "origin": "accepted_spec",
                "type_sha256": "0" * 64,
                "semantic_dependencies": [],
                "dependencies": [],
                "axioms": [],
                "native_decide_uses": [],
            }
        ]
        ordinary = axiom_audit.audit_program(
            expected, project_modules=["Demo"]
        )
        counterexample = axiom_audit.counterexample_audit_program(
            module="AutoFVCounterexample",
            theorem="AutoFV.counterexample",
            proposition="True",
            baseline_modules=["Demo"],
        )
        for program, forbidden_import in (
            (ordinary, b"import AutoFVReferenceCheck"),
            (counterexample, b"import AutoFVCounterexample"),
        ):
            self.assertNotIn(forbidden_import, program)
            self.assertIn(b"(plugins := #[]) (loadExts := false)", program)
            self.assertIn(b"def main", program)

    def test_unchanged_baseline_helper_reaching_stub_is_fresh_replayed(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            source = root / "Demo.lean"
            source.write_text(
                "namespace Demo\n"
                "axiom stub : True\n"
                "theorem helper : True := stub\n"
                "axiom result : True\n"
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
            source.write_text(
                "namespace Demo\n"
                "theorem stub : True := by trivial\n"
                "theorem helper : True := stub\n"
                "theorem result : True := helper\n"
                "end Demo\n"
            )
            candidate = subprocess.run(
                [lean, "-R", ".", "-o", "Demo.olean", source.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(candidate.returncode, 0, candidate.stderr.decode())
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            shutil.copyfile(root / "Demo.olean", lake_dir / "Demo.olean")
            audit = root / axiom_audit.AUDIT_SOURCE
            audit.write_text(
                axiom_audit._audit_prelude(
                    ["Demo"],
                    ["Demo"],
                    ["Demo"],
                    forced_replay=["Demo.stub", "Demo.result"],
                    preserved_baseline=True,
                )
                + "def main : IO Unit := autofvAuditRunIO "
                "[`Demo.result] [`Demo.result]\n"
            )
            checked = subprocess.run(
                [lean, "-R", ".", "--run", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
        output = (checked.stdout + checked.stderr).decode()
        self.assertEqual(checked.returncode, 0, output)
        _replayed, kernel_checked, _baseline_bound = (
            axiom_audit.parse_kernel_replay_provenance(
                checked.stdout, checked.stderr
            )
        )
        self.assertIn("Demo.helper", kernel_checked)
        marker = re.search(r"AUTOFV_CHECKED_DEPS:Demo\.result:([^\n]*)", output)
        self.assertIsNotNone(marker, output)
        checked_dependencies = set(marker.group(1).split(","))
        self.assertIn("AutoFVKernelChecked.Demo.stub", checked_dependencies)
        self.assertIn("AutoFVKernelChecked.Demo.helper", checked_dependencies)
        self.assertNotIn("Demo.stub", checked_dependencies)
        self.assertNotIn("sorryAx", checked_dependencies)

    def test_checked_replay_rejects_sorry_axiom_in_full_closure(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            source = root / "Demo.lean"
            source.write_text(
                "namespace Demo\n"
                "theorem unfinished : True := by sorry\n"
                "end Demo\n"
            )
            compiled = subprocess.run(
                [lean, "-R", ".", "-o", "Demo.olean", source.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            shutil.copyfile(root / "Demo.olean", lake_dir / "Demo.olean")
            audit = root / axiom_audit.AUDIT_SOURCE
            audit.write_text(
                axiom_audit._audit_prelude(
                    ["Demo"],
                    [],
                    ["Demo"],
                    forced_replay=["Demo.unfinished"],
                )
                + "def main : IO Unit := autofvAuditRunIO "
                "[`Demo.unfinished] [`Demo.unfinished]\n"
            )
            checked = subprocess.run(
                [lean, "-R", ".", "--run", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
        output = (checked.stdout + checked.stderr).decode()
        self.assertNotEqual(checked.returncode, 0, output)
        self.assertIn("checked closure retained untrusted dependency", output)

    def test_unfinished_parameterized_target_does_not_taint_trusted_reference(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        statement = "forall input : Nat, Demo.value input = input"
        proof = "by\n  intro input\n  rfl"
        reference = {
            "leaves": [
                {
                    "declaration": "Demo.value",
                    "spec": "Demo.unfinished",
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            source = root / "Demo.lean"
            source.write_text(
                "namespace Demo\n"
                "inductive Flag where\n"
                "  | off\n"
                "  | on\n"
                "def flip : Flag \u2192 Flag\n"
                "  | .off => .on\n"
                "  | .on => .off\n"
                "def value (input : Nat) : Nat := input\n"
                "theorem unfinished (input : Nat) : value input = input := by\n"
                "  sorry\n"
                "end Demo\n"
            )
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
            baseline_dir = root / ".autofv-baseline"
            baseline_dir.mkdir()
            shutil.copyfile(root / "Demo.olean", baseline_dir / "Demo.olean")
            expected = [
                {
                    "declaration": declaration,
                    "origin": origin,
                    "type_sha256": "0" * 64,
                    "semantic_dependencies": [],
                    "dependencies": [],
                    "axioms": [],
                    "native_decide_uses": [],
                }
                for declaration, origin in (
                    ("Demo.unfinished", "accepted_spec"),
                    ("AutoFVVerifier.hidden_0", "hidden_reference"),
                    ("AutoFVVerifier.meaning_0", "meaning_check"),
                )
            ]
            bindings = axiom_audit.type_bindings(
                {
                    "frozen_contracts": {
                        "Demo.unfinished": {
                            "canon": (
                                "theorem Demo.unfinished (input : Nat) : "
                                "Demo.value input = input"
                            )
                        }
                    }
                },
                reference,
            )
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
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            shutil.copyfile(root / "Demo.olean", lake_dir / "Demo.olean")
            shutil.copyfile(
                root / axiom_audit.REFERENCE_OLEAN.rsplit("/", 1)[1],
                root / axiom_audit.REFERENCE_OLEAN,
            )
            kernel_audit = root / axiom_audit.AUDIT_SOURCE
            kernel_audit.write_bytes(
                axiom_audit.audit_program(
                    expected,
                    bindings=bindings,
                    project_modules=["Demo"],
                    permitted_incomplete_accepted=["Demo.unfinished"],
                )
            )
            audited = subprocess.run(
                [lean, "-R", ".", "--run", kernel_audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            self.assertEqual(
                audited.returncode,
                0,
                (audited.stdout + audited.stderr).decode(),
            )
            try:
                replayed, checked, baseline_bound = (
                    axiom_audit.parse_kernel_replay_provenance(
                    audited.stdout, audited.stderr
                    )
                )
                project_identities = axiom_audit.parse_project_kernel_identities(
                    audited.stdout,
                    audited.stderr,
                    ["AutoFVVerifier.hidden_0"],
                )
            except Exception as exc:
                self.fail(f"{exc}\n{(audited.stdout + audited.stderr).decode()}")
            self.assertIn("Demo.value", project_identities)
            self.assertIn("Demo.Flag", replayed)
            self.assertIn("Demo.flip", replayed)
            self.assertIn("Demo.Flag", baseline_bound)
            self.assertIn("Demo.flip", baseline_bound)
            self.assertIn("Demo.unfinished", checked)
            self.assertNotIn("Demo.unfinished", baseline_bound)
            inventory = axiom_audit.parse_inventory(
                audited.stdout, audited.stderr, expected
            )
            accepted = next(
                record
                for record in inventory
                if record["declaration"] == "Demo.unfinished"
            )
            self.assertEqual(accepted["origin"], "accepted_spec")
            self.assertEqual(accepted["axioms"], ["sorryAx"])
            accepted_identity = axiom_audit.parse_kernel_identities(
                audited.stdout, audited.stderr, ["Demo.unfinished"]
            )["Demo.unfinished"]
            self.assertIn("sorryAx", accepted_identity["dependencies"])
            self.assertEqual(
                next(
                    record["axioms"]
                    for record in inventory
                    if record["declaration"] == "AutoFVVerifier.hidden_0"
                ),
                [],
            )
            self.assertEqual(
                next(
                    record["axioms"]
                    for record in inventory
                    if record["declaration"] == "AutoFVVerifier.meaning_0"
                ),
                [],
            )
            audit = root / "ReferenceAxioms.lean"
            audit.write_text(
                "import AutoFVReferenceCheck\n"
                "#print axioms Demo.unfinished\n"
                "#print axioms AutoFVVerifier.hidden_0\n"
                "#print axioms AutoFVVerifier.meaning_0\n"
            )
            checked = subprocess.run(
                [lean, "-R", ".", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
            output = (checked.stdout + checked.stderr).decode()
            self.assertEqual(checked.returncode, 0, output)
            self.assertIn("'Demo.unfinished' depends on axioms: [sorryAx]", output)
            self.assertIn(
                "'AutoFVVerifier.hidden_0' does not depend on any axioms", output
            )
            self.assertIn(
                "'AutoFVVerifier.meaning_0' does not depend on any axioms", output
            )

    def test_full_kernel_closure_includes_transitive_unlisted_project_helpers(self):
        program = axiom_audit.audit_program([], project_modules=["Demo"])
        self.assertNotIn(b".filter autofvAuditInteresting", program)
        self.assertIn(b"AUTOFV_PROJECT_DEPS", program)
        baseline = (
            b"AUTOFV_TYPE_BEGIN:Demo.root\ntype-root\n"
            b"AUTOFV_TYPE_END:Demo.root\n"
            b"AUTOFV_VALUE_BEGIN:Demo.root\nvalue-root\n"
            b"AUTOFV_VALUE_END:Demo.root\n"
            b"AUTOFV_DEPS:Demo.root:Demo.helper,Demo.root,Nat.add\n"
            b"AUTOFV_PROJECT_DEPS:Demo.root:Demo.helper,Demo.root\n"
            b"AUTOFV_TYPE_BEGIN:Demo.helper\ntype-helper\n"
            b"AUTOFV_TYPE_END:Demo.helper\n"
            b"AUTOFV_VALUE_BEGIN:Demo.helper\nvalue-helper\n"
            b"AUTOFV_VALUE_END:Demo.helper\n"
            b"AUTOFV_DEPS:Demo.helper:Demo.helper,Nat.add\n"
            b"AUTOFV_PROJECT_DEPS:Demo.helper:Demo.helper\n"
        )
        accepted = baseline.replace(b"value-helper", b"hostile-helper")
        baseline_identities = axiom_audit.parse_project_kernel_identities(
            baseline, b"", ["Demo.root"]
        )
        accepted_identities = axiom_audit.parse_project_kernel_identities(
            accepted, b"", ["Demo.root"]
        )
        with self.assertRaisesRegex(Exception, "identity mismatch"):
            axiom_audit.compare_kernel_identities(
                baseline_identities,
                accepted_identities,
                frozen_types=set(),
                frozen_definitions=set(baseline_identities),
            )

    def test_kernel_replay_rejects_an_invalid_serialized_definition_body(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        program = axiom_audit._audit_prelude([], [], []) + (
            "run_cmd do\n"
            "  let invalid : DefinitionVal := {\n"
            "    name := `AutoFV.invalidSerializedBody\n"
            "    levelParams := []\n"
            "    type := mkConst ``Nat\n"
            "    value := mkConst ``True\n"
            "    hints := .regular 0\n"
            "    safety := .safe\n"
            "  }\n"
            "  let constants : Std.HashMap Name ConstantInfo := {}\n"
            "  let constants := constants.insert invalid.name "
            "(.defnInfo invalid)\n"
            "  discard <| autofvAuditReplayConstants constants "
            "[invalid.name]\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            source = root / "InvalidReplay.lean"
            source.write_text(program)
            checked = subprocess.run(
                [lean, source.name], cwd=source.parent, capture_output=True
            )
        output = (checked.stdout + checked.stderr).decode()
        self.assertNotEqual(checked.returncode, 0, output)
        self.assertIn("invalidSerializedBody", output)
        self.assertRegex(output, r"kernel|type mismatch")

    def test_counterexample_native_artifact_is_kernel_replayed(self):
        lean = shutil.which("lean")
        if lean is None:
            self.skipTest("Lean is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lean-toolchain").write_text(
                (Path(__file__).parent / "fixtures/diamond/lean-toolchain").read_text()
            )
            env = {**os.environ, "LEAN_PATH": str(root)}
            (root / "Demo.lean").write_text(
                "namespace Demo\n"
                "def value (input : Nat) : Nat := input\n"
                "end Demo\n"
            )
            (root / "AutoFVCounterexample.lean").write_text(
                "import Demo\n"
                "namespace AutoFV\n"
                "theorem counterexample : Demo.value 3 = 3 := by\n"
                "  native_decide\n"
                "end AutoFV\n"
            )
            for module in ("Demo", "AutoFVCounterexample"):
                compiled = subprocess.run(
                    [lean, "-R", ".", "-o", f"{module}.olean", f"{module}.lean"],
                    cwd=root,
                    capture_output=True,
                    env=env,
                )
                self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            lake_dir = root / ".lake/build/lib/lean"
            lake_dir.mkdir(parents=True)
            for module in ("Demo", "AutoFVCounterexample"):
                shutil.copyfile(root / f"{module}.olean", lake_dir / f"{module}.olean")
            expected_source = root / axiom_audit.EXPECTED_SOURCE
            expected_source.write_bytes(
                axiom_audit.expected_program(
                    ["Demo"],
                    [
                        "axiom AutoFVExpectedCounterexample : Demo.value 3 = 3",
                        "#autofv_same_type AutoFVExpectedCounterexample "
                        "AutoFV.counterexample",
                    ],
                )
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
            baseline_dir = root / ".autofv-baseline"
            baseline_dir.mkdir()
            shutil.copyfile(
                root / "AutoFVExpected.olean",
                baseline_dir / "AutoFVExpected.olean",
            )
            audit = root / "AutoFVCounterexampleAudit.lean"
            audit.write_bytes(
                axiom_audit.counterexample_audit_program(
                    module="AutoFVCounterexample",
                    theorem="AutoFV.counterexample",
                    proposition="Demo.value 3 = 3",
                    baseline_modules=["Demo"],
                )
            )
            checked = subprocess.run(
                [lean, "-R", ".", "--run", audit.name],
                cwd=root,
                capture_output=True,
                env=env,
            )
        output = (checked.stdout + checked.stderr).decode()
        self.assertEqual(checked.returncode, 0, output)
        replayed, kernel_checked, baseline_bound = (
            axiom_audit.parse_kernel_replay_provenance(
                checked.stdout, checked.stderr
            )
        )
        self.assertIn("AutoFV.counterexample", replayed)
        self.assertIn("AutoFV.counterexample", kernel_checked)
        self.assertNotIn("AutoFV.counterexample", baseline_bound)
        self.assertIn("Lean.trustCompiler", output)


if __name__ == "__main__":
    unittest.main()
