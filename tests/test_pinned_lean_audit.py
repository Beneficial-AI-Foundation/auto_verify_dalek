"""Real pinned-Lean P1 audit through the production volume orchestration.

`prepare_auditor` and `audit_artifacts` run unchanged; only Docker is replaced by
local execution, so this checks the generated programs on Dalek's Lean v4.31.0
rather than the older fixture toolchain.  runsc isolation is not exercised here.
"""

import copy
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from autofv import axiom_audit, contracts, reviewed_snapshot, verifier
from autofv.lean_kernel_audit import parse_kernel_replay_provenance

LEAN = Path.home() / ".elan/toolchains/leanprover--lean4---v4.31.0/bin/lean"
BASELINE = (
    "namespace Demo\n"
    "def value (n : Nat) : Nat := n + 0\n"
    "theorem root_spec : value 2 = 2 := by sorry\n"
    "end Demo\n"
)
HELPER = "theorem value_spec (n : Nat) : value n = n := rfl\n"
BUILD = [
    "sh", "-eu", "-c",
    f'mkdir -p .lake/build/lib/lean; '
    f'if test -f Library.lean; then "{LEAN}" -o .lake/build/lib/lean/Library.olean Library.lean; fi; '
    f'"{LEAN}" -o .lake/build/lib/lean/Demo.olean Demo.lean',
]
STATE = {
    "graph": {
        "selected_nodes": ["probe:Demo.root", "probe:Demo.value"],
        "frozen_targets": ["probe:Demo.root"],
        "source_paths": {"probe:Demo.root": "Demo.lean", "probe:Demo.value": "Demo.lean"},
        "term_dependencies": [["probe:Demo.root", "probe:Demo.value"]],
        "type_dependencies": [],
    },
    "frozen_contracts": {
        "Demo.value_spec": {"canon": "theorem Demo.value_spec (n : Nat) : Demo.value n = n"}
    },
    "native_decide_uses": [],
    "partial_target": "probe:Demo.value",
}
FORGE = r"""
import Lean
open Lean
def main : IO Unit := do
  let path : System.FilePath := ".lake/build/lib/lean/Demo.olean"
  let (data, _) ← readModuleData path
  let constants := data.constants.map fun
    | .thmInfo info => if info.name == `Demo.value_spec then
        .thmInfo { info with value := mkConst ``Nat.zero } else .thmInfo info
    | info => info
  IO.FS.removeFile path
  saveModuleData path `Demo { data with constants }
"""


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
    ).stdout.strip()


class PinnedLeanPartialAuditTests(unittest.TestCase):
    def setUp(self):
        if not LEAN.exists():
            self.skipTest("pinned Lean v4.31.0 is unavailable")
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)

    def _local(self, volume: str) -> Path:
        return self.root / "volumes" / volume

    def runtime_argv(self, image, volume, *command, workdir="/project", **_options):
        return (volume, workdir, *command)

    def docker(self, volume, workdir, *command, **_options):
        local = str(self._local(volume))
        if command[:3] == ("lake", "env", "lean"):
            command = (str(LEAN), *command[3:])
        argv = [part.replace("/project", local) for part in command]
        repo = self._local(volume) / "repo"
        completed = subprocess.run(
            argv, cwd=workdir.replace("/project", local), capture_output=True, timeout=30,
            env={**os.environ, "LEAN_NUM_THREADS": "1", "LEAN_PATH": ":".join(
                map(str, [repo / ".lake/build/lib/lean", *getattr(self, "extra_libs", [])]))},
        )
        if completed.returncode:
            raise contracts.ContractError(
                "local docker failed: " + (completed.stdout + completed.stderr).decode()[-3000:]
            )
        if b"AUTOFV_REPLAYED:" in completed.stdout:
            self.replay_provenance = parse_kernel_replay_provenance(
                completed.stdout, completed.stderr
            )
        return completed

    def seed_file(self, image, volume, path, raw, *, runtime, allowed_paths=frozenset()):
        target = self._local(volume) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o644)
        target.write_bytes(raw)
        target.chmod(0o444)

    def _audit(self, candidate: str, *, forge: bool = False, canon: str | None = None,
               baseline: str = BASELINE, reviewed: str | None = None,
               baseline_files: dict[str, str] | None = None, forge_program: str = FORGE) -> list[dict]:
        state = copy.deepcopy(STATE)
        if canon is not None:
            state["frozen_contracts"]["Demo.value_spec"]["canon"] = canon
        source = self.root / "source"
        source.mkdir()
        _git(source, "init", "-q")
        (source / "Demo.lean").write_text(baseline)
        for path, content in (baseline_files or {}).items():
            (source / path).write_text(content)
        _git(source, "add", "Demo.lean", *(baseline_files or {}))
        _git(source, "commit", "-qm", "baseline")
        base = _git(source, "rev-parse", "HEAD")
        (source / "Demo.lean").write_text(candidate)
        _git(source, "commit", "-qam", "candidate")
        accepted = _git(source, "rev-parse", "HEAD")
        _git(source, "tag", "base", base)
        _git(source, "tag", "accepted", accepted)
        _git(source, "bundle", "create", "-q", str(self.root / "repo.bundle"), "--all")
        bundle = (self.root / "repo.bundle").read_bytes()
        for volume in ("audit", "witness", "reviewed"):
            self._local(volume).mkdir(parents=True)
        seams = {"docker": self.docker, "runtime_argv": self.runtime_argv,
                 "seed_file": self.seed_file}
        def prepare_reviewed():
            if reviewed is None:
                return {}
            return {"Demo.value_spec": axiom_audit.prepare_reviewed_artifact(
                image="local", volume="reviewed", audit_volume="audit", repository_bundle=bundle,
                base_commit=base, verify_command=BUILD, declaration="Demo.value_spec",
                contract=state["frozen_contracts"]["Demo.value_spec"], runtime="runsc-hardened", **seams)}
        if reviewed is not None:
            record = state["frozen_contracts"]["Demo.value_spec"]
            record["reviewed_snapshot"] = reviewed_snapshot.make(
                declaration="Demo.value_spec", canon=record["canon"], path="Demo.lean", source=reviewed,
                baseline_source=baseline, base_commit=base, review_sha256="e" * 64)
        reference = {"leaves": []}
        expected = axiom_audit.expected_inventory(state, reference)
        identities = axiom_audit.prepare_auditor(
            image="local", volume="audit", repository_bundle=bundle, base_commit=base,
            verify_command=BUILD, expected=expected, state=state, reference=reference,
            runtime="runsc-hardened", prepare_reviewed=prepare_reviewed, **seams,
        )
        axiom_audit.checkout_volume(
            image="local", volume="witness", repository_bundle=bundle, commit=accepted,
            runtime="runsc-hardened", **seams,
        )
        self.docker(*self.runtime_argv("local", "witness", *BUILD, workdir="/project/repo"))
        if forge:
            (self._local("witness") / "repo/Forge.lean").write_text(forge_program)
            self.docker("witness", "/project/repo", "lake", "env", "lean", "--run", "Forge.lean")
        self.seed_file(
            "local", "witness", f"repo/{axiom_audit.REFERENCE_SOURCE}",
            axiom_audit.reference_program(reference, allow_empty=True), runtime="runsc-hardened",
        )
        self.docker(
            "witness", "/project/repo", "lake", "env", "lean", "-o",
            axiom_audit.REFERENCE_OLEAN, axiom_audit.REFERENCE_SOURCE,
        )
        return axiom_audit.audit_artifacts(
            image="local", witness_volume="witness", audit_volume="audit",
            artifacts=axiom_audit.olean_paths(state["graph"]), expected=expected,
            state=state, reference=reference, baseline_identities=identities,
            runtime="runsc-hardened", max_artifact_bytes=32 * 1024 * 1024, **seams,
        )

    def test_expected_type_preserves_namespace_open_and_type_alias_context(self):
        baseline = ("namespace Types\nabbrev Word := Nat\nend Types\n" +
                    BASELINE.replace("namespace Demo\n", "namespace Demo\nopen Types\n"))
        helper = HELPER.replace("(n : Nat)", "(n : Word)")
        inventory = self._audit(baseline.replace("end Demo", helper + "end Demo"), baseline=baseline,
            canon="theorem Demo.value_spec (n : Word) : value n = n",
            reviewed=baseline.replace("end Demo", helper.replace(":= rfl", ":= by sorry") + "end Demo"))
        self.assertEqual([(r["declaration"], r["axioms"]) for r in inventory], [("Demo.value_spec", [])])

    def test_expected_type_preserves_scoped_notation_context(self):
        baseline = BASELINE.replace("theorem root_spec", 'scoped notation "⟪" n "⟫" => value n\nopen scoped Demo\ntheorem root_spec')
        helper = HELPER.replace("value n = n", "⟪ n ⟫ = n")
        inventory = self._audit(baseline.replace("end Demo", helper + "end Demo"), baseline=baseline,
            canon="theorem Demo.value_spec (n : Nat) : ⟪ n ⟫ = n",
            reviewed=baseline.replace("end Demo", helper.replace(":= rfl", ":= by sorry") + "end Demo"))
        self.assertEqual([(r["declaration"], r["axioms"]) for r in inventory], [("Demo.value_spec", [])])

    def test_project_syntax_cannot_reparse_the_trusted_audit_library(self):
        packages = Path.cwd() / "ledger/phase-02/preparation/lake-cache/packages"
        aeneas = packages / "aeneas/backends/lean/.lake/build/lib/lean"
        if not (aeneas / "Aeneas.olean").exists():
            self.skipTest("existing Aeneas cache is unavailable; never download it")
        self.extra_libs = [aeneas, *[packages / p / ".lake/build/lib/lean" for p in
            ("mathlib", "batteries", "Qq", "aesop", "proofwidgets", "importGraph", "LeanSearchClient", "plausible", "Cli", "PrimeCert")]]
        baseline = "import Aeneas\n" + BASELINE
        reviewed = baseline.replace("end Demo", HELPER.replace(":= rfl", ":= by sorry") + "end Demo")
        inventory = self._audit(baseline.replace("end Demo", HELPER + "end Demo"), baseline=baseline,
            reviewed=reviewed, canon="theorem Demo.value_spec (n : Nat) : value n = n")
        self.assertFalse(inventory[0]["axioms"])

    def test_expected_type_preserves_section_variables_and_local_instances(self):
        cases = [
            ("namespace Demo\nvariable {α : Type} [Inhabited α]\n"
             "def value (x : α) := x\ntheorem root_spec : value (2 : Nat) = 2 := by sorry\nend Demo\n",
             "theorem value_spec : value (default : α) = default := rfl\n",
             "theorem Demo.value_spec : value (default : α) = default"),
            (BASELINE.replace("theorem root_spec", "local instance custom : Inhabited Nat := ⟨0⟩\ntheorem root_spec"),
             "theorem value_spec : value (default : Nat) = 0 := rfl\n",
             "theorem Demo.value_spec : value (default : Nat) = 0"),
        ]
        for baseline, helper, canon in cases:
            with self.subTest(canon=canon):
                self.setUp()
                inventory = self._audit(baseline.replace("end Demo", helper + "end Demo"), baseline=baseline,
                    canon=canon, reviewed=baseline.replace("end Demo", helper.replace(":= rfl", ":= by sorry") + "end Demo"))
                self.assertEqual([r["declaration"] for r in inventory], ["Demo.value_spec"])
                self.assertFalse(inventory[0]["axioms"])

    def test_reviewed_context_keeps_helper_and_target_integrity_checks(self):
        reviewed = BASELINE.replace("end Demo", HELPER.replace(":= rfl", ":= by sorry") + "end Demo")
        canon = "theorem Demo.value_spec (n : Nat) : value n = n"
        good = "theorem aux (n : Nat) : value n = n := rfl\n" + HELPER.replace("rfl", "aux n")
        inventory = self._audit(BASELINE.replace("end Demo", good + "end Demo"), canon=canon, reviewed=reviewed)
        self.assertFalse(inventory[0]["axioms"])
        for helper, failure in (
            (HELPER.replace("value n = n", "value n = value n"), "audited declaration type mismatch"),
            ("theorem aux (n : Nat) : value n = n := by sorry\n" + HELPER.replace("rfl", "aux n"), "untrusted dependency"),
            ("axiom aux (n : Nat) : value n = n\n" + HELPER.replace("rfl", "aux n"), "unapproved transferred axiom"),
            ("-- required target deliberately missing\n", "forced kernel replay declaration is absent"),
        ):
            with self.subTest(failure=failure):
                self.setUp()
                with self.assertRaisesRegex(contracts.ContractError, failure):
                    self._audit(BASELINE.replace("end Demo", helper + "end Demo"), canon=canon, reviewed=reviewed)

    def test_unchanged_public_text_does_not_authorize_changed_meaning_definition(self):
        baseline = BASELINE.replace("theorem root_spec", "def expected (n : Nat) := n + 0\ntheorem root_spec")
        helper = "theorem value_spec (n : Nat) : value n = expected n := rfl\n"
        reviewed = baseline.replace("end Demo", helper.replace(":= rfl", ":= by sorry") + "end Demo")
        candidate = baseline.replace("def expected (n : Nat) := n + 0", "def expected (n : Nat) := 0 + n")
        candidate = candidate.replace("end Demo", helper.replace(":= rfl", ":= by simp [value, expected]") + "end Demo")
        with self.assertRaisesRegex(contracts.ContractError, "kernel declaration identity mismatch"):
            self._audit(candidate, baseline=baseline, reviewed=reviewed,
                canon="theorem Demo.value_spec (n : Nat) : value n = expected n")

    def test_forged_project_artifact_cannot_shadow_a_pristine_library_definition(self):
        baseline = "import Library\n" + BASELINE.replace("n + 0", "0")
        helper = "theorem value_spec (n : Nat) : value n = Library.rhs n := by sorry\n"
        forge = r'''
import Lean
open Lean
def main : IO Unit := do
  let path : System.FilePath := ".lake/build/lib/lean/Demo.olean"
  let (data, _) ← readModuleData path
  let (library, _) ← readModuleData ".lake/build/lib/lean/Library.olean"
  let some (.defnInfo rhs) := library.constants.find? (fun i => i.name == `Library.rhs)
    | throw <| IO.userError "fixture definition missing"
  let fake := ConstantInfo.defnInfo { rhs with value := mkLambda `n .default (mkConst ``Nat) (mkNatLit 0) }
  let constants := data.constants.map fun
    | .thmInfo info => if info.name == `Demo.value_spec then
        .thmInfo { info with value := mkLambda `n .default (mkConst ``Nat) (mkApp2 (mkConst ``Eq.refl [.succ .zero]) (mkConst ``Nat) (mkNatLit 0)) } else .thmInfo info
    | info => info
  IO.FS.removeFile path
  saveModuleData path `Demo { data with constNames := #[`Library.rhs] ++ data.constNames, constants := #[fake] ++ constants }
'''
        with self.assertRaisesRegex(contracts.ContractError, "pristine dependency mismatch Library.rhs"):
            self._audit(baseline.replace("end Demo", helper + "end Demo"), baseline=baseline,
                reviewed=baseline.replace("end Demo", helper + "end Demo"),
                canon="theorem Demo.value_spec (n : Nat) : value n = Library.rhs n",
                baseline_files={"Library.lean": "def Library.rhs (n : Nat) := n + 1\n"},
                forge=True, forge_program=forge)

    def test_required_closure_ignores_unused_development_hole(self):
        candidate = BASELINE.replace(
            "end Demo", HELPER + "theorem unfinished : False := by sorry\nend Demo"
        )
        inventory = self._audit(candidate)
        self.assertEqual(inventory[0]["axioms"], [])
        self.assertNotIn("Demo.unfinished", inventory[0]["dependencies"])
        replayed, checked, baseline_bound = self.replay_provenance
        self.assertIn("Demo.value_spec", checked)
        self.assertIn("Demo.value", baseline_bound)
        self.assertNotIn("Demo.unfinished", replayed | checked | baseline_bound)

    def test_unused_changed_helper_is_not_reported_as_baseline_bound(self):
        baseline = BASELINE.replace("end Demo", "def unused : Nat := 1\nend Demo")
        candidate = baseline.replace("unused : Nat := 1", "unused : Nat := 2")
        inventory = self._audit(candidate.replace("end Demo", HELPER + "end Demo"),
                                baseline=baseline)
        self.assertEqual(inventory[0]["axioms"], [])
        replayed, checked, baseline_bound = self.replay_provenance
        self.assertNotIn("Demo.unused", replayed | checked | baseline_bound)

    def test_existing_nonmeaning_helper_can_be_used_or_revised(self):
        baseline = BASELINE.replace(
            "end Demo", "theorem helper (n : Nat) : value n = n := rfl\nend Demo"
        )
        for proof in ("rfl", "by exact Eq.symm (Eq.refl n)"):
            with self.subTest(proof=proof):
                self.setUp()
                candidate = baseline.replace(":= rfl", ":= " + proof).replace(
                    "end Demo", HELPER.replace("rfl", "by exact helper n") + "end Demo"
                )
                if proof != "rfl":
                    candidate = candidate.replace(
                        "theorem helper (n : Nat) : value n = n",
                        "theorem helper (n : Nat) : value n + 0 = n",
                    )
                inventory = self._audit(candidate, baseline=baseline)
                self.assertEqual(inventory[0]["axioms"], [])
                self.assertIn("Demo.helper", inventory[0]["dependencies"])

    def test_missing_transferred_helper_cannot_fall_back_to_pristine(self):
        baseline = BASELINE.replace(
            "end Demo", "theorem helper (n : Nat) : value n = n := rfl\nend Demo"
        )
        candidate = baseline.replace(
            "end Demo", HELPER.replace("rfl", "by exact helper n") + "end Demo"
        )
        start = FORGE.index("  let constants :=")
        end = FORGE.index("  IO.FS.removeFile")
        forge = FORGE[:start] + (
            "  let constants := data.constants.filter (fun info => info.name != `Demo.helper)\n"
        ) + FORGE[end:].replace(
            "{ data with constants }",
            "{ data with constants, constNames := data.constNames.filter (· != `Demo.helper) }",
        )
        with self.assertRaisesRegex(contracts.ContractError, "missing transferred dependency Demo.helper"):
            self._audit(candidate, baseline=baseline, forge=True, forge_program=forge)

    def test_new_helper_is_kernel_checked_against_pristine_baseline(self):
        candidate = BASELINE.replace("end Demo", HELPER + "end Demo")
        inventory = self._audit(candidate)
        self.assertEqual(
            [(record["declaration"], record["axioms"]) for record in inventory],
            [("Demo.value_spec", [])],
        )

    def test_tactic_generated_auxiliary_declarations_are_accepted(self):
        for proof in (
            "by simp [value]",
            "by unfold value; omega",
            "by rw [value.eq_def]; simp",
            "match n with\n  | 0 => rfl\n  | _ + 1 => rfl",
            "by\n  have _h : value 3 = 3 := by decide +kernel\n  simp [value]",
            "private_aux n",
        ):
            with self.subTest(proof):
                self.setUp()
                helper = HELPER.replace("rfl", proof)
                if proof == "private_aux n":
                    helper = "private theorem private_aux (n : Nat) : value n = n := rfl\n" + helper
                inventory = self._audit(BASELINE.replace("end Demo", helper + "end Demo"))
                self.assertEqual([record["declaration"] for record in inventory], ["Demo.value_spec"])
                self.assertLessEqual(
                    set(inventory[0]["axioms"]), {"propext", "Quot.sound", "Classical.choice"})
                lock = contracts.load_toolchain_lock()
                axiom_audit.validate_report_inventory(
                    inventory, lock=lock, compiler_assumptions=verifier.compiler_assumptions(lock),
                    require_complete=False,
                    expected_scope_sha256=axiom_audit.inventory_scope_sha256(inventory),
                    expected_identity_sha256=axiom_audit.inventory_identity_sha256(inventory),
                    accepted_native_decide_uses=[], hidden_native_decide_uses=[],
                    required_native_uses=[],
                )

    def test_hostile_helpers_fail_closed(self):
        cases = {
            "sorry": (HELPER.replace(":= rfl", ":= by sorry"), False,
                      "retained untrusted dependency Demo.value_spec"),
            "weakened_statement": (HELPER.replace("value n = n", "value n = value n"), False,
                                   "audited declaration type mismatch Demo.value_spec"),
            # Ignore the unrelated hole, but still freeze the implementation.
            "changed_definition": (HELPER, False, "kernel declaration identity mismatch"),
            "forged_olean": (HELPER, True, r"\(kernel\) declaration type mismatch"),
            "aux_sorry": ("theorem aux (n : Nat) : value n = n := by sorry\n"
                          + HELPER.replace("rfl", "aux n"), False,
                          "retained untrusted dependency Demo.aux"),
            "aux_axiom": ("axiom aux (n : Nat) : value n = n\n"
                          + HELPER.replace("rfl", "aux n"), False,
                          "unapproved transferred axiom Demo.aux"),
        }
        vacuous = {  # frozen exactly as written, so only the subject guard can reject
            "reflexive": ("(n : Nat) : value n = value n", "helper statement is vacuous"),
            "no_subject": ("(n : Nat) : n + 0 = n", "helper statement omits its subject"),
        }
        for name, (statement, pattern) in vacuous.items():
            with self.subTest(name):
                self.setUp()
                helper = f"theorem value_spec {statement} := rfl\n"
                canon = "theorem Demo.value_spec " + statement.replace("value n", "Demo.value n")
                with self.assertRaisesRegex(contracts.ContractError, pattern):
                    self._audit(BASELINE.replace("end Demo", helper + "end Demo"), canon=canon)
        for name, (helper, forge, pattern) in cases.items():
            with self.subTest(name):
                self.setUp()
                candidate = BASELINE.replace("end Demo", helper + "end Demo")
                if name == "changed_definition":
                    candidate = candidate.replace("n + 0", "0 + n").replace(
                        ":= rfl", ":= Nat.zero_add n")
                with self.assertRaisesRegex(contracts.ContractError, pattern):
                    self._audit(candidate, forge=forge)


if __name__ == "__main__":
    unittest.main()
