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

from autofv import axiom_audit, contracts

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
    f'mkdir -p .lake/build/lib/lean; "{LEAN}" -o .lake/build/lib/lean/Demo.olean Demo.lean',
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
            argv, cwd=workdir.replace("/project", local), capture_output=True,
            env={**os.environ, "LEAN_PATH": str(repo / ".lake/build/lib/lean")},
        )
        if completed.returncode:
            raise contracts.ContractError(
                "local docker failed: " + (completed.stdout + completed.stderr).decode()[-3000:]
            )
        return completed

    def seed_file(self, image, volume, path, raw, *, runtime, allowed_paths=frozenset()):
        target = self._local(volume) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(0o644)
        target.write_bytes(raw)
        target.chmod(0o444)

    def _audit(self, candidate: str, *, forge: bool = False, canon: str | None = None) -> list[dict]:
        state = copy.deepcopy(STATE)
        if canon is not None:
            state["frozen_contracts"]["Demo.value_spec"]["canon"] = canon
        source = self.root / "source"
        source.mkdir()
        _git(source, "init", "-q")
        (source / "Demo.lean").write_text(BASELINE)
        _git(source, "add", "Demo.lean")
        _git(source, "commit", "-qm", "baseline")
        base = _git(source, "rev-parse", "HEAD")
        (source / "Demo.lean").write_text(candidate)
        _git(source, "commit", "-qam", "candidate")
        accepted = _git(source, "rev-parse", "HEAD")
        _git(source, "tag", "base", base)
        _git(source, "tag", "accepted", accepted)
        _git(source, "bundle", "create", "-q", str(self.root / "repo.bundle"), "--all")
        bundle = (self.root / "repo.bundle").read_bytes()
        for volume in ("audit", "witness"):
            self._local(volume).mkdir(parents=True)
        seams = {"docker": self.docker, "runtime_argv": self.runtime_argv,
                 "seed_file": self.seed_file}
        reference = {"leaves": []}
        expected = axiom_audit.expected_inventory(state, reference)
        identities = axiom_audit.prepare_auditor(
            image="local", volume="audit", repository_bundle=bundle, base_commit=base,
            verify_command=BUILD, expected=expected, state=state, reference=reference,
            runtime="runsc-hardened", **seams,
        )
        axiom_audit.checkout_volume(
            image="local", volume="witness", repository_bundle=bundle, commit=accepted,
            runtime="runsc-hardened", **seams,
        )
        self.docker(*self.runtime_argv("local", "witness", *BUILD, workdir="/project/repo"))
        if forge:
            (self._local("witness") / "repo/Forge.lean").write_text(FORGE)
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

    def test_new_helper_is_kernel_checked_against_pristine_baseline(self):
        candidate = BASELINE.replace("end Demo", HELPER + "end Demo")
        inventory = self._audit(candidate)
        self.assertEqual(
            [(record["declaration"], record["axioms"]) for record in inventory],
            [("Demo.value_spec", [])],
        )

    def test_hostile_helpers_fail_closed(self):
        cases = {
            "sorry": (HELPER.replace(":= rfl", ":= by sorry"), False,
                      "retained untrusted dependency Demo.value_spec"),
            "weakened_statement": (HELPER.replace("value n = n", "value n = value n"), False,
                                   "audited declaration type mismatch Demo.value_spec"),
            # The changed body also taints the unrelated baseline hole's closure.
            "changed_definition": (HELPER, False, "retained untrusted dependency Demo.root_spec"),
            "forged_olean": (HELPER, True, r"\(kernel\) declaration type mismatch"),
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
