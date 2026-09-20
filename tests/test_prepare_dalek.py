import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCALAR_ROOT = (
    "probe:curve25519_dalek/4.1.3/"
    "curve25519_dalek.scalar.Scalar.from_canonical_bytes()"
)
OTHER_ROOT = (
    "probe:curve25519_dalek/4.1.3/"
    "curve25519_dalek.edwards.EdwardsPoint.compress()"
)
SCALAR = "probe:curve25519_dalek.scalar.Scalar.from_canonical_bytes"
SCALAR_SPEC = f"{SCALAR}_spec"
HELPER = "probe:Curve25519Dalek.Scalar.decode"
HELPER_SPEC = f"{HELPER}_spec"
OTHER = "probe:Curve25519Dalek.Edwards.compress"
OTHER_SPEC = f"{OTHER}_spec"
TYPE = "probe:Curve25519Dalek.Types.Scalar"
MATH = "probe:Math.Trusted.reduce"
SOLUTION = "probe:Solution.secretLemma"


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _block_span(text, marker):
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if marker in line)
    end = next(
        (index - 1 for index in range(start + 1, len(lines)) if not lines[index]),
        len(lines) - 1,
    )
    return [start + 1, end + 1]


def _tree_bytes(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _tree_sha256(root):
    entries = [
        {
            "path": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        for name, raw in sorted(_tree_bytes(root).items())
    ]
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class DalekPreparationShapeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "solved"
        self.source.mkdir()
        self.scalar_source = """import Dalek.Types
import Bridge
import SolutionOnly

namespace Curve25519Dalek.Scalar

def decode (x : Nat) : Nat :=
  Math.Trusted.reduce x

set_option maxHeartbeats 1000 in
theorem decode_spec (x : Nat) : decode x = x := by
  exact Solution.secretLemma x

def fromCanonicalBytes (x : Nat) : Nat :=
  decode x

theorem fromCanonicalBytes_spec (x : Nat) :
    fromCanonicalBytes x = x := by
  have nested : x = x := by
    rfl
  exact Solution.secretLemma x

end Curve25519Dalek.Scalar
"""
        self.other_source = """import Dalek.Types

namespace Curve25519Dalek.Edwards

def compress (x : Nat) : Nat := x

theorem compress_spec (x : Nat) : compress x = x := by
  exact rfl

end Curve25519Dalek.Edwards
"""
        self.type_source = """namespace Curve25519Dalek.Types

abbrev Scalar := Nat

end Curve25519Dalek.Types
"""
        self.math_source = """namespace Math.Trusted

def reduce (x : Nat) : Nat := x

end Math.Trusted
"""
        self.solution_source = """namespace Solution

theorem secretLemma (x : Nat) : x = x := by
  exact rfl

end Solution
"""
        for name, text in {
            "Dalek/Scalar.lean": self.scalar_source,
            "Dalek/Edwards.lean": self.other_source,
            "Dalek/Types.lean": self.type_source,
            "Math/Trusted.lean": self.math_source,
            "Bridge.lean": "import Math.Trusted\n",
            "SolutionOnly.lean": self.solution_source,
            "LICENSE": "Apache License 2.0\n",
            "curve25519-dalek/LICENSE": "BSD 3-Clause License\n",
            "lakefile.toml": 'name = "DalekSynthetic"\n',
            "lean-toolchain": "leanprover/lean4:v4.28.0-rc1\n",
        }.items():
            _write(self.source, name, text)

        self.report = self.root / "target-report.json"
        self.report.write_text(
            json.dumps(
                {
                    "schema": "target-report/v1",
                    "inputs": {
                        "probe_aeneas_sha256": "1" * 64,
                        "probe_rust_sha256": "2" * 64,
                    },
                    "tools": {
                        "probe_aeneas": {
                            "name": "probe-aeneas",
                            "version": "0.19.0",
                            "command": "extract",
                        },
                        "probe_rust": {
                            "name": "probe-rust",
                            "version": "0.10.0",
                            "command": "extract",
                        },
                    },
                    "graph_tops": [OTHER_ROOT, SCALAR_ROOT],
                    "declarations": {
                        SCALAR_ROOT: {
                            "public_api": True,
                            "declaration": SCALAR,
                            "primary_spec": SCALAR_SPEC,
                            "directed_closure": [HELPER, SCALAR],
                            "source": {"path": "src/scalar.rs", "lines": [1, 8]},
                        },
                        OTHER_ROOT: {
                            "public_api": True,
                            "declaration": OTHER,
                            "primary_spec": OTHER_SPEC,
                            "directed_closure": [OTHER],
                            "source": {"path": "src/edwards.rs", "lines": [1, 3]},
                        },
                    },
                    "diagnostics": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        records = {
            HELPER: ("Dalek/Scalar.lean", "def decode", "implementation", [MATH], [SOLUTION]),
            HELPER_SPEC: ("Dalek/Scalar.lean", "theorem decode_spec", "statement", [HELPER], [SOLUTION]),
            SCALAR: ("Dalek/Scalar.lean", "def fromCanonicalBytes", "implementation", [HELPER, TYPE], []),
            SCALAR_SPEC: ("Dalek/Scalar.lean", "theorem fromCanonicalBytes_spec", "statement", [SCALAR], [SOLUTION]),
            OTHER: ("Dalek/Edwards.lean", "def compress", "implementation", [TYPE], []),
            OTHER_SPEC: ("Dalek/Edwards.lean", "theorem compress_spec", "statement", [OTHER], []),
            TYPE: ("Dalek/Types.lean", "abbrev Scalar", "type", [], []),
            MATH: ("Math/Trusted.lean", "def reduce", "trusted_math", [], []),
            SOLUTION: ("SolutionOnly.lean", "theorem secretLemma", "proof_only", [], []),
        }
        texts = {
            "Dalek/Scalar.lean": self.scalar_source,
            "Dalek/Edwards.lean": self.other_source,
            "Dalek/Types.lean": self.type_source,
            "Math/Trusted.lean": self.math_source,
            "SolutionOnly.lean": self.solution_source,
        }
        self.identities = self.root / "probe-identities.json"
        self.identities.write_text(
            json.dumps(
                {
                    "schema": "autofv-dalek-probe-identities/v1",
                    "source": {
                        "repository": "https://example.invalid/curve25519-dalek-lean-verify.git",
                        "revision": "a" * 40,
                        "tree_sha256": _tree_sha256(self.source),
                    },
                    "probes": {
                        name: {
                            "repository": f"https://example.invalid/{name}.git",
                            "revision": char * 40,
                            "tree_sha256": char * 64,
                            "version": version,
                        }
                        for name, char, version in (
                            ("probe-aeneas", "c", "0.19.0"),
                            ("probe-rust", "d", "0.10.0"),
                            ("probe-lean", "e", "0.15.0"),
                        )
                    },
                    "files": {
                        "lakefile.toml": {"role": "build"},
                        "lean-toolchain": {"role": "build"},
                    },
                    "declarations": {
                        name: {
                            "path": path,
                            "lines": _block_span(texts[path], marker),
                            "kind": kind,
                            "dependencies": dependencies,
                            "proof_dependencies": proof_dependencies,
                        }
                        for name, (path, marker, kind, dependencies, proof_dependencies) in records.items()
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _prepare(self, mode, output, manifest):
        module_spec = importlib.util.find_spec("autofv.prepare_dalek")
        self.assertIsNotNone(module_spec, "Dalek preparation module is missing")
        from autofv import prepare_dalek

        with mock.patch.object(prepare_dalek, "_run_build"):
            prepare_dalek.prepare_dalek(
                self.source,
                self.report,
                self.identities,
                mode,
                output,
                manifest,
            )
        return prepare_dalek

    def test_full_and_small_shapes_strip_solutions_and_keep_fixed_statements(self):
        full = self.root / "full"
        full_manifest = self.root / "full-manifest.json"
        prepare_dalek = self._prepare("full", full, full_manifest)
        full_files = _tree_bytes(full)
        self.assertEqual(
            set(full_files),
            {
                "Dalek/Edwards.lean",
                "Dalek/Scalar.lean",
                "Dalek/Types.lean",
                "Curve25519Dalek.lean",
                "Math/Trusted.lean",
                "LICENSE",
                "LICENSES/curve25519-dalek-BSD-3-Clause.txt",
                "README.md",
                "autofv.json",
                "lakefile.toml",
                "lean-toolchain",
            },
        )
        scalar = full_files["Dalek/Scalar.lean"].decode()
        self.assertIn("theorem fromCanonicalBytes_spec (x : Nat) :", scalar)
        self.assertIn("fromCanonicalBytes x = x := by\n  sorry", scalar)
        self.assertNotIn("have nested", scalar)
        self.assertNotIn("decode_spec", scalar)
        self.assertNotIn("set_option maxHeartbeats 1000 in", scalar)
        self.assertNotIn("secretLemma", scalar)
        self.assertNotIn("SolutionOnly", scalar)
        self.assertIn("import Math.Trusted\n", scalar)
        self.assertNotIn("import Bridge\n", scalar)
        root_module = full_files["Curve25519Dalek.lean"].decode()
        self.assertIn("import Dalek.Scalar\n", root_module)
        self.assertIn("import Dalek.Edwards\n", root_module)
        self.assertNotIn("SolutionOnly", root_module)
        self.assertEqual(full_files["LICENSE"], b"Apache License 2.0\n")
        self.assertEqual(
            full_files["LICENSES/curve25519-dalek-BSD-3-Clause.txt"],
            b"BSD 3-Clause License\n",
        )
        readme = full_files["README.md"].decode()
        self.assertIn("- Shape: `full`", readme)
        self.assertIn("- Targets: 2", readme)
        self.assertIn(f"- Source revision: `{'a' * 40}`", readme)
        self.assertNotIn("secretLemma", readme)

        small = self.root / "small"
        small_manifest = self.root / "small-manifest.json"
        self._prepare("small", small, small_manifest)
        self.assertEqual(
            set(_tree_bytes(small)),
            set(full_files) - {"Dalek/Edwards.lean"},
        )
        self.assertNotIn(
            "import Dalek.Edwards\n",
            (small / "Curve25519Dalek.lean").read_text(),
        )
        self.assertEqual(
            json.loads((small / "autofv.json").read_text())["targets"],
            [{"function": SCALAR_ROOT, "spec": SCALAR_SPEC.removeprefix("probe:")}],
        )

        cli = self.root / "small-cli"
        cli_manifest = self.root / "small-cli-manifest.json"
        with mock.patch.object(prepare_dalek, "_run_build"):
            prepare_dalek.main(
                [
                    "--source", str(self.source),
                    "--target-report", str(self.report),
                    "--probe-identities", str(self.identities),
                    "--mode", "small",
                    "--output", str(cli),
                    "--manifest", str(cli_manifest),
                ]
            )
        self.assertEqual(_tree_bytes(cli), _tree_bytes(small))
        self.assertEqual(cli_manifest.read_bytes(), small_manifest.read_bytes())

    def _case_inputs(self, name):
        source = self.root / name / "source"
        source.parent.mkdir()
        shutil.copytree(self.source, source)
        identities = json.loads(self.identities.read_text())
        identities["source"]["tree_sha256"] = _tree_sha256(source)
        identities_path = source.parent / "probe-identities.json"
        identities_path.write_text(
            json.dumps(identities, sort_keys=True, separators=(",", ":"))
        )
        return source, identities_path

    def _call(self, source, identities, name, *, build_error=None):
        from autofv import prepare_dalek

        output = self.root / name / "output"
        manifest = self.root / name / "manifest.json"
        effect = build_error if build_error is not None else None
        with mock.patch.object(prepare_dalek, "_run_build", side_effect=effect):
            result = prepare_dalek.prepare_dalek(
                source,
                self.report,
                identities,
                "small",
                output,
                manifest,
            )
        return result, output, manifest

    def test_reproducible_manifest_binds_inputs_tree_and_all_local_gates(self):
        first, first_output, first_manifest = self._call(
            self.source, self.identities, "repro-first"
        )
        second, second_output, second_manifest = self._call(
            self.source, self.identities, "repro-second"
        )
        self.assertEqual(_tree_bytes(first_output), _tree_bytes(second_output))
        self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(
            set(first["gates"]),
            {
                "build",
                "provenance",
                "reproducibility",
                "secret_scan",
                "spoiler_scan",
                "symlink_scan",
            },
        )
        self.assertTrue(all(value == "passed" for value in first["gates"].values()))
        self.assertEqual(first["source"], json.loads(self.identities.read_text())["source"])
        self.assertEqual(first["probes"], json.loads(self.identities.read_text())["probes"])
        self.assertEqual(first["tree_sha256"], _tree_sha256(first_output))
        self.assertEqual(
            first["manifest_sha256"],
            hashlib.sha256(
                json.dumps(
                    {key: value for key, value in first.items() if key != "manifest_sha256"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )

    def test_nested_generated_declaration_shares_its_owner_source_span(self):
        from autofv import prepare_dalek

        identities = json.loads(self.identities.read_text())
        owner = identities["declarations"][SCALAR]
        nested = "probe:Dalek.Scalar.generated_projection"
        owner["dependencies"].append(nested)
        identities["declarations"][nested] = {
            "path": owner["path"],
            "lines": [owner["lines"][1], owner["lines"][1]],
            "kind": "type",
            "dependencies": [],
            "proof_dependencies": [],
        }
        identities_path = self.root / "nested-identities.json"
        identities_path.write_text(
            json.dumps(identities, sort_keys=True, separators=(",", ":"))
        )
        output = self.root / "nested-output"
        manifest = self.root / "nested-manifest.json"

        with mock.patch.object(prepare_dalek, "_run_build"):
            result = prepare_dalek.prepare_dalek(
                self.source,
                self.report,
                identities_path,
                "small",
                output,
                manifest,
            )

        self.assertIn(nested, result["retained_declarations"])
        self.assertIn("def fromCanonicalBytes", (output / owner["path"]).read_text())

    def test_build_cache_is_linked_only_into_the_disposable_build_tree(self):
        from autofv import prepare_dalek

        project = self.root / "build-project"
        packages = self.root / "trusted-packages"
        project.mkdir()
        packages.mkdir()

        with (
            mock.patch.dict(
                os.environ,
                {"AUTOFV_LAKE_PACKAGES_DIR": str(packages)},
            ),
            mock.patch.object(prepare_dalek.subprocess, "run") as run,
        ):
            prepare_dalek._run_build(project)

        self.assertTrue((project / ".lake/packages").is_symlink())
        self.assertEqual((project / ".lake/packages").resolve(), packages.resolve())
        run.assert_called_once_with(
            ("lake", "build"),
            cwd=project,
            check=True,
            capture_output=True,
        )

    def test_hostile_inputs_fail_before_output_finalization(self):
        from autofv import prepare_dalek

        cases = []
        source, identities = self._case_inputs("symlink")
        os.symlink("Dalek/Scalar.lean", source / "linked.lean")
        cases.append(("symlink", source, identities, "symlink"))

        for name, marker, reason in (
            ("secret", "\n-- OPENAI_API_KEY=sk-test-secret\n", "secret"),
            ("spoiler", "\n-- hidden reference.json solution\n", "spoiler"),
        ):
            source, identities = self._case_inputs(name)
            scalar = source / "Dalek/Scalar.lean"
            scalar.write_text(scalar.read_text() + marker)
            values = json.loads(identities.read_text())
            values["source"]["tree_sha256"] = _tree_sha256(source)
            identities.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
            cases.append((name, source, identities, reason))

        source, identities = self._case_inputs("provenance")
        values = json.loads(identities.read_text())
        values["source"]["tree_sha256"] = "f" * 64
        identities.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
        cases.append(("provenance", source, identities, "provenance"))

        source, identities = self._case_inputs("missing-license")
        (source / "LICENSE").unlink()
        values = json.loads(identities.read_text())
        values["source"]["tree_sha256"] = _tree_sha256(source)
        identities.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
        cases.append(
            ("missing-license", source, identities, "source is not a regular file: LICENSE")
        )

        source, identities = self._case_inputs("unsafe")
        values = json.loads(identities.read_text())
        values["files"]["../escape"] = {"role": "build"}
        identities.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")))
        cases.append(("unsafe", source, identities, "unsafe"))

        for name, source, identities, reason in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                prepare_dalek.PreparationError, reason
            ):
                self._call(source, identities, name)
            self.assertFalse((self.root / name / "output").exists())
            self.assertFalse((self.root / name / "manifest.json").exists())

        source, identities = self._case_inputs("build")
        with self.assertRaisesRegex(prepare_dalek.PreparationError, "build"):
            self._call(
                source,
                identities,
                "build",
                build_error=prepare_dalek.PreparationError("build failed"),
            )
        self.assertFalse((self.root / "build" / "output").exists())
        self.assertFalse((self.root / "build" / "manifest.json").exists())

    def test_rejected_destination_does_not_mutate_solved_source(self):
        from autofv import prepare_dalek

        created_parent = self.source / "new-output-parent"
        with self.assertRaisesRegex(
            prepare_dalek.PreparationError, "cannot modify solved source"
        ):
            prepare_dalek.prepare_dalek(
                self.source,
                self.report,
                self.identities,
                "small",
                created_parent / "output",
                self.root / "outside-manifest.json",
            )
        self.assertFalse(created_parent.exists())

    def test_write_once_outputs_allow_identical_bytes_and_refuse_replacement(self):
        from autofv import prepare_dalek

        _, output, manifest = self._call(self.source, self.identities, "write-once")
        before = _tree_bytes(output)
        self._call(self.source, self.identities, "write-once")
        self.assertEqual(_tree_bytes(output), before)
        (output / "Dalek/Scalar.lean").write_text("changed\n")
        with self.assertRaisesRegex(
            prepare_dalek.PreparationError, "different-byte replacement"
        ):
            self._call(self.source, self.identities, "write-once")
        self.assertTrue(manifest.is_file())

    def test_publication_receipt_requires_matching_approved_and_observed_hashes(self):
        from autofv import prepare_dalek

        validator = getattr(prepare_dalek, "validate_publication_receipt", None)
        self.assertIsNotNone(validator, "publication receipt validator is missing")
        hashes = {
            "full": {"manifest_sha256": "1" * 64, "tree_sha256": "2" * 64},
            "small": {"manifest_sha256": "3" * 64, "tree_sha256": "4" * 64},
        }
        approved = {
            mode: {
                "repository": f"https://github.com/BAIF/dalek-clean{'-small' if mode == 'small' else ''}.git",
                "tag": "autofv-baseline-v1",
                **hashes[mode],
            }
            for mode in ("full", "small")
        }
        observed = {
            mode: {
                **approved[mode],
                "commit": commit * 40,
                "tag_object": tag * 40,
            }
            for mode, commit, tag in (("full", "a", "c"), ("small", "b", "d"))
        }
        receipt = self.root / "publication-receipt.json"
        receipt.write_text(
            json.dumps(
                {
                    "schema": "autofv-publication-receipt/v1",
                    "approved": approved,
                    "observed": observed,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        self.assertEqual(validator(receipt), json.loads(receipt.read_text()))

        for section, mode, field in (
            ("observed", "full", "tree_sha256"),
            ("observed", "small", "repository"),
            ("approved", "full", "tag"),
        ):
            changed = json.loads(receipt.read_text())
            changed[section][mode][field] = "mismatch"
            receipt.write_text(json.dumps(changed))
            with self.subTest(section=section, mode=mode, field=field), self.assertRaises(
                prepare_dalek.PreparationError
            ):
                validator(receipt)
            receipt.write_text(
                json.dumps(
                    {
                        "schema": "autofv-publication-receipt/v1",
                        "approved": approved,
                        "observed": observed,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )


if __name__ == "__main__":
    unittest.main()
