import hashlib
import importlib.util
import json
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
SCALAR = "probe:Curve25519Dalek.Scalar.fromCanonicalBytes"
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


class DalekPreparationShapeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "solved"
        self.source.mkdir()
        self.scalar_source = """import Dalek.Types
import Math.Trusted
import SolutionOnly

namespace Curve25519Dalek.Scalar

def decode (x : Nat) : Nat :=
  Math.Trusted.reduce x

theorem decode_spec (x : Nat) : decode x = x := by
  exact Solution.secretLemma x

def fromCanonicalBytes (x : Nat) : Nat :=
  decode x

theorem fromCanonicalBytes_spec (x : Nat) :
    fromCanonicalBytes x = x := by
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
            "SolutionOnly.lean": self.solution_source,
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
                        "tree_sha256": "b" * 64,
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
                "Math/Trusted.lean",
                "autofv.json",
                "lakefile.toml",
                "lean-toolchain",
            },
        )
        scalar = full_files["Dalek/Scalar.lean"].decode()
        self.assertIn("theorem fromCanonicalBytes_spec (x : Nat) :", scalar)
        self.assertIn("fromCanonicalBytes x = x := by\n  sorry", scalar)
        self.assertNotIn("decode_spec", scalar)
        self.assertNotIn("secretLemma", scalar)
        self.assertNotIn("SolutionOnly", scalar)

        small = self.root / "small"
        small_manifest = self.root / "small-manifest.json"
        self._prepare("small", small, small_manifest)
        self.assertEqual(
            set(_tree_bytes(small)),
            set(full_files) - {"Dalek/Edwards.lean"},
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


if __name__ == "__main__":
    unittest.main()
