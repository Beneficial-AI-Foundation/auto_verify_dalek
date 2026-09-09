import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker" / "autofv" / "Dockerfile"
LOCK_PATH = ROOT / "docker" / "autofv" / "toolchain-lock.json"
DOCKER = ("sudo", "docker")
SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}")
FINAL_UID = "65532"
LEAN_VERSION = "v4.28.0-rc1"


def load_lock():
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def canonical_sha256(value):
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, *, check=True):
    return subprocess.run(command, cwd=ROOT, capture_output=True, check=check)


def docker(*args, check=True):
    return run([*DOCKER, *args], check=check)


def image_record():
    image = load_lock()["image"]
    if SHA256.fullmatch(image["image_digest"]) is None:
        raise AssertionError("image_digest is not a SHA-256 digest")
    return image


class ImageIdentityError(ValueError):
    pass


class ControlBundleError(ValueError):
    pass


def compute_image_build_identity(lock, dockerfile_bytes):
    try:
        image = lock["image"]
        build_inputs = image["build_inputs"]
        policy = lock["native_decide_policy"]
        return {
            "schema": "autofv-image-build-identity/v1",
            "dockerfile_sha256": hashlib.sha256(dockerfile_bytes).hexdigest(),
            "build_inputs_sha256": canonical_sha256(build_inputs),
            "platform": build_inputs["platform"],
            "base_oci_digest": build_inputs["base_oci"]["digest"],
            "native_decide_policy_sha256": canonical_sha256(policy),
        }
    except (KeyError, TypeError) as error:
        raise ImageIdentityError("stale image lock: incomplete identity inputs") from error


def assert_image_lock_current(lock, dockerfile_bytes):
    image = lock.get("image", {})
    current = compute_image_build_identity(lock, dockerfile_bytes)
    checks = (
        current == image.get("build_identity"),
        canonical_sha256(current) == image.get("build_identity_sha256"),
        current["dockerfile_sha256"] == image.get("dockerfile_sha256"),
        current["build_inputs_sha256"] == image.get("build_inputs_sha256"),
        current["platform"] == image.get("platform"),
        current["native_decide_policy_sha256"]
        == lock.get("native_decide_policy_sha256"),
        current["native_decide_policy_sha256"]
        == image.get("build_inputs", {}).get("native_decide_policy_sha256"),
        SHA256.fullmatch(image.get("image_digest", "")) is not None,
    )
    if not all(checks):
        raise ImageIdentityError("stale image lock: rebuild and re-pin required")
    return image["image_digest"]


def _canonical_member_path(member):
    if not isinstance(member, str) or not member or "\\" in member or "\0" in member:
        raise ControlBundleError("non-canonical bundle member")
    try:
        member.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ControlBundleError("non-canonical bundle member") from error
    parts = member.split("/")
    if member.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise ControlBundleError("non-canonical bundle member")
    return parts


def _member_is_allowed(member, allowed_roots):
    return any(
        member.startswith(root) if root.endswith("/") else member == root
        for root in allowed_roots
    )


def _validate_bundle_contract(contract):
    try:
        allowed = contract["allowed_members"]
        allowed_roots = contract["allowed_roots"]
        manifest = contract["manifest"]
        modes = contract["modes"]
    except (KeyError, TypeError) as error:
        raise ControlBundleError("incomplete control-bundle contract") from error
    if (
        not isinstance(allowed, list)
        or not all(isinstance(member, str) for member in allowed)
        or allowed != sorted(set(allowed))
    ):
        raise ControlBundleError("allowed members are not canonical and unique")
    if not isinstance(allowed_roots, list) or not all(
        isinstance(root, str) for root in allowed_roots
    ):
        raise ControlBundleError("allowed roots are invalid")
    if not isinstance(manifest, dict):
        raise ControlBundleError("manifest contract is invalid")
    for member in allowed:
        _canonical_member_path(member)
        if not _member_is_allowed(member, allowed_roots):
            raise ControlBundleError("allowed member lies outside allowed roots")
    if manifest.get("file_types") != ["regular_file"]:
        raise ControlBundleError("only regular bundle members are supported")
    if set(manifest.get("entry_fields", ())) != {"path", "sha256", "size"}:
        raise ControlBundleError("non-canonical bundle entry schema")
    if modes != {"directory": "0555", "file": "0444"}:
        raise ControlBundleError("bundle must be delivered read-only")
    return allowed, manifest, modes


def _read_regular_member(root, member):
    parts = _canonical_member_path(member)
    candidate = root
    for index, part in enumerate(parts):
        candidate = candidate / part
        try:
            member_stat = os.lstat(candidate)
        except OSError as error:
            raise ControlBundleError("bundle member is missing") from error
        if stat.S_ISLNK(member_stat.st_mode):
            raise ControlBundleError("bundle member may not be a symlink")
        if index < len(parts) - 1 and not stat.S_ISDIR(member_stat.st_mode):
            raise ControlBundleError("bundle member parent is not a directory")
    if not stat.S_ISREG(member_stat.st_mode):
        raise ControlBundleError("bundle member must be a regular file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ControlBundleError("bundle member could not be opened safely") from error
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode) or (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ) != (member_stat.st_dev, member_stat.st_ino):
            raise ControlBundleError("bundle member changed during validation")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def build_control_bundle_manifest(root, members, contract):
    allowed, manifest_contract, modes = _validate_bundle_contract(contract)
    if not isinstance(members, list):
        raise ControlBundleError("bundle members must be a list")
    for member in members:
        _canonical_member_path(member)
    if len(members) != len(set(members)):
        raise ControlBundleError("duplicate bundle member")
    if set(members) != set(allowed):
        raise ControlBundleError("bundle members do not match the exact allowlist")

    root = Path(root)
    try:
        root_stat = os.lstat(root)
    except OSError as error:
        raise ControlBundleError("bundle root is missing") from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ControlBundleError("bundle root must be a real directory")
    entries = []
    for member in sorted(members):
        data = _read_regular_member(root, member)
        entries.append(
            {
                "path": member,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    body = {
        "schema": manifest_contract["schema"],
        "entries": entries,
        "modes": modes,
    }
    return {**body, "bundle_sha256": canonical_sha256(body)}


def validate_control_bundle_manifest(root, manifest, contract):
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "entries",
        "modes",
        "bundle_sha256",
    }:
        raise ControlBundleError("non-canonical bundle metadata")
    if not isinstance(manifest.get("entries"), list):
        raise ControlBundleError("non-canonical bundle metadata")
    contract_manifest = contract.get("manifest", {})
    if (
        manifest.get("schema") != contract_manifest.get("schema")
        or manifest.get("modes") != contract.get("modes")
        or not isinstance(manifest.get("bundle_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["bundle_sha256"]) is None
    ):
        raise ControlBundleError("non-canonical bundle metadata")
    expected_fields = set(contract_manifest.get("entry_fields", ()))
    if any(
        not isinstance(entry, dict) or set(entry) != expected_fields
        for entry in manifest["entries"]
    ):
        raise ControlBundleError("non-canonical bundle metadata")
    for entry in manifest["entries"]:
        _canonical_member_path(entry["path"])
        if (
            not isinstance(entry["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise ControlBundleError("non-canonical bundle metadata")
    paths = [entry["path"] for entry in manifest["entries"]]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ControlBundleError("non-canonical bundle metadata")
    expected = build_control_bundle_manifest(root, paths, contract)
    if manifest != expected:
        raise ControlBundleError("control bundle content mismatch before copy")
    return manifest["bundle_sha256"]


class ImageBuildTests(unittest.TestCase):
    def test_dockerfile_is_digest_pinned_toolchain_only_and_nonroot(self):
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        lock = load_lock()
        self.assertIn(
            f"docker.io/library/python@{lock['base_oci']['pin']}", dockerfile
        )
        self.assertRegex(dockerfile, rf"(?m)^USER {FINAL_UID}:{FINAL_UID}$")
        self.assertIn("org.autofv.toolchain-lock-schema", dockerfile)
        self.assertIn("org.autofv.build-inputs-sha256", dockerfile)
        self.assertIn("org.autofv.native-decide-policy-sha256", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^\s*(ADD|COPY)\s+\.\s")
        for forbidden in (
            "autofv/experiment.py",
            "tests/fixtures",
            ".git",
            ".planning",
            "docker.sock",
            "provider_api_key",
            "autofv-proxy-signing-private",
        ):
            self.assertNotIn(forbidden, dockerfile.lower())

    def test_offline_probe_runtime_closure_is_pinned(self):
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        closure = load_lock()["image"]["build_inputs"]["probe_runtime_closure"]
        self.assertEqual(
            set(closure),
            {
                "rustup",
                "rust_analyzer",
                "scip",
                "cargo_public_api",
                "nightly",
                "charon",
                "probe_lean_runtime",
            },
        )
        for record in closure.values():
            self.assertEqual(record["legitimacy"], "verified")

        self.assertIn("rustup component add rust-analyzer rust-src", dockerfile)
        self.assertIn("nightly-2026-06-01", dockerfile)
        self.assertIn("cargo-public-api-0.52.0.crate", dockerfile)
        self.assertIn("[dependencies.curl-sys]", dockerfile)
        self.assertIn('features = ["static-curl"]', dockerfile)
        self.assertIn("scip-linux-arm64.tar.gz", dockerfile)
        self.assertIn("inputs/charon.tar.gz", dockerfile)
        self.assertIn("charon-driver", dockerfile)
        self.assertIn(f"probe-lean-{LEAN_VERSION}", dockerfile)
        self.assertIn(".lake/build/lib/lean", dockerfile)
        self.assertIn('RUSTUP_AUTO_INSTALL="0"', dockerfile)

    def test_recorded_build_identity_matches_locked_inputs(self):
        lock = load_lock()
        image = image_record()
        self.assertEqual(image["schema"], "autofv-toolchain-image/v1")
        self.assertEqual(image["platform"], "linux/arm64")
        self.assertEqual(image["dockerfile_sha256"], file_sha256(DOCKERFILE))
        self.assertEqual(
            image["build_inputs"]["native_decide_policy_sha256"],
            lock["native_decide_policy_sha256"],
        )
        self.assertEqual(
            image["build_inputs_sha256"], canonical_sha256(image["build_inputs"])
        )
        self.assertRegex(image["image_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(image["image_manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            image["builder_receipt_sha256"],
            canonical_sha256(image["builder_receipt"]),
        )
        self.assertRegex(image["build_metadata_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(image["no_secret_build"])
        self.assertEqual(
            image["labels"],
            {
                "org.autofv.toolchain-lock-schema": lock["schema"],
                "org.autofv.build-inputs-sha256": image["build_inputs_sha256"],
                "org.autofv.native-decide-policy-sha256": lock[
                    "native_decide_policy_sha256"
                ],
            },
        )

    def test_actual_image_inspection_matches_the_lock(self):
        image = image_record()
        inspected = json.loads(
            docker("image", "inspect", image["image_digest"]).stdout
        )[0]
        self.assertEqual(inspected["Id"], image["image_digest"])
        self.assertEqual(inspected["Os"], "linux")
        self.assertEqual(inspected["Architecture"], "arm64")
        self.assertEqual(inspected["Config"]["User"], f"{FINAL_UID}:{FINAL_UID}")
        self.assertEqual(inspected["Config"]["Labels"], image["labels"])

        history = docker(
            "image", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image["image_digest"]
        ).stdout.lower()
        for forbidden in (
            b"autofv/experiment.py",
            b"tests/fixtures",
            b"provider_api_key",
            b"autofv-proxy-signing-private",
        ):
            self.assertNotIn(forbidden, history)


class RuntimeSmokeTests(unittest.TestCase):
    def setUp(self):
        self.image = image_record()
        self.volume = f"autofv-plan02-{os.getpid()}-{self._testMethodName.lower()}"
        docker("volume", "create", self.volume)
        docker(
            "run",
            "--rm",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={self.volume},dst=/work,volume-nocopy",
            self.image["image_digest"],
            "sh",
            "-c",
            f"chown {FINAL_UID}:{FINAL_UID} /work && chmod 0700 /work",
        )

    def tearDown(self):
        docker("volume", "rm", "-f", self.volume, check=False)

    def runtime_argv(self, *command):
        return [
            *DOCKER,
            "run",
            "--rm",
            "--runtime",
            "runsc-hardened",
            "--read-only",
            "--network",
            "none",
            "--user",
            f"{FINAL_UID}:{FINAL_UID}",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--tmpfs",
            "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m",
            "--mount",
            f"type=volume,src={self.volume},dst=/work,volume-nocopy",
            self.image["image_digest"],
            *command,
        ]

    def copy_tree_to_volume(self, source, destination):
        name = f"autofv-plan02-copy-{os.getpid()}-{self._testMethodName.lower()}"
        docker(
            "create",
            "--name",
            name,
            "--network",
            "none",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={self.volume},dst=/work,volume-nocopy",
            self.image["image_digest"],
            "sleep",
            "60",
        )
        try:
            docker("start", name)
            docker("exec", "--user", "0:0", name, "mkdir", "-p", destination)
            docker("cp", f"{source}/.", f"{name}:{destination}")
            docker(
                "exec",
                "--user",
                "0:0",
                name,
                "chown",
                "-R",
                f"{FINAL_UID}:{FINAL_UID}",
                destination,
            )
        finally:
            docker("rm", "-f", name, check=False)

    @staticmethod
    def write_rust_fixture(root):
        (root / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            """[package]
name = "tiny-probe"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
""",
            encoding="utf-8",
        )
        (root / "src" / "lib.rs").write_text(
            """pub fn leaf(value: u64) -> u64 {
    value + 1
}

pub fn top(value: u64) -> u64 {
    leaf(value)
}
""",
            encoding="utf-8",
        )

    @staticmethod
    def probe_rust_facts(document):
        selected = {}
        for atom in document["data"].values():
            name = atom.get("display-name")
            if name in {"leaf", "top"}:
                selected[name] = {
                    "code-path": atom.get("code-path"),
                    "is-public": atom.get("is-public"),
                    "is-public-api": atom.get("is-public-api"),
                    "has-locations": "dependencies-with-locations" in atom,
                }
        return {
            "schema": document["schema"],
            "schema-version": document["schema-version"],
            "tool": document["tool"],
            "source-language": document["source"]["language"],
            "source-package": document["source"]["package"],
            "functions": selected,
        }

    def probe_contract(self, name):
        contracts = {
            item["name"]: item for item in self.image["probe_contract_smokes"]
        }
        return contracts[name]

    def test_read_only_runsc_runtime_uses_final_user_and_managed_writes(self):
        completed = run(
            self.runtime_argv(
                "sh",
                "-ec",
                f'test "$(id -u)" = {FINAL_UID}; '
                "! touch /etc/autofv-write-test; "
                "touch /tmp/autofv-tmp-test /work/autofv-volume-test",
            )
        )
        self.assertEqual(completed.returncode, 0)

    def test_every_locked_runtime_smoke_matches_its_output_hash(self):
        names = {smoke["name"] for smoke in self.image["runtime_smokes"]}
        self.assertEqual(
            names,
            {
                "python",
                "git",
                "lean",
                "lake",
                "rustup",
                "rustc",
                "cargo",
                "rust-analyzer",
                "scip",
                "cargo-public-api",
                "nightly-rustc",
                "charon",
                "probe-aeneas",
                "probe-rust",
                "probe-lean",
                "model-client",
                "python-packages",
            },
        )
        for smoke in self.image["runtime_smokes"]:
            with self.subTest(smoke=smoke["name"]):
                completed = run(self.runtime_argv(*smoke["argv"]), check=False)
                digest = hashlib.sha256(
                    completed.stdout + b"\0" + completed.stderr
                ).hexdigest()
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                self.assertEqual(digest, smoke["output_sha256"])

    def test_probe_rust_extract_runs_with_full_closure_offline(self):
        contract = self.probe_contract("probe-rust-extract-offline")
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "rust-fixture"
            self.write_rust_fixture(fixture)
            self.copy_tree_to_volume(fixture, "/work/rust-fixture")

        completed = run(self.runtime_argv(*contract["argv"]), check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertIn(b"cargo-public-api found", completed.stdout)
        document = json.loads(
            run(self.runtime_argv("cat", "/work/rust-atoms.json")).stdout
        )
        facts = self.probe_rust_facts(document)
        self.assertEqual(facts, contract["expected_facts"])
        self.assertEqual(canonical_sha256(facts), contract["facts_sha256"])

    def test_probe_aeneas_extract_resolves_pinned_subtools_offline(self):
        contract = self.probe_contract("probe-aeneas-extract-offline")
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "aeneas-fixture"
            self.write_rust_fixture(fixture)
            (fixture / "aeneas-config.yml").write_text(
                'crate:\n  dir: "."\n  name: "tiny-probe"\n',
                encoding="utf-8",
            )
            (fixture / "lakefile.toml").write_text(
                """name = "TinyProbe"
version = "0.1.0"
defaultTargets = ["TinyProbe"]

[[lean_lib]]
name = "TinyProbe"
""",
                encoding="utf-8",
            )
            (fixture / "lean-toolchain").write_text(
                f"leanprover/lean4:{LEAN_VERSION}\n", encoding="utf-8"
            )
            (fixture / "TinyProbe.lean").write_text(
                """namespace TinyProbe
def leaf (value : Nat) : Nat := value + 1
def top (value : Nat) : Nat := leaf value
end TinyProbe
""",
                encoding="utf-8",
            )
            (fixture / "functions.json").write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "lean_name": "TinyProbe.leaf",
                                "rust_name": "tiny_probe::leaf",
                                "source": "src/lib.rs",
                                "lines": "L1-L3",
                            },
                            {
                                "lean_name": "TinyProbe.top",
                                "rust_name": "tiny_probe::top",
                                "source": "src/lib.rs",
                                "lines": "L5-L7",
                            },
                        ]
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            self.copy_tree_to_volume(fixture, "/work/aeneas-fixture")

        completed = run(self.runtime_argv(*contract["argv"]), check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        rust_document = json.loads(
            run(
                self.runtime_argv(
                    "cat",
                    "/work/aeneas-fixture/.verilib/probes/rust_extract.json",
                )
            ).stdout
        )
        merged = json.loads(
            run(self.runtime_argv("cat", "/work/aeneas-atoms.json")).stdout
        )
        charon_versions = sorted(
            {
                atom["charon-version"]
                for atom in rust_document["data"].values()
                if atom.get("charon-version")
            }
        )
        facts = {
            "schema": merged["schema"],
            "schema-version": merged["schema-version"],
            "tool": merged["tool"],
            "input-languages": sorted(
                item["source"]["language"] for item in merged["inputs"]
            ),
            "charon-versions": charon_versions,
            "public-api-ran": b"cargo-public-api found" in completed.stdout,
        }
        self.assertEqual(facts, contract["expected_facts"])
        self.assertEqual(canonical_sha256(facts), contract["facts_sha256"])

    def test_statement_gate_runs_from_a_copied_control_file(self):
        name = f"autofv-plan02-gate-{os.getpid()}"
        create = [
            *self.runtime_argv("sleep", "60"),
        ]
        create[create.index("run")] = "create"
        create[create.index("--rm")] = "--name"
        create.insert(create.index("--name") + 1, name)
        run(create)
        try:
            docker("start", name)
            with tempfile.TemporaryDirectory() as tmp:
                smoke = Path(tmp) / "Curve25519Dalek.lean"
                smoke.write_text(
                    "namespace Curve25519Dalek\ndef smoke : Nat := 1\nend Curve25519Dalek\n",
                    encoding="utf-8",
                )
                docker(
                    "cp", str(ROOT / "harness/gates/StmtCanon.lean"), f"{name}:/work/StmtCanon.lean"
                )
                docker("cp", str(smoke), f"{name}:/work/Curve25519Dalek.lean")
            completed = docker(
                "exec",
                "--user",
                f"{FINAL_UID}:{FINAL_UID}",
                "--env",
                "LEAN_PATH=/tmp",
                name,
                "sh",
                "-ec",
                "lean -o /tmp/Curve25519Dalek.olean /work/Curve25519Dalek.lean && "
                "lean --run /work/StmtCanon.lean Curve25519Dalek.smoke",
            )
            self.assertIn(b'"found":true', completed.stdout)
        finally:
            docker("rm", "-f", name, check=False)


class ContentDriftTests(unittest.TestCase):
    def test_recorded_image_identity_matches_current_content_inputs(self):
        lock = load_lock()
        identity = compute_image_build_identity(lock, DOCKERFILE.read_bytes())
        self.assertEqual(identity, lock["image"]["build_identity"])
        self.assertEqual(
            canonical_sha256(identity), lock["image"]["build_identity_sha256"]
        )
        assert_image_lock_current(lock, DOCKERFILE.read_bytes())

    def test_image_content_and_policy_mutations_make_the_lock_stale(self):
        lock = load_lock()
        cases = []

        changed_inputs = json.loads(json.dumps(lock))
        changed_inputs["image"]["build_inputs"]["lean"]["commit"] = "f" * 40
        cases.append(("build-input", changed_inputs, DOCKERFILE.read_bytes()))

        changed_policy = json.loads(json.dumps(lock))
        changed_policy["native_decide_policy"]["criterion"]["scope"] = {
            "kind": "named_specs",
            "specs": ["A"],
        }
        cases.append(("policy", changed_policy, DOCKERFILE.read_bytes()))

        cases.append(
            ("dockerfile", lock, DOCKERFILE.read_bytes() + b"\n# content drift\n")
        )

        for name, candidate, dockerfile in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ImageIdentityError, "stale image lock"):
                    assert_image_lock_current(candidate, dockerfile)

    def test_controller_only_mutation_changes_bundle_not_image_identity(self):
        lock = load_lock()
        identity = compute_image_build_identity(lock, DOCKERFILE.read_bytes())
        contract = json.loads(json.dumps(lock["controller_delivery"]))
        contract["allowed_members"] = ["autofv/experiment.py"]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "autofv" / "experiment.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"before\n")
            before = build_control_bundle_manifest(
                root, contract["allowed_members"], contract
            )
            source.write_bytes(b"after\n")
            after = build_control_bundle_manifest(
                root, contract["allowed_members"], contract
            )

        self.assertNotEqual(before["bundle_sha256"], after["bundle_sha256"])
        self.assertEqual(
            identity, compute_image_build_identity(lock, DOCKERFILE.read_bytes())
        )


class ControlBundleBoundaryTests(unittest.TestCase):
    @staticmethod
    def contract_with_members(*members):
        contract = json.loads(json.dumps(load_lock()["controller_delivery"]))
        contract["allowed_members"] = list(members)
        return contract

    def test_manifest_is_canonical_for_the_exact_locked_members(self):
        contract = load_lock()["controller_delivery"]
        manifest = build_control_bundle_manifest(
            ROOT, contract["allowed_members"], contract
        )
        entries = manifest["entries"]

        self.assertEqual(
            set(manifest), {"schema", "entries", "modes", "bundle_sha256"}
        )
        self.assertEqual(
            [entry["path"] for entry in entries],
            sorted(contract["allowed_members"]),
        )
        self.assertTrue(
            all(set(entry) == set(contract["manifest"]["entry_fields"])
                for entry in entries)
        )
        self.assertEqual(manifest["modes"], contract["modes"])
        self.assertEqual(
            manifest["bundle_sha256"],
            canonical_sha256(
                {
                    "schema": manifest["schema"],
                    "entries": entries,
                    "modes": manifest["modes"],
                }
            ),
        )
        validate_control_bundle_manifest(ROOT, manifest, contract)

    def test_split_experiment_modules_remain_in_the_control_bundle(self):
        members = set(load_lock()["controller_delivery"]["allowed_members"])
        moved_experiment_code = {
            "autofv/contracts.py",
            "autofv/diamond.py",
            "autofv/evidence.py",
            "autofv/model.py",
            "autofv/results.py",
            "autofv/run_state.py",
        }
        self.assertTrue(moved_experiment_code <= members)

    def test_rejects_noncanonical_duplicate_and_out_of_allowlist_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "autofv" / "experiment.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"trusted\n")
            contract = self.contract_with_members("autofv/experiment.py")

            hostile_members = (
                ["autofv/experiment.py", "autofv/experiment.py"],
                ["harness/driver.py"],
                ["/autofv/experiment.py"],
                ["autofv//experiment.py"],
                ["autofv/./experiment.py"],
                ["autofv/../experiment.py"],
                ["autofv\\experiment.py"],
            )
            for members in hostile_members:
                with self.subTest(members=members):
                    with self.assertRaises(ControlBundleError):
                        build_control_bundle_manifest(root, members, contract)

    def test_rejects_symlinks_and_special_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "autofv"
            bundle.mkdir()
            regular = bundle / "regular.py"
            regular.write_bytes(b"trusted\n")
            symlink = bundle / "symlink.py"
            symlink.symlink_to(regular)
            fifo = bundle / "special"
            os.mkfifo(fifo)

            for member in ("autofv/symlink.py", "autofv/special"):
                with self.subTest(member=member):
                    contract = self.contract_with_members(member)
                    with self.assertRaises(ControlBundleError):
                        build_control_bundle_manifest(root, [member], contract)

    def test_rejects_stale_hashes_and_noncanonical_metadata_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "autofv" / "experiment.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"trusted\n")
            contract = self.contract_with_members("autofv/experiment.py")
            manifest = build_control_bundle_manifest(
                root, contract["allowed_members"], contract
            )

            source.write_bytes(b"mutated\n")
            with self.assertRaisesRegex(ControlBundleError, "content mismatch"):
                validate_control_bundle_manifest(root, manifest, contract)

            source.write_bytes(b"trusted\n")
            reversed_manifest = json.loads(json.dumps(manifest))
            reversed_manifest["entries"].append(
                json.loads(json.dumps(reversed_manifest["entries"][0]))
            )
            with self.assertRaises(ControlBundleError):
                validate_control_bundle_manifest(root, reversed_manifest, contract)

            unknown_metadata = json.loads(json.dumps(manifest))
            unknown_metadata["unexpected"] = True
            with self.assertRaises(ControlBundleError):
                validate_control_bundle_manifest(root, unknown_metadata, contract)

    def test_final_image_build_context_excludes_the_control_bundle(self):
        lock = load_lock()
        context = set(lock["image"]["builder_receipt"]["build_context"])
        members = set(lock["controller_delivery"]["allowed_members"])
        dockerfile = DOCKERFILE.read_text(encoding="utf-8").lower()

        self.assertTrue(context.isdisjoint(members))
        self.assertNotIn(lock["controller_delivery"]["destination"], dockerfile)
        self.assertFalse(lock["image"]["builder_receipt"]["host_checkout_mounted"])
        self.assertFalse(lock["controller_delivery"]["bind_mount"])


if __name__ == "__main__":
    unittest.main()
