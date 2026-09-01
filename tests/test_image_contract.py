import hashlib
import json
import os
import re
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
        self.assertRegex(image["builder_receipt_sha256"], r"^[0-9a-f]{64}$")
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
            f"type=volume,src={self.volume},dst=/work",
            self.image["image_digest"],
            "sh",
            "-c",
            f"chown {FINAL_UID}:{FINAL_UID} /work",
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
            f"type=volume,src={self.volume},dst=/work",
            self.image["image_digest"],
            *command,
        ]

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


if __name__ == "__main__":
    unittest.main()
