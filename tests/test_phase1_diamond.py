import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import experiment, verifier, worker


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"
MODEL_FIXTURE = ROOT / "tests" / "fixtures" / "model-proxy" / "diamond-responses.json"
RUST_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-rust.json"
AENEAS_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-aeneas.json"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class _FixtureProxy:
    def __init__(self, fixture):
        self.entries = {
            entry["request"]["request_id"]: entry for entry in fixture["entries"]
        }
        self.seen = []

    def __call__(self, request):
        request_id = request["request_id"]
        entry = self.entries[request_id]
        if experiment.canonical_json_bytes(request) != experiment.canonical_json_bytes(
            entry["request"]
        ):
            raise AssertionError(f"request mismatch for {request_id}")
        self.seen.append(request_id)
        return copy.deepcopy(entry["response"]), copy.deepcopy(entry["receipt"])


class _Seams:
    def __init__(self, root, fixture):
        self.root = root
        self.fixture = fixture
        self.project = root / "work" / "diamond"
        self.accepted_commits = []

    def prepare(self, target, manifest, lock):
        shutil.copytree(target, self.project)
        subprocess.run(
            ("git", "init", "-q", "--object-format=sha1"),
            cwd=self.project,
            check=True,
        )
        subprocess.run(("git", "config", "core.autocrlf", "false"), cwd=self.project, check=True)
        subprocess.run(("git", "config", "core.filemode", "false"), cwd=self.project, check=True)
        subprocess.run(("git", "add", "--all"), cwd=self.project, check=True)
        git = self.fixture["git"]
        env = os.environ | {
            "GIT_AUTHOR_NAME": git["author_name"],
            "GIT_AUTHOR_EMAIL": git["author_email"],
            "GIT_AUTHOR_DATE": git["timestamp"],
            "GIT_COMMITTER_NAME": git["author_name"],
            "GIT_COMMITTER_EMAIL": git["author_email"],
            "GIT_COMMITTER_DATE": git["timestamp"],
        }
        subprocess.run(
            ("git", "commit", "-q", "--no-gpg-sign", "-m", git["message"]),
            cwd=self.project,
            env=env,
            check=True,
        )
        commit = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=self.project,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assert_equal(commit, git["base_commit"])
        snapshot = worker.hash_tree(self.project)
        return {
            "run_id": self.fixture["run_id"],
            "run_root": str(self.root),
            "project_dir": str(self.project),
            "evidence_dir": str(self.root / "evidence"),
            "volume": "fixture-volume",
            "agent_worker_id": "agent-worker-fixture",
            "snapshot_sha256": snapshot,
            "manifest_sha256": _sha256(experiment.canonical_json_bytes(manifest)),
            "image_digest": lock["image"]["image_digest"],
            "control_bundle_sha256": "1" * 64,
            "base_commit": commit,
            "events": ["validated", "target_copied", "control_bundle_verified", "runsc_started"],
        }

    @staticmethod
    def assert_equal(left, right):
        if left != right:
            raise AssertionError(f"{left!r} != {right!r}")

    def run_probes(self, run):
        evidence = Path(run["evidence_dir"])
        evidence.mkdir(parents=True)
        rust = RUST_PROBE.read_bytes()
        aeneas = AENEAS_PROBE.read_bytes()
        (evidence / "probe-rust.json").write_bytes(rust)
        (evidence / "probe-aeneas.json").write_bytes(aeneas)
        run["events"].extend(("probe_rust", "probe_aeneas"))
        return rust, aeneas

    def accept(self, run, candidate, manifest):
        patch = candidate["payload"]["patch"]
        applied = subprocess.run(
            ("git", "apply", "--index"),
            cwd=self.project,
            input=patch,
            text=True,
            capture_output=True,
        )
        if applied.returncode:
            raise experiment.ContractError(applied.stderr)
        subprocess.run(
            (
                "git",
                "-c",
                "user.name=AutoFV",
                "-c",
                "user.email=autofv@invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                candidate["request_id"],
            ),
            cwd=self.project,
            check=True,
        )
        commit = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=self.project,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.accepted_commits.append(commit)
        run["events"].append(f"accepted:{candidate['assigned_path']}")
        return {
            "accepted_commit": commit,
            "accepted_tree_sha256": worker.hash_tree(self.project),
            "checks": ["scope", "statement", "native_decide", "trust", "kernel"],
        }

    def verify(self, run, expected):
        body = {
            "schema": "autofv-verifier-report/v1",
            "run_id": run["run_id"],
            "agent_worker_id": run["agent_worker_id"],
            "verifier_worker_id": "verifier-worker-fixture",
            **expected,
            "verdict": "PASS",
        }
        return {**body, "report_sha256": _sha256(experiment.canonical_json_bytes(body))}

    def persist(self, run, result, receipt):
        (self.root / "result.json").write_bytes(experiment.canonical_json_bytes(result) + b"\n")
        evidence = self.root / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "l0.json").write_bytes(experiment.canonical_json_bytes(receipt) + b"\n")


class TracerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(MODEL_FIXTURE.read_text())

    def test_one_command_crosses_the_sealed_tracer_and_needs_clean_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), self.fixture)
            proxy = _FixtureProxy(self.fixture)
            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(worker, "run_probes", seams.run_probes),
                mock.patch.object(worker, "accept_candidate", seams.accept),
                mock.patch.object(worker, "persist_result", seams.persist),
                mock.patch.object(verifier, "verify_run", seams.verify),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=proxy
                )

            self.assertEqual(result["schema"], "autofv-result/v1")
            self.assertEqual((result["outcome"], result["termination_reason"]), ("success", "all_targets_verified"))
            self.assertEqual(result["run_id"], self.fixture["run_id"])
            self.assertEqual(result["frozen_targets"], ["probe:Diamond.top"])
            self.assertEqual(result["targets_total"], 1)
            self.assertEqual(result["targets_verified_final"], 1)
            self.assertEqual(result["internal_specs_accepted"], 2)
            self.assertEqual(result["internal_proofs_accepted"], 2)
            self.assertEqual(result["proxy_requests"], 8)
            self.assertEqual(result["cost_usd"], "0.022350")
            self.assertEqual(result["native_decide_policy"], "allow_audited")
            self.assertEqual(result["accepted_commit"], seams.accepted_commits[-1])
            self.assertEqual(len(seams.accepted_commits), 3)
            self.assertEqual(proxy.seen, [entry["request"]["request_id"] for entry in self.fixture["entries"]])
            self.assertEqual(
                result["events"][:8],
                [
                    "validated",
                    "target_copied",
                    "control_bundle_verified",
                    "runsc_started",
                    "probe_rust",
                    "probe_aeneas",
                    "targets_frozen",
                    "proxy:scout-001",
                ],
            )
            self.assertEqual(result["events"][-2:], ["clean_verifier:PASS", "result_emitted"])
            self.assertTrue((Path(tmp) / "result.json").is_file())
            self.assertTrue((Path(tmp) / "evidence" / "l0.json").is_file())
            released = b"".join(path.read_bytes() for path in Path(tmp).rglob("*") if path.is_file())
            self.assertNotIn(MODEL_FIXTURE.read_bytes(), released)
            self.assertNotIn(b"diamond-reference", released)

    def test_mismatched_verifier_or_proxy_receipt_cannot_succeed(self):
        mutations = ("verifier", "receipt")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                seams = _Seams(Path(tmp), self.fixture)
                proxy = _FixtureProxy(self.fixture)
                verify = seams.verify
                if mutation == "verifier":
                    def verify(run, expected):
                        report = seams.verify(run, expected)
                        report["accepted_commit"] = "0" * 40
                        return report
                else:
                    original = proxy
                    def proxy(request):
                        response, receipt = original(request)
                        if request["request_id"] == "scout-001":
                            receipt["response_sha256"] = "0" * 64
                        return response, receipt
                with (
                    mock.patch.object(worker, "prepare_run", seams.prepare),
                    mock.patch.object(worker, "run_probes", seams.run_probes),
                    mock.patch.object(worker, "accept_candidate", seams.accept),
                    mock.patch.object(worker, "persist_result", seams.persist),
                    mock.patch.object(verifier, "verify_run", verify),
                ):
                    result = experiment.run_experiment(
                        TARGET, TARGET / "run.json", run_round=proxy
                    )
                self.assertNotEqual(result["outcome"], "success")


if __name__ == "__main__":
    unittest.main()
