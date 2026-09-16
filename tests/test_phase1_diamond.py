import base64
import copy
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import (
    axiom_audit,
    contracts,
    experiment,
    probes,
    results,
    verifier,
    verifier_bundle,
    worker,
    worker_runtime,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"
MODEL_FIXTURE = ROOT / "tests" / "fixtures" / "model-proxy" / "diamond-responses.json"
RUST_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-rust.json"
AENEAS_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-aeneas.json"
REFERENCE = ROOT / "tests" / "fixtures" / "diamond-reference" / "reference.json"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _generic_graph():
    graph = {
        "frozen_targets": ["probe:Diamond.top"],
        "selected_nodes": [
            "probe:Diamond.left",
            "probe:Diamond.right",
            "probe:Diamond.top",
        ],
        "term_dependencies": [
            ["probe:Diamond.right", "probe:Diamond.left"],
            ["probe:Diamond.top", "probe:Diamond.right"],
        ],
        "type_dependencies": [],
        "source_paths": {
            "probe:Diamond.left": "Diamond/Left.lean",
            "probe:Diamond.right": "Diamond/Right.lean",
            "probe:Diamond.top": "Diamond/Top.lean",
            "probe:Diamond.top_spec": "Diamond/Top.lean",
        },
        "supplied_specs": {"probe:Diamond.top": "probe:Diamond.top_spec"},
        "probe_rust_sha256": "1" * 64,
        "probe_aeneas_sha256": "2" * 64,
    }
    immutable = {
        key: graph[key]
        for key in (
            "frozen_targets",
            "selected_nodes",
            "term_dependencies",
            "type_dependencies",
            "source_paths",
            "supplied_specs",
        )
    }
    graph["graph_sha256"] = _sha256(experiment.canonical_json_bytes(immutable))
    return graph


class _SignedRoleProvider:
    def __init__(self, private_key):
        self.private_key = private_key
        self.calls = []

    @staticmethod
    def _patch(path, before, after):
        return (
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            "@@ -1,1 +1,1 @@\n"
            f"-{before}\n"
            f"+{after}\n"
        )

    def _arguments(self, role):
        occurrence = sum(call["role"] == role for call in self.calls)
        if role == "prover":
            if occurrence == 0:
                patch = MODEL_FIXTURE_DATA["entries"][5]["response"]["payload"][
                    "patch"
                ]
            elif occurrence == 1:
                patch = MODEL_FIXTURE_DATA["entries"][6]["response"]["payload"][
                    "patch"
                ]
            else:
                patch = MODEL_FIXTURE_DATA["entries"][7]["response"]["payload"][
                    "patch"
                ]
        elif role == "proof_reviewer":
            if occurrence == 0:
                patch = MODEL_FIXTURE_DATA["entries"][5]["response"]["payload"][
                    "patch"
                ]
            elif occurrence == 1:
                patch = MODEL_FIXTURE_DATA["entries"][6]["response"]["payload"][
                    "patch"
                ]
            else:
                patch = MODEL_FIXTURE_DATA["entries"][7]["response"]["payload"][
                    "patch"
                ]
        elif role == "verification_adviser":
            patch = MODEL_FIXTURE_DATA["entries"][7]["response"]["payload"][
                "patch"
            ]
        else:
            path = "Diamond/Top.lean"
            if role in {"specifier", "spec_reviewer"}:
                path = (
                    "Diamond/Left.lean"
                    if role == "specifier" and occurrence == 1
                    else "Diamond/Right.lean"
                )
            patch = self._patch(path, "namespace Diamond", "namespace Diamond")
        evidence = [f"deterministic:{role}"]
        if role == "specifier":
            evidence = [
                "statement:theorem Diamond.left_spec (n : Nat) : "
                "Diamond.left n = Nat.succ n"
                if occurrence == 1
                else "statement:theorem Diamond.right_spec (n : Nat) : n ≤ "
                "Diamond.right n"
            ]
        elif role == "spec_reviewer":
            evidence = [
                "statement:theorem Diamond.right_spec (n : Nat) : "
                "Diamond.right n = n * (Nat.succ 1)"
            ]
        return {
            "patch": patch,
            "claimed_status": "candidate",
            "evidence": evidence,
        }

    def __call__(self, request):
        role = request["role"]
        payload = {
            "schema": "autofv-lane-tool-call/v1",
            "name": "submit_candidate",
            "arguments": self._arguments(role),
        }
        response = {
            "schema": "autofv-model-response/v1",
            **{
                key: copy.deepcopy(request[key])
                for key in (
                    "run_id",
                    "sequence",
                    "batch_id",
                    "request_id",
                    "role",
                    "model_id",
                    "input_hashes",
                    "prompt_sha256",
                )
            },
            "kind": "tool_call",
            "assigned_path": None,
            "base_commit": MODEL_FIXTURE_DATA["git"]["base_commit"],
            "statement_fingerprints": [],
            "payload": payload,
            "payload_sha256": _sha256(experiment.canonical_json_bytes(payload)),
        }
        request_sha256 = _sha256(experiment.canonical_json_bytes(request))
        response_sha256 = _sha256(experiment.canonical_json_bytes(response))
        unsigned = {
            "schema": "autofv-model-proxy-receipt/v1",
            "proxy_id": "autofv-local-fixture-proxy-v1",
            "route_id": "autofv-infer-v1",
            "run_id": request["run_id"],
            "sequence": request["sequence"],
            "request_id": request["request_id"],
            "model_id": request["model_id"],
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
            "status": "ok",
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            "cost": {"amount": "0.000001", "currency": "USD"},
            "auth": {
                "algorithm": "Ed25519",
                "key_id": "autofv-role-test-ed25519-v1",
            },
        }
        signed = experiment.canonical_json_bytes(unsigned)
        receipt = copy.deepcopy(unsigned)
        receipt["auth"]["signature"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        receipt["receipt_sha256"] = _sha256(signed)
        self.calls.append(copy.deepcopy(request))
        return response, receipt


MODEL_FIXTURE_DATA = json.loads(MODEL_FIXTURE.read_text())


def _role_test_lock(private_key):
    lock = copy.deepcopy(experiment.load_toolchain_lock())
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    auth = lock["fixed_proxy"]["receipt_schema"]["authentication"]
    auth.update(
        {
            "algorithm": "Ed25519",
            "key_id": "autofv-role-test-ed25519-v1",
            "public_key_pem": public_pem,
            "public_key_der_sha256": _sha256(public_der),
        }
    )
    return lock


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
        self.feasibility_calls = 0

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
            "execution_tier": "simulation",
            "cost_classification": "synthetic_fixture",
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

    def check_contract_feasibility(self, run, statements):
        self.feasibility_calls += 1
        passed = self.feasibility_calls == 2
        detail = "consumer proof compiled" if passed else "left equality is unavailable"
        return {
            "status": "passed" if passed else "failed",
            "reason": None if passed else "consumer_proof_failed",
            "diagnostic_sha256": _sha256(detail.encode()),
            "diagnostic": detail,
        }

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
        inventory = axiom_audit.expected_inventory(
            run["verification_state"], json.loads(REFERENCE.read_text())
        )
        accepted_uses, hidden_uses, all_uses = (
            axiom_audit.native_use_provenance(inventory)
        )
        body = {
            "schema": "autofv-verifier-report/v1",
            "run_id": run["run_id"],
            "agent_worker_id": run["agent_worker_id"],
            "verifier_worker_id": "verifier-worker-fixture",
            "toolchain_lock_sha256": "2" * 64,
            "bundle_sha256": "3" * 64,
            "reference_sha256": "4" * 64,
            **expected,
            "checks": {name: True for name in verifier_bundle.REPORT_CHECKS},
            "failures": [],
            "native_decide_uses": all_uses,
            "accepted_native_decide_uses": accepted_uses,
            "hidden_native_decide_uses": hidden_uses,
            "compiler_assumptions": verifier.compiler_assumptions(
                experiment.load_toolchain_lock()
            ),
            "axiom_inventory": inventory,
            "axiom_inventory_sha256": (
                axiom_audit.inventory_identity_sha256(inventory)
            ),
            "meaning": {
                "reference_integrity": True,
                "statement_equivalence": True,
                "non_vacuity": True,
                "broken_implementation_rejected": True,
            },
            "sorry_count_before": 1,
            "sorry_count_after": 0,
            "evidence_level": "L4",
            "verdict": "PASS",
        }
        return {**body, "report_sha256": _sha256(experiment.canonical_json_bytes(body))}

    def persist(self, run, result, receipt):
        (self.root / "result.json").write_bytes(experiment.canonical_json_bytes(result) + b"\n")
        evidence = self.root / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "l0.json").write_bytes(experiment.canonical_json_bytes(receipt) + b"\n")


class WorkerBridgeTests(unittest.TestCase):
    def test_concurrent_atomic_writes_use_distinct_temporary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            sources = []
            barrier = threading.Barrier(2)
            replace = os.replace

            def delayed_replace(source, destination):
                sources.append(source)
                barrier.wait(timeout=2)
                replace(source, destination)

            with (
                mock.patch.object(
                    worker_runtime.os, "replace", side_effect=delayed_replace
                ),
                ThreadPoolExecutor(max_workers=2) as pool,
            ):
                writes = [
                    pool.submit(worker_runtime._atomic_write, path, b"same\n")
                    for _ in range(2)
                ]
                for write in writes:
                    write.result(timeout=3)

            self.assertEqual(path.read_bytes(), b"same\n")
            self.assertEqual(len(set(sources)), 2)

    def test_verification_repository_exports_only_the_expected_head(self):
        with mock.patch.object(
            worker_runtime,
            "_git",
            side_effect=(b"a" * 40 + b"\n", b"repository-bundle"),
        ) as git:
            bundle = worker.verification_repository({}, "a" * 40)

        self.assertEqual(bundle, b"repository-bundle")
        self.assertEqual(git.call_count, 2)

        with mock.patch.object(
            worker_runtime, "_git", return_value=b"b" * 40 + b"\n"
        ) as git:
            bundle = worker.verification_repository({}, "a" * 40)

        self.assertIsNone(bundle)
        git.assert_called_once_with({}, "rev-parse", "HEAD")

    def test_worker_errors_keep_command_stdout_and_stderr(self):
        completed = subprocess.CompletedProcess(
            args=("command",),
            returncode=1,
            stdout=b"useful compiler diagnostic\n",
            stderr=b"error: build failed\n",
        )
        with mock.patch.object(subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                worker.WorkerError, "(?s)useful compiler diagnostic.*build failed"
            ):
                worker_runtime._lima("command")

    def test_runsc_commands_use_the_sealed_project_as_workdir(self):
        lock = experiment.load_toolchain_lock()
        argv = worker_runtime._runtime_argv(lock, "test-volume", "true")

        self.assertEqual(argv[argv.index("--workdir") + 1], "/volume/work/project")
        self.assertEqual(argv[argv.index("--pull") + 1], "never")
        self.assertIn("CARGO_NET_OFFLINE=true", argv)

    def test_bridge_keeps_project_rust_atoms_without_is_relevant(self):
        manifest = json.loads((TARGET / "autofv.json").read_text())
        bridge = json.loads(worker.probe_bridge(RUST_PROBE.read_bytes(), manifest))

        self.assertEqual(
            [item["rust_name"] for item in bridge["functions"]],
            [
                "autofv_diamond::left",
                "autofv_diamond::right",
                "autofv_diamond::top",
            ],
        )

    def test_proxy_requests_bind_the_stable_graph_not_raw_probe_bytes(self):
        manifest = json.loads((TARGET / "autofv.json").read_text())
        graph = probes.parse_probe_bytes(
            manifest, RUST_PROBE.read_bytes(), AENEAS_PROBE.read_bytes()
        )
        fixture = json.loads(MODEL_FIXTURE.read_text())
        requests = {
            item["request"]["request_id"]: item["request"]
            for item in fixture["entries"]
        }

        for request_id in ("scout-001", "proof-left-001", "proof-right-001"):
            self.assertIn(graph["graph_sha256"], requests[request_id]["input_hashes"])
            self.assertNotIn(
                graph["probe_aeneas_sha256"], requests[request_id]["input_hashes"]
            )


class VerifierRuntimeTests(unittest.TestCase):
    def test_clean_verifier_uses_fresh_volume_and_pinned_image_without_network(self):
        image = experiment.load_toolchain_lock()["image"]["image_digest"]
        argv = verifier._runtime_argv(image, "fresh-verifier-volume", "lake", "build")

        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--pull") + 1], "never")
        self.assertIn("CARGO_NET_OFFLINE=true", argv)
        self.assertIn(
            "type=volume,src=fresh-verifier-volume,dst=/project,volume-nocopy",
            argv,
        )
        self.assertNotIn("fixture-volume", " ".join(argv))
        self.assertEqual(argv[-3:], (image, "lake", "build"))

    def test_clean_verifier_start_failure_is_a_verifier_error(self):
        failed = subprocess.CompletedProcess(
            args=("limactl", "start", verifier.VERIFIER_VM),
            returncode=1,
            stdout=b"verifier boot failed\n",
            stderr=b"instance unavailable\n",
        )
        with (
            mock.patch.object(subprocess, "run", return_value=failed),
            mock.patch.object(worker, "export_accepted") as export,
            self.assertRaisesRegex(
                verifier.VerifierInfrastructureError,
                "(?s)verifier boot failed.*instance unavailable",
            ),
        ):
            verifier.verify_run({}, {})
        export.assert_not_called()


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
                mock.patch.object(
                    worker,
                    "check_contract_feasibility",
                    seams.check_contract_feasibility,
                ),
                mock.patch.object(worker, "accept_candidate", seams.accept),
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(verifier, "verify_run", seams.verify),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=proxy
                )

            self.assertEqual(result["schema"], "autofv-result/v1")
            self.assertEqual(result["execution_tier"], "simulation")
            self.assertEqual(result["cost_classification"], "synthetic_fixture")
            self.assertEqual((result["outcome"], result["termination_reason"]), ("success", "all_targets_verified"))
            self.assertIsNone(result["termination_detail"])
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
            expected_requests = [
                entry["request"]["request_id"] for entry in self.fixture["entries"]
            ]
            self.assertEqual(proxy.seen[:5], expected_requests[:5])
            self.assertEqual(set(proxy.seen[5:7]), set(expected_requests[5:7]))
            self.assertEqual(proxy.seen[7:], expected_requests[7:])
            self.assertEqual(
                [item["status"] for item in result["accepted_sequence"]],
                ["accepted", "accepted_reverified", "accepted_reverified"],
            )
            self.assertEqual(len(result["processed_candidate_sha256"]), 3)
            lane_results = sorted(Path(tmp).glob("lanes/*/result/candidate.json"))
            self.assertEqual(len(lane_results), 3)
            self.assertTrue(
                all('"patch":' not in path.read_text() for path in lane_results)
            )
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
                    mock.patch.object(
                        worker,
                        "check_contract_feasibility",
                        seams.check_contract_feasibility,
                    ),
                    mock.patch.object(worker, "accept_candidate", seams.accept),
                    mock.patch.object(results, "persist_attempt", seams.persist),
                    mock.patch.object(verifier, "verify_run", verify),
                ):
                    result = experiment.run_experiment(
                        TARGET, TARGET / "run.json", run_round=proxy
                    )
                self.assertNotEqual(result["outcome"], "success")
                self.assertTrue(result["termination_detail"])
                self.assertEqual(result["execution_tier"], "simulation")
                self.assertEqual(result["cost_classification"], "synthetic_fixture")
                self.assertEqual(result["graph_sha256"], probes.parse_probe_bytes(
                    json.loads((TARGET / "autofv.json").read_text()),
                    RUST_PROBE.read_bytes(),
                    AENEAS_PROBE.read_bytes(),
                )["graph_sha256"])
                if mutation == "verifier":
                    self.assertEqual(result["proxy_requests"], 8)
                    self.assertEqual(result["cost_usd"], "0.022350")
                    self.assertEqual(result["accepted_commit"], seams.accepted_commits[-1])
                else:
                    self.assertEqual(result["proxy_requests"], 0)
                    self.assertEqual(result["cost_usd"], "0.000000")

    def test_generic_full_role_slice_preserves_acceptance_and_verifier_order(self):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        lock = _role_test_lock(private_key)
        graph = _generic_graph()
        provider = _SignedRoleProvider(private_key)
        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), self.fixture)
            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(worker, "run_probes", seams.run_probes),
                mock.patch.object(
                    worker,
                    "check_contract_feasibility",
                    seams.check_contract_feasibility,
                ),
                mock.patch.object(worker, "accept_candidate", seams.accept),
                mock.patch.object(worker, "prepare_lanes", return_value=None),
                mock.patch.object(worker, "persist_lane_result", return_value=None),
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(verifier, "verify_run", seams.verify),
                mock.patch.object(probes, "parse_probe_bytes", return_value=graph),
                mock.patch.object(experiment, "load_toolchain_lock", return_value=lock),
                mock.patch.object(contracts, "load_toolchain_lock", return_value=lock),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=provider
                )
            result_exists = (Path(tmp) / "result.json").is_file()
            l0_exists = (Path(tmp) / "evidence" / "l0.json").is_file()

        self.assertEqual(
            (result["outcome"], result["termination_reason"]),
            ("success", "all_targets_verified"),
            result,
        )
        self.assertEqual(result["graph_sha256"], graph["graph_sha256"])
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["proxy_requests"], 12)
        self.assertEqual(result["model_attempts"], 12)
        self.assertEqual(result["internal_specs_accepted"], 2)
        self.assertEqual(result["internal_proofs_accepted"], 2)
        self.assertEqual(len(seams.accepted_commits), 3)
        self.assertEqual(result["accepted_commit"], seams.accepted_commits[-1])
        self.assertEqual(len(result["processed_candidate_sha256"]), 3)
        self.assertEqual(
            [call["sequence"] for call in provider.calls], list(range(1, 13))
        )
        self.assertNotEqual(
            result["agent_worker_id"], result["verifier_worker_id"]
        )
        self.assertTrue(result_exists)
        self.assertTrue(l0_exists)
        self.assertEqual(
            [item["status"] for item in result["accepted_sequence"]],
            ["accepted", "accepted_reverified", "accepted_reverified"],
        )
        self.assertEqual(
            [call["role"] for call in provider.calls],
            [
                "scout",
                "dependency_planner",
                "specifier",
                "specifier",
                "spec_reviewer",
                "prover",
                "proof_reviewer",
                "prover",
                "proof_reviewer",
                "prover",
                "proof_reviewer",
                "verification_adviser",
            ],
        )
        role_events = [
            event
            for event in result["events"]
            if event.startswith(("role:", "lane_tool:", "candidate_", "clean_verifier:"))
        ]
        expected_events = []
        for role in (
            "scout",
            "dependency_planner",
            "specifier",
            "specifier",
            "spec_reviewer",
            "prover",
            "proof_reviewer",
        ):
            expected_events.extend(
                (
                    f"role:{role}:started",
                    f"lane_tool:{role}:submit_candidate",
                    f"role:{role}:candidate",
                )
            )
        expected_events.append("candidate_accepted:proof-left-001")
        for role in ("prover", "proof_reviewer"):
            expected_events.extend(
                (
                    f"role:{role}:started",
                    f"lane_tool:{role}:submit_candidate",
                    f"role:{role}:candidate",
                )
            )
        expected_events.append("candidate_accepted_reverified:proof-right-001")
        for role in ("prover", "proof_reviewer"):
            expected_events.extend(
                (
                    f"role:{role}:started",
                    f"lane_tool:{role}:submit_candidate",
                    f"role:{role}:candidate",
                )
            )
        expected_events.append("candidate_accepted_reverified:proof-top-001")
        expected_events.extend(
            (
                "role:verification_adviser:started",
                "lane_tool:verification_adviser:submit_candidate",
                "role:verification_adviser:candidate",
                "clean_verifier:PASS",
            )
        )
        self.assertEqual(role_events, expected_events)

    def test_controller_interrupt_persists_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), self.fixture)
            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH,
                    "stream",
                    side_effect=KeyboardInterrupt,
                ),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=lambda request: request
                )

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(result["termination_reason"], "interrupted")
            self.assertEqual(result["termination_detail"], "controller interrupted")
            self.assertTrue((Path(tmp) / "result.json").is_file())

    def test_clean_verifier_boundary_failure_is_infrastructure(self):
        with tempfile.TemporaryDirectory() as tmp:
            seams = _Seams(Path(tmp), self.fixture)
            with (
                mock.patch.object(worker, "prepare_run", seams.prepare),
                mock.patch.object(results, "persist_attempt", seams.persist),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH,
                    "stream",
                    side_effect=verifier.VerifierInfrastructureError(
                        "clean verifier failed to start"
                    ),
                ),
            ):
                result = experiment.run_experiment(
                    TARGET, TARGET / "run.json", run_round=lambda request: request
                )

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(
                result["termination_reason"],
                "clean_verifier_infrastructure_failed",
            )


class Phase1DiamondTests(unittest.TestCase):
    def test_one_full_sealed_concurrent_diamond(self):
        from tests.test_model_proxy_fixture import (
            PROOF_PAIR,
            RUN_ID,
            RUN_TOKEN,
            _trusted_proxy,
        )

        fixture = json.loads(MODEL_FIXTURE.read_text())
        lock = experiment.load_toolchain_lock()
        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            reservation.bind(("127.0.0.1", 0))
        except PermissionError as exc:
            self.skipTest(f"managed sandbox forbids loopback bind: {exc}")
        finally:
            reservation.close()
        ledger_root = Path(tempfile.mkdtemp(prefix="autofv-phase1-ledger-"))
        ledger = ledger_root / "attempts.jsonl"
        barrier = threading.Barrier(2)
        with _trusted_proxy(
            fixture, lock["fixed_proxy"], barrier=barrier
        ) as (base_url, program, audit):
            port = urllib.parse.urlsplit(base_url).port
            environment = {
                "AUTOFV_ATTEMPT_LEDGER": str(ledger),
                "AUTOFV_PROXY_BASE": f"http://192.168.5.2:{port}",
                "AUTOFV_RUN_ID": RUN_ID,
                "AUTOFV_RUN_TOKEN": RUN_TOKEN,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                result = experiment.run_experiment(TARGET, TARGET / "run.json")

        self.assertEqual(
            (result["outcome"], result["termination_reason"]),
            ("success", "all_targets_verified"),
            result.get("termination_detail"),
        )
        self.assertEqual(result["execution_tier"], "sealed_runsc")
        self.assertTrue(result["scored"])
        self.assertEqual(result["evidence_level"], "L4")
        self.assertEqual(result["claim"]["status"], "supported")
        self.assertEqual(result["missing_evidence"], [])
        self.assertEqual(result["sorry_counts"], {"before": 1, "after": 0})
        self.assertEqual(result["proxy_requests"], 8)
        self.assertEqual(result["cost_usd"], "0.022350")
        self.assertEqual(audit["stripped_run_credentials"], 8)

        intervals = [program.intervals[request_id] for request_id in PROOF_PAIR]
        self.assertLess(
            max(start for start, _ in intervals),
            min(end for _, end in intervals),
        )
        self.assertEqual(
            [item["status"] for item in result["accepted_sequence"]],
            ["accepted", "accepted_reverified", "accepted_reverified"],
        )

        run_root = Path(result["run_root"])
        report = json.loads((run_root / "evidence/verifier.json").read_text())
        egress = json.loads((run_root / "evidence/egress.json").read_text())
        self.assertEqual(report["accepted_commit"], result["accepted_commit"])
        self.assertNotEqual(report["agent_worker_id"], report["verifier_worker_id"])
        self.assertTrue(report["checks"]["runtime_identity"])
        self.assertEqual(
            egress["policy"]["upstream_policy_sha256"],
            egress["upstream_policy"]["policy_sha256"],
        )
        self.assertTrue(
            all(
                case["blocked"]
                for layer in (
                    "upstream_denied",
                    "worker_denied",
                    "container_denied",
                )
                for case in egress[layer]
            )
        )
        self.assertTrue((run_root / "result.json").is_file())
        self.assertTrue((run_root / "evidence/l0.json").is_file())
        self.assertEqual(len(ledger.read_text().splitlines()), 1)
        self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))


if __name__ == "__main__":
    unittest.main()
