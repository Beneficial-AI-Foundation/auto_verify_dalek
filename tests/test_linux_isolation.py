from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from autofv import experiment, worker
from tests.test_model_proxy_fixture import (
    FIXTURE_PATH as MODEL_FIXTURE_PATH,
    RUN_TOKEN,
    _trusted_proxy,
)
from tests.test_phase1_diamond import TARGET


ROOT = Path(__file__).resolve().parents[1]
EGRESS_FIXTURE = ROOT / "tests/fixtures/linux-isolation/egress-targets.json"
LOCK = experiment.load_toolchain_lock()
MODEL_FIXTURE = json.loads(MODEL_FIXTURE_PATH.read_text(encoding="utf-8"))
FIRST_REQUEST = MODEL_FIXTURE["entries"][0]["request"]


class LinuxIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(EGRESS_FIXTURE.read_text(encoding="utf-8"))
        self.manifest = json.loads((TARGET / "autofv.json").read_text(encoding="utf-8"))

    def prepare(self, run_id: str = "fixture-diamond-run-0001") -> dict:
        with mock.patch.dict(os.environ, {"AUTOFV_RUN_ID": run_id}, clear=False):
            return worker.prepare_run(TARGET, self.manifest, LOCK)

    def test_fixture_covers_the_four_denied_classes_and_locked_route(self) -> None:
        self.assertEqual(self.fixture["schema"], "autofv-linux-isolation-fixture/v1")
        self.assertEqual(
            [case["id"] for case in self.fixture["denied"]],
            ["external_dns", "literal_ipv4", "literal_ipv6", "link_local_metadata"],
        )
        self.assertEqual(
            self.fixture["fixed_proxy"],
            {
                "method": LOCK["fixed_proxy"]["method"],
                "path": LOCK["fixed_proxy"]["path"],
            },
        )

    def test_worker_contract_rejects_mutable_or_mismatched_inputs(self) -> None:
        run = self.prepare("worker-contract-001")
        try:
            inventory = run["worker_inventory"]
            self.assertEqual(inventory["platform"], "linux")
            self.assertEqual(
                inventory["resources"],
                {"containers": [], "volumes": [], "networks": []},
            )
            self.assertEqual(inventory["run_id"], run["run_id"])
            self.assertEqual(inventory["image_digest"], LOCK["image"]["image_digest"])
            self.assertEqual(inventory["runtime"], LOCK["tools"]["runsc"]["runtime_name"])
            self.assertEqual(inventory["runtime_args"], LOCK["tools"]["runsc"]["runtime_args"])

            mutations = []
            tagged = copy.deepcopy(LOCK)
            tagged["image"]["image_digest"] = "autofv-toolchain:latest"
            mutations.append(("immutable image digest", tagged))
            bad_runtime = copy.deepcopy(LOCK)
            bad_runtime["tools"]["runsc"]["runtime_name"] = "runc"
            mutations.append(("runsc", bad_runtime))
            bad_policy = copy.deepcopy(LOCK)
            bad_policy["native_decide_policy_sha256"] = "0" * 64
            mutations.append(("policy", bad_policy))
            bad_bundle = copy.deepcopy(LOCK)
            bad_bundle["controller_delivery"]["allowed_members"] = []
            mutations.append(("control bundle", bad_bundle))
            for message, lock in mutations:
                with self.subTest(message=message), self.assertRaisesRegex(
                    worker.WorkerError, message
                ):
                    worker.inspect_worker(lock, run_id=run["run_id"])
        finally:
            worker.dispose_run(run, interrupted=True)
        self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))

    def test_runtime_inspection_and_external_deny_matrix(self) -> None:
        route = LOCK["fixed_proxy"]
        with _trusted_proxy(MODEL_FIXTURE, route) as (base_url, _, audit):
            port = urllib.parse.urlsplit(base_url).port
            run = self.prepare()
            try:
                proxy_base = f"http://{worker.lima_host_address()}:{port}"
                with mock.patch.dict(
                    os.environ,
                    {"AUTOFV_PROXY_BASE": proxy_base, "AUTOFV_RUN_TOKEN": RUN_TOKEN},
                    clear=False,
                ):
                    runtime = worker.inspect_scored_container(run)
                    matrix = worker.run_egress_matrix(run, self.fixture, FIRST_REQUEST)
            finally:
                worker.dispose_run(run, interrupted=True)

        self.assertEqual(runtime["runtime"], LOCK["tools"]["runsc"]["runtime_name"])
        self.assertTrue(runtime["read_only_root"])
        self.assertEqual(runtime["user"], "65532:65532")
        self.assertEqual(runtime["volume"], run["volume"])
        self.assertEqual(runtime["mount_count"], 1)
        self.assertEqual(runtime["bind_mounts"], [])
        self.assertEqual(runtime["runtime_sockets"], [])
        self.assertEqual(runtime["cap_add"], [])
        self.assertEqual(runtime["cap_drop"], ["ALL"])
        self.assertEqual(runtime["pids_limit"], 256)
        self.assertEqual(runtime["memory_bytes"], 2 * 1024**3)
        self.assertEqual(runtime["nano_cpus"], 2_000_000_000)
        self.assertEqual(
            matrix["policy"]["enforcer"],
            "worker-firewall-and-docker-internal-network",
        )
        for layer in ("worker_denied", "container_denied"):
            self.assertEqual(
                [case["id"] for case in matrix[layer]],
                [case["id"] for case in self.fixture["denied"]],
            )
            self.assertTrue(all(case["blocked"] for case in matrix[layer]))
        self.assertEqual(matrix["fixed_proxy"]["status"], "ok")
        self.assertEqual(matrix["fixed_proxy"]["request_id"], FIRST_REQUEST["request_id"])
        self.assertEqual(audit["stripped_run_credentials"], 1)
        self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))

    def test_claim_collision_and_export_before_disposal(self) -> None:
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted), tempfile.TemporaryDirectory() as tmp:
                with mock.patch.object(worker.tempfile, "mkdtemp", return_value=tmp):
                    run = self.prepare(f"export-order-{int(interrupted)}")
                disposed = False
                try:
                    with self.assertRaisesRegex(worker.WorkerError, "already claimed"):
                        worker.claim_worker(
                            {
                                **run,
                                "run_id": "second-run",
                                "volume": f"{run['volume']}-collision",
                            }
                        )

                    export = worker.export_run(run, interrupted=interrupted)
                    if interrupted:
                        worker._docker(
                            *worker._runtime_argv(
                                LOCK,
                                run["volume"],
                                "sh",
                                "-c",
                                "printf '\n-- changed after export\n' >> Diamond/Left.lean",
                            )
                        )
                        with self.assertRaisesRegex(
                            worker.WorkerError, "changed after export"
                        ):
                            worker.dispose_run(run, interrupted=True)
                        self.assertIsNotNone(
                            worker.inspect_lima_instance(worker.AGENT_VM)
                        )
                        worker._git(run, "reset", "--hard", run["accepted"]["accepted_commit"])
                    disposal = worker.dispose_run(run, interrupted=interrupted)
                    disposed = True
                finally:
                    if not disposed:
                        worker.dispose_run(run, interrupted=True)

                self.assertEqual(export["schema"], "autofv-export/v1")
                self.assertTrue(export["verified_before_disposal"])
                self.assertEqual(disposal["schema"], "autofv-disposal/v1")
                self.assertEqual(
                    disposal["export_manifest_sha256"], export["manifest_sha256"]
                )
                self.assertEqual(disposal["interrupted"], interrupted)
                self.assertLess(export["sequence"], disposal["sequence"])
                self.assertTrue(disposal["worker_absent"])
                self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))
                if interrupted:
                    try:
                        observed = worker.inspect_resume_state(run, self.manifest)
                        self.assertTrue(observed["valid"])
                        self.assertEqual(
                            observed["accepted_commit"], run["accepted"]["accepted_commit"]
                        )
                    finally:
                        worker.dispose_run(run, interrupted=True)

    def test_dirty_working_state_survives_export_and_worker_recreation(self) -> None:
        run = self.prepare("dirty-recovery-001")
        try:
            worker._docker(
                *worker._runtime_argv(
                    LOCK,
                    run["volume"],
                    "sh",
                    "-c",
                    "printf '\\n-- retained working state\\n' >> Diamond/Left.lean; "
                    "printf retained > recovery-note.txt",
                )
            )
            worker.dispose_run(run, interrupted=True)
            self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))

            observed = worker.inspect_resume_state(run, self.manifest)
            self.assertTrue(observed["valid"])
            self.assertTrue(observed["dirty"])
            self.assertIn(
                b"retained working state",
                worker.read_project_file(run, "Diamond/Left.lean"),
            )
            self.assertEqual(worker.read_project_file(run, "recovery-note.txt"), b"retained")
        finally:
            if worker.inspect_lima_instance(worker.AGENT_VM) is not None:
                worker._git(run, "reset", "--hard", run["accepted"]["accepted_commit"])
                worker._git(run, "clean", "-ffd")
                worker.dispose_run(run, interrupted=True)

    def test_export_rejects_unaccepted_head_without_destroying_worker(self) -> None:
        run = self.prepare("unaccepted-head-001")
        try:
            worker._docker(
                *worker._runtime_argv(
                    LOCK,
                    run["volume"],
                    "sh",
                    "-c",
                    "printf '\\n-- unaccepted commit\\n' >> Diamond/Left.lean",
                )
            )
            worker._git(run, "add", "--", "Diamond/Left.lean")
            worker._git(
                run,
                "-c",
                "user.name=AutoFV test",
                "-c",
                "user.email=autofv-test@invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "unaccepted",
            )
            with self.assertRaisesRegex(worker.WorkerError, "accepted commit"):
                worker.dispose_run(run, interrupted=True)
            self.assertIsNotNone(worker.inspect_lima_instance(worker.AGENT_VM))
        finally:
            if worker.inspect_lima_instance(worker.AGENT_VM) is not None:
                worker._git(run, "reset", "--hard", run["accepted"]["accepted_commit"])
                worker.dispose_run(run, interrupted=True)

    def test_export_rejects_symlinked_host_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "elsewhere").mkdir()
            (root / "evidence/linked-directory").symlink_to(
                root / "elsewhere", target_is_directory=True
            )
            with self.assertRaisesRegex(worker.WorkerError, "not a regular file"):
                worker._host_artifacts({"run_root": tmp})

    def test_interrupted_result_marks_disposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = {
                "run_root": tmp,
                "execution_tier": "sealed_runsc",
                "base_commit": "1" * 40,
            }
            result = {"termination_reason": "interrupted"}
            with mock.patch.object(worker, "dispose_run") as dispose:
                worker.persist_result(run, result, {})

            dispose.assert_called_once_with(run, interrupted=True)

    def test_preparation_failure_destroys_worker_but_export_failure_retains_it(self) -> None:
        _, control_manifest, snapshot_sha256 = worker._seed_archive(TARGET, LOCK)
        with mock.patch.object(
            worker,
            "_seed_archive",
            return_value=(b"not a tar archive", control_manifest, snapshot_sha256),
        ):
            with self.assertRaises(worker.WorkerError) as raised:
                self.prepare("failed-prepare-001")
        failed_run = raised.exception.run
        self.assertIsNotNone(failed_run)
        self.assertTrue(failed_run["worker_disposed"])
        self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))

        run = self.prepare("failed-export-001")
        try:
            run["artifact_scan_markers"] = ("synthetic-blocked-marker",)
            worker._docker(
                *worker._runtime_argv(
                    LOCK,
                    run["volume"],
                    "sh",
                    "-c",
                    "printf synthetic-blocked-marker >> Diamond/Left.lean",
                )
            )
            with self.assertRaisesRegex(worker.WorkerError, "forbidden material"):
                worker.dispose_run(run, interrupted=True)
            self.assertFalse(run.get("worker_disposed", False))
            self.assertIsNotNone(worker.inspect_lima_instance(worker.AGENT_VM))
        finally:
            if worker.inspect_lima_instance(worker.AGENT_VM) is not None:
                worker._git(run, "reset", "--hard", run["accepted"]["accepted_commit"])
                run.pop("artifact_scan_markers", None)
                worker.dispose_run(run, interrupted=True)


if __name__ == "__main__":
    unittest.main()
