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
        inventory = worker.inspect_worker(LOCK)
        self.assertEqual(inventory["platform"], "linux")
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
                worker.inspect_worker(lock)

    def test_runtime_inspection_and_external_deny_matrix(self) -> None:
        route = LOCK["fixed_proxy"]
        with _trusted_proxy(MODEL_FIXTURE, route) as (base_url, _, audit):
            port = urllib.parse.urlsplit(base_url).port
            proxy_base = f"http://{worker.lima_host_address()}:{port}"
            with mock.patch.dict(
                os.environ,
                {"AUTOFV_PROXY_BASE": proxy_base, "AUTOFV_RUN_TOKEN": RUN_TOKEN},
                clear=False,
            ):
                run = worker.prepare_run(TARGET, self.manifest, LOCK)
                try:
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
            [case["id"] for case in matrix["denied"]],
            [case["id"] for case in self.fixture["denied"]],
        )
        self.assertTrue(all(case["blocked"] for case in matrix["denied"]))
        self.assertEqual(matrix["fixed_proxy"]["status"], "ok")
        self.assertEqual(matrix["fixed_proxy"]["request_id"], FIRST_REQUEST["request_id"])
        self.assertEqual(audit["stripped_run_credentials"], 1)

    def test_claim_collision_and_export_before_disposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(worker.tempfile, "mkdtemp", return_value=tmp):
                run = worker.prepare_run(TARGET, self.manifest, LOCK)
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

                export = worker.export_run(run, interrupted=True)
                disposal = worker.dispose_run(run, interrupted=True)
                disposed = True
            finally:
                if not disposed:
                    worker.dispose_run(run, interrupted=True)

            self.assertEqual(export["schema"], "autofv-export/v1")
            self.assertTrue(export["verified_before_disposal"])
            self.assertEqual(disposal["schema"], "autofv-disposal/v1")
            self.assertEqual(disposal["export_manifest_sha256"], export["manifest_sha256"])
            self.assertTrue(disposal["interrupted"])
            self.assertLess(export["sequence"], disposal["sequence"])


if __name__ == "__main__":
    unittest.main()
