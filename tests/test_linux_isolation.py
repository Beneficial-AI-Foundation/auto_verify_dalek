from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.parse
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import (
    experiment,
    model,
    preflight,
    results,
    worker,
    worker_artifacts,
    worker_proxy,
    worker_runtime,
)
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


def _require_loopback_bind(test_case: unittest.TestCase) -> None:
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        reservation.bind(("127.0.0.1", 0))
    except PermissionError as exc:
        test_case.skipTest(f"managed sandbox forbids loopback bind: {exc}")
    finally:
        reservation.close()


class UpstreamPolicyTests(unittest.TestCase):
    def test_seatbelt_profile_allows_only_the_worker_and_proxy_ports(self) -> None:
        profile = worker_runtime._seatbelt_profile(
            Path("/Users/ada/.lima/autofv-agent-run"),
            ssh_port=61593,
            proxy_port=61234,
        )

        self.assertIn("(deny network-outbound)", profile)
        self.assertIn('(remote ip "localhost:61593")', profile)
        self.assertIn('(remote ip "localhost:61234")', profile)
        self.assertIn(
            '(remote unix-socket (subpath "/Users/ada/.lima/autofv-agent-run"))',
            profile,
        )
        self.assertNotIn("localhost:*", profile)


class LinuxIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(EGRESS_FIXTURE.read_text(encoding="utf-8"))
        self.manifest = json.loads((TARGET / "autofv.json").read_text(encoding="utf-8"))

    def prepare(self, run_id: str = "fixture-diamond-run-0001") -> dict:
        _require_loopback_bind(self)
        with mock.patch.dict(os.environ, {"AUTOFV_RUN_ID": run_id}, clear=False):
            return worker.prepare_run(TARGET, self.manifest, LOCK)

    def test_fixture_covers_the_four_denied_classes_and_locked_route(self) -> None:
        self.assertEqual(self.fixture["schema"], "autofv-linux-isolation-fixture/v1")
        self.assertEqual(
            self.fixture["denied"],
            worker_proxy._egress_fixture({"lock": LOCK})["denied"],
        )
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
            self.assertEqual(inventory["forbidden_guest_paths"], [])
            self.assertEqual(inventory["image_digest"], LOCK["image"]["image_digest"])
            self.assertEqual(inventory["runtime"], LOCK["tools"]["runsc"]["runtime_name"])
            self.assertEqual(inventory["runtime_args"], LOCK["tools"]["runsc"]["runtime_args"])
            scored = run["scored_container_receipt"]
            self.assertEqual(scored["schema"], "autofv-scored-container/v1")
            self.assertEqual(scored["run_id"], run["run_id"])
            self.assertTrue(
                (Path(run["evidence_dir"]) / "scored-container.json").is_file()
            )

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
        _require_loopback_bind(self)
        route = LOCK["fixed_proxy"]
        with _trusted_proxy(MODEL_FIXTURE, route) as (base_url, _, audit):
            port = urllib.parse.urlsplit(base_url).port
            with mock.patch.dict(
                os.environ,
                {"AUTOFV_PROXY_BASE": base_url, "AUTOFV_RUN_TOKEN": RUN_TOKEN},
                clear=False,
            ):
                run = self.prepare()
            try:
                proxy_base = f"http://{worker.lima_host_address()}:{port}"
                with mock.patch.dict(
                    os.environ,
                    {"AUTOFV_PROXY_BASE": proxy_base, "AUTOFV_RUN_TOKEN": RUN_TOKEN},
                    clear=False,
                ):
                    runtime = worker.inspect_scored_container(run)
                    matrix = worker.run_egress_matrix(run, self.fixture)
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
            "upstream-default-deny+worker-firewall+docker-internal-network",
        )
        self.assertEqual(
            matrix["policy"]["upstream_policy_sha256"],
            run["upstream_policy_sha256"],
        )
        for layer in ("upstream_denied", "worker_denied", "container_denied"):
            self.assertEqual(
                [case["id"] for case in matrix[layer]],
                [case["id"] for case in self.fixture["denied"]],
            )
            self.assertTrue(all(case["blocked"] for case in matrix[layer]))
        self.assertEqual(matrix["fixed_proxy"]["status"], "reachable")
        self.assertEqual(matrix["fixed_proxy"]["probe_status"], 400)
        self.assertEqual(audit["stripped_run_credentials"], 0)
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
                        worker_runtime._docker(
                            *worker_runtime._runtime_argv(
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
                        worker_runtime._git(
                            run,
                            "reset",
                            "--hard",
                            run["accepted"]["accepted_commit"],
                        )
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
            worker_runtime._docker(
                *worker_runtime._runtime_argv(
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
                worker_runtime._git(
                    run, "reset", "--hard", run["accepted"]["accepted_commit"]
                )
                worker_runtime._git(run, "clean", "-ffd")
                worker.dispose_run(run, interrupted=True)

    def test_export_rejects_unaccepted_head_without_destroying_worker(self) -> None:
        run = self.prepare("unaccepted-head-001")
        try:
            worker_runtime._docker(
                *worker_runtime._runtime_argv(
                    LOCK,
                    run["volume"],
                    "sh",
                    "-c",
                    "printf '\\n-- unaccepted commit\\n' >> Diamond/Left.lean",
                )
            )
            worker_runtime._git(run, "add", "--", "Diamond/Left.lean")
            worker_runtime._git(
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
                worker_runtime._git(
                    run, "reset", "--hard", run["accepted"]["accepted_commit"]
                )
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
                worker_artifacts._host_artifacts({"run_root": tmp})

    def test_interrupted_result_marks_disposal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = {
                "attempt_id": "attempt-interrupted",
                "attempt_ledger": str(Path(tmp) / "attempts.jsonl"),
                "run_id": "interrupted-run",
                "run_root": tmp,
                "execution_tier": "sealed_runsc",
                "cost_classification": "synthetic_fixture",
                "base_commit": "1" * 40,
                "events": [],
            }
            state = {
                "run": run,
                "config": {},
                "receipts": [],
                "checkpoint_enabled": False,
            }
            with (
                mock.patch.object(worker, "dispose_run") as dispose,
                mock.patch.object(results, "materialize_accepted"),
                mock.patch.object(results, "persist_attempt") as persist,
            ):
                result = experiment._finish_attempt(
                    run,
                    state,
                    outcome="infrastructure_failed",
                    reason="interrupted",
                )

            dispose.assert_called_once_with(run, interrupted=True)
            persist.assert_called_once()
            self.assertEqual(result["termination_reason"], "interrupted")

    def test_preparation_failure_destroys_worker_but_export_failure_retains_it(self) -> None:
        _, control_manifest, snapshot_sha256 = worker_runtime._seed_archive(
            TARGET, LOCK
        )
        with mock.patch.object(
            worker_runtime,
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
            worker_runtime._docker(
                *worker_runtime._runtime_argv(
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
                worker_runtime._git(
                    run, "reset", "--hard", run["accepted"]["accepted_commit"]
                )
                run.pop("artifact_scan_markers", None)
                worker.dispose_run(run, interrupted=True)


class ProxyAccountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(EGRESS_FIXTURE.read_text(encoding="utf-8"))
        self.manifest = json.loads((TARGET / "autofv.json").read_text(encoding="utf-8"))

    @staticmethod
    def proxy_run(root: str) -> dict:
        return {
            "run_id": FIRST_REQUEST["run_id"],
            "run_root": root,
            "volume": "fixture-volume",
            "lock": copy.deepcopy(LOCK),
            "image_digest": LOCK["image"]["image_digest"],
            "control_bundle_sha256": LOCK["controller_delivery"]["bundle_sha256"],
            "native_decide_policy_sha256": LOCK["native_decide_policy_sha256"],
            "worker_inventory_sha256": "1" * 64,
            "fixed_proxy_sha256": hashlib.sha256(
                experiment.canonical_json_bytes(LOCK["fixed_proxy"])
            ).hexdigest(),
            "events": [],
        }

    def test_request_envelope_rejects_caller_controlled_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = self.proxy_run(tmp)
            self.assertEqual(
                worker_proxy._validate_proxy_request(run, FIRST_REQUEST),
                hashlib.sha256(
                    experiment.canonical_json_bytes(FIRST_REQUEST)
                ).hexdigest(),
            )

            for capability in (
                *LOCK["fixed_proxy"]["forbidden_caller_capabilities"],
                "unclassified_surface",
            ):
                request = copy.deepcopy(FIRST_REQUEST)
                request[capability] = "caller-controlled"
                with self.subTest(capability=capability), self.assertRaisesRegex(
                    worker.WorkerError, "fields"
                ):
                    worker_proxy._validate_proxy_request(run, request)

            wrong_run = copy.deepcopy(FIRST_REQUEST)
            wrong_run["run_id"] = "caller-selected-run"
            with self.assertRaisesRegex(worker.WorkerError, "identity"):
                worker_proxy._validate_proxy_request(run, wrong_run)

            run["lock"]["fixed_proxy"]["path"] = "/v1/caller-selected"
            with self.assertRaisesRegex(worker.WorkerError, "policy"):
                worker_proxy._validate_proxy_request(run, FIRST_REQUEST)

            worker_proxy._bind_proxy_client_identity(run, "first-run-scoped-token")
            with self.assertRaisesRegex(worker.WorkerError, "client identity"):
                worker_proxy._bind_proxy_client_identity(run, "replacement-token")

    def test_proxy_transport_failure_is_explicit_hash_only_evidence(self) -> None:
        cases = (
            ("authentication_error", 401),
            ("rate_limited", 429),
            ("timeout", 504),
            ("upstream_error", 502),
            ("malformed_response", None),
        )
        for classification, status_code in cases:
            with self.subTest(
                classification=classification
            ), tempfile.TemporaryDirectory() as tmp:
                run = self.proxy_run(tmp)
                stdout = (
                    b"not-json"
                    if classification == "malformed_response"
                    else experiment.canonical_json_bytes(
                        {
                            "proxy_error": {
                                "classification": classification,
                                "status_code": status_code,
                            }
                        }
                    )
                )
                completed = subprocess.CompletedProcess(
                    ("docker", "run"),
                    0,
                    stdout=stdout,
                    stderr=b"synthetic-provider-secret-must-not-be-retained",
                )
                with (
                    mock.patch.object(
                        worker_proxy,
                        "_ensure_proxy_relay",
                        return_value=("net", "10.0.0.2"),
                    ),
                    mock.patch.object(
                        worker_proxy, "_docker", return_value=completed
                    ),
                    self.assertRaisesRegex(worker.WorkerError, classification),
                ):
                    worker.proxy_round(run, FIRST_REQUEST)

                records = list(
                    (Path(tmp) / "evidence" / "proxy-errors").glob("*.json")
                )
                self.assertEqual(len(records), 1)
                raw = records[0].read_bytes()
                self.assertNotIn(b"synthetic-provider-secret", raw)
                record = json.loads(raw)
                body = {
                    key: value
                    for key, value in record.items()
                    if key != "error_sha256"
                }
                self.assertEqual(record["classification"], classification)
                self.assertEqual(record["status_code"], status_code)
                self.assertEqual(record["run_id"], FIRST_REQUEST["run_id"])
                self.assertEqual(record["request_id"], FIRST_REQUEST["request_id"])
                self.assertEqual(
                    record["error_sha256"],
                    hashlib.sha256(experiment.canonical_json_bytes(body)).hexdigest(),
                )

    def test_invalid_receipt_never_enters_pending_or_checkpoint_state(self) -> None:
        entry = copy.deepcopy(MODEL_FIXTURE["entries"][0])
        secret = "synthetic-provider-secret-in-invalid-receipt"
        entry["receipt"]["authorization"] = secret
        with tempfile.TemporaryDirectory() as tmp:
            run = self.proxy_run(tmp)
            run["base_commit"] = MODEL_FIXTURE["git"]["base_commit"]
            state = {
                "run": run,
                "config": {
                    "model": MODEL_FIXTURE["model_id"],
                    "max_cost_usd": Decimal("1.000000"),
                    "max_wall_seconds": 300,
                },
                "run_round": lambda _request: (entry["response"], entry["receipt"]),
                "receipts": [],
                "cost": Decimal("0.000000"),
                "receipt_rejections": [],
                "pending_model_exchanges": {},
                "model_exchanges": {},
                "checkpoint_enabled": False,
            }
            with self.assertRaises(experiment.ContractError):
                experiment._model_request(
                    state,
                    request_id=entry["request"]["request_id"],
                    role=entry["request"]["role"],
                    input_hashes=entry["request"]["input_hashes"],
                )

            self.assertEqual(state["pending_model_exchanges"], {})
            self.assertEqual(state["receipts"], [])
            self.assertEqual(state["cost"], Decimal("0.000000"))
            retained = {
                key: state[key]
                for key in (
                    "pending_model_exchanges",
                    "model_exchanges",
                    "receipts",
                    "receipt_rejections",
                )
            }
            self.assertNotIn(
                secret.encode(), experiment.canonical_json_bytes(retained)
            )
            self.assertEqual(len(state["receipt_rejections"]), 1)

    def test_real_proxy_policy_accounting_and_retained_surface_scans(self) -> None:
        _require_loopback_bind(self)
        provider_marker = "synthetic-provider-secret-never-forward"
        fixture_marker = MODEL_FIXTURE_PATH.read_bytes()
        surface_marker = "synthetic-retained-surface-leak"
        run = None
        with _trusted_proxy(MODEL_FIXTURE, LOCK["fixed_proxy"]) as (
            base_url,
            program,
            audit,
        ):
            audit["provider_credential"] = provider_marker
            port = urllib.parse.urlsplit(base_url).port
            with mock.patch.dict(
                os.environ,
                {
                    "AUTOFV_PROXY_BASE": base_url,
                    "AUTOFV_RUN_ID": FIRST_REQUEST["run_id"],
                    "AUTOFV_RUN_TOKEN": RUN_TOKEN,
                },
                clear=False,
            ):
                run = worker.prepare_run(TARGET, self.manifest, LOCK)
            try:
                proxy_base = f"http://{worker.lima_host_address()}:{port}"
                with mock.patch.dict(
                    os.environ,
                    {"AUTOFV_PROXY_BASE": proxy_base, "AUTOFV_RUN_TOKEN": RUN_TOKEN},
                    clear=False,
                ):
                    with mock.patch.object(
                        worker_proxy,
                        "_RELAY_PROGRAM",
                        worker_proxy._RELAY_PROGRAM.replace(
                            "timeout=30", "timeout=1"
                        ),
                    ):
                        policy = worker.run_proxy_policy_matrix(run, self.fixture)
                    state = {
                        "run": run,
                        "config": {
                            "model": MODEL_FIXTURE["model_id"],
                            "max_cost_usd": Decimal("1.000000"),
                        },
                        "receipts": [],
                        "cost": Decimal("0.000000"),
                        "receipt_rejections": [],
                        "pending_model_exchanges": {},
                        "model_exchanges": {},
                        "checkpoint_enabled": False,
                    }
                    for entry in MODEL_FIXTURE["entries"]:
                        response, receipt = worker.proxy_round(run, entry["request"])
                        experiment._accept_model_exchange(
                            state, entry["request"], response, receipt
                        )

                    result, _ = results.render_attempt(
                        run,
                        state,
                        outcome="success",
                        reason="proxy_matrix_complete",
                    )
                    self.assertEqual(
                        [case["id"] for case in policy["rejected"]],
                        [case["id"] for case in self.fixture["rejected_proxy"]],
                    )
                    self.assertTrue(all(case["blocked"] for case in policy["rejected"]))
                    self.assertEqual(state["cost"], Decimal("0.022350"))
                    self.assertEqual(result["proxy_requests"], 8)
                    self.assertEqual(result["cost_usd"], "0.022350")
                    self.assertEqual(audit["stripped_run_credentials"], 8)
                    self.assertEqual(audit["forwarded_headers"], [{}] * 8)
                    self.assertEqual(audit["provider_credential"], provider_marker)
                    self.assertRegex(run["proxy_client_identity_sha256"], r"^[0-9a-f]{64}$")

                    run["artifact_scan_markers"] = (provider_marker, fixture_marker)
                    artifacts = worker_artifacts._export_artifacts(run)
                    scan = worker.scan_retained_state(
                        run, artifacts, run["artifact_scan_markers"]
                    )
                    self.assertTrue(scan["clean"])
                    self.assertEqual(
                        scan["scanned_surfaces"],
                        [
                            "environment",
                            "filesystem",
                            "log",
                            "transcript",
                            "state",
                            "result",
                            "export",
                        ],
                    )

                    with self.assertRaisesRegex(worker.WorkerError, "environment"):
                        worker.scan_retained_state(run, artifacts, (RUN_TOKEN,))

                    worker_runtime._docker(
                        *worker_runtime._runtime_argv(
                            LOCK,
                            run["volume"],
                            "sh",
                            "-eu",
                            "-c",
                            "printf %s \"$1\" > leak.txt; "
                            "printf %s \"$1\" > /volume/logs/agent.log; "
                            "printf %s \"$1\" > /volume/evidence/transcript.jsonl",
                            "sh",
                            surface_marker,
                        )
                    )
                    run["synthetic_state"] = surface_marker
                    result_path = Path(run["run_root"]) / "result.json"
                    result_path.write_text(surface_marker, encoding="utf-8")
                    leaked_artifacts = worker_artifacts._export_artifacts(run)
                    with self.assertRaises(worker.WorkerError) as leaked:
                        worker.scan_retained_state(
                            run, leaked_artifacts, (surface_marker,)
                        )
                    for surface in (
                        "filesystem",
                        "log",
                        "transcript",
                        "state",
                        "result",
                        "export",
                    ):
                        self.assertIn(surface, str(leaked.exception))

                    timeout_request = copy.deepcopy(FIRST_REQUEST)
                    timeout_request["sequence"] = 9
                    timeout_request["request_id"] = "timeout-probe"
                    timeout_request["prompt_sha256"] = hashlib.sha256(
                        (
                            f"{timeout_request['run_id']}\0timeout-probe\0"
                            f"{timeout_request['role']}\0bounded-v1"
                        ).encode("utf-8")
                    ).hexdigest()
                    original_invoke = program.invoke

                    def delayed_failure(_request):
                        time.sleep(2)
                        raise ValueError("delayed synthetic upstream failure")

                    program.invoke = delayed_failure
                    try:
                        with self.assertRaisesRegex(worker.WorkerError, "timeout"):
                            worker.proxy_round(run, timeout_request)
                    finally:
                        program.invoke = original_invoke
                    errors = [
                        json.loads(path.read_bytes())
                        for path in (
                            Path(run["run_root"]) / "evidence" / "proxy-errors"
                        ).glob("*.json")
                    ]
                    self.assertEqual(errors[-1]["classification"], "timeout")
            finally:
                if run is not None and worker.inspect_lima_instance(worker.AGENT_VM):
                    worker_runtime._git(run, "clean", "-ffd")
                    worker_runtime._docker(
                        *worker_runtime._runtime_argv(
                            LOCK,
                            run["volume"],
                            "rm",
                            "-f",
                            "/volume/logs/agent.log",
                            "/volume/evidence/transcript.jsonl",
                        )
                    )
                    run.pop("synthetic_state", None)
                    result_path = Path(run["run_root"]) / "result.json"
                    if result_path.exists():
                        result_path.unlink()
                    run["artifact_scan_markers"] = (provider_marker, fixture_marker)
                    worker.dispose_run(run, interrupted=True)

        self.assertIsNotNone(run)
        self.assertIsNone(worker.inspect_lima_instance(worker.AGENT_VM))


class DeterministicPreflightTests(unittest.TestCase):
    def _inputs(self):
        suite_sha256 = hashlib.sha256(
            b"python -m unittest selected deterministic suite: all passed"
        ).hexdigest()
        cases = {
            name: experiment.named_check_evidence(
                f"tests.deterministic::{name}",
                f"PASS tests.deterministic::{name}\n".encode(),
                suite_sha256=suite_sha256,
                evidence_kind="unittest",
                applicability="simulated_static",
            )
            for name in experiment.DETERMINISTIC_PREFLIGHT_CASES
        }
        gates = {
            name: experiment.named_check_evidence(
                f"tests.isolation::{name}",
                f"PASS tests.isolation::{name}\n".encode(),
                suite_sha256=suite_sha256,
                evidence_kind=(
                    "sealed_runtime"
                    if name in {"fixed_egress_path", "distinct_terminal_verifier"}
                    else "static_policy"
                ),
                applicability=(
                    "applicable_sealed_runtime"
                    if name in {"fixed_egress_path", "distinct_terminal_verifier"}
                    else "simulated_static"
                ),
            )
            for name in experiment.DETERMINISTIC_PREFLIGHT_GATES
        }
        identities = {
            "image_digest": "sha256:" + "1" * 64,
            "runtime_sha256": "2" * 64,
            "native_decide_policy_sha256": "3" * 64,
            "tool_schema_sha256": "4" * 64,
            "provider_identity_sha256": "5" * 64,
        }
        return suite_sha256, cases, gates, identities

    def test_fresh_green_preflight_names_every_case_gate_and_identity(self):
        suite_sha256, cases, gates, identities = self._inputs()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "preflight.json"
            written = experiment.write_deterministic_preflight(
                path,
                suite_sha256=suite_sha256,
                case_evidence=cases,
                gate_evidence=gates,
                identities=identities,
                zero_secret_scan_sha256="7" * 64,
                source_head="8" * 40,
                completed_at_unix=1_700_000_000,
            )
            loaded = experiment.require_deterministic_preflight(
                path,
                expected_identities=identities,
                expected_source_head="8" * 40,
                expected_suite_sha256=suite_sha256,
                now_unix=1_700_000_120,
                max_age_seconds=300,
            )

        self.assertEqual(written, loaded)
        self.assertEqual(written["readiness"], "ready")
        self.assertEqual(set(written["cases"]), set(cases))
        self.assertEqual(set(written["gates"]), set(gates))
        self.assertEqual(written["identities"], identities)
        self.assertEqual(
            written["preflight_sha256"],
            hashlib.sha256(
                experiment.canonical_json_bytes(
                    {
                        key: value
                        for key, value in written.items()
                        if key != "preflight_sha256"
                    }
                )
            ).hexdigest(),
        )

    def test_preflight_rejects_stale_red_partial_or_tampered_evidence(self):
        suite_sha256, cases, gates, identities = self._inputs()
        mutations = ("stale", "red", "partial", "tampered")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "preflight.json"
                experiment.write_deterministic_preflight(
                    path,
                    suite_sha256=suite_sha256,
                    case_evidence=cases,
                    gate_evidence=gates,
                    identities=identities,
                    zero_secret_scan_sha256="7" * 64,
                    source_head="8" * 40,
                    completed_at_unix=1_700_000_000,
                )
                now = 1_700_000_120
                if mutation != "stale":
                    record = json.loads(path.read_text(encoding="utf-8"))
                    if mutation == "red":
                        record["readiness"] = "red"
                    elif mutation == "partial":
                        record["cases"].pop(next(iter(record["cases"])))
                    else:
                        record["suite_sha256"] = "9" * 64
                    path.write_bytes(experiment.canonical_json_bytes(record) + b"\n")
                else:
                    now = 1_700_000_301

                with self.assertRaises(experiment.ContractError):
                    experiment.require_deterministic_preflight(
                        path,
                        expected_identities=identities,
                        expected_source_head="8" * 40,
                        expected_suite_sha256=suite_sha256,
                        now_unix=now,
                        max_age_seconds=300,
                    )

    def test_external_provider_boundary_requires_current_suite_authorization(self):
        suite_sha256, cases, gates, identities = self._inputs()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "preflight.json"
            record = experiment.write_deterministic_preflight(
                path,
                suite_sha256=suite_sha256,
                case_evidence=cases,
                gate_evidence=gates,
                identities=identities,
                zero_secret_scan_sha256="7" * 64,
                source_head="8" * 40,
                completed_at_unix=1_700_000_000,
            )
            run = {
                "deterministic_preflight": {
                    "path": str(path),
                    "identities": identities,
                    "source_head": "8" * 40,
                    "suite_sha256": suite_sha256,
                    "max_age_seconds": 300,
                }
            }
            with mock.patch("autofv.preflight.time.time", return_value=1_700_000_120):
                authorized = preflight.authorize_external_action(run)

            self.assertEqual(authorized, record)
            self.assertEqual(
                run["deterministic_preflight_sha256"], record["preflight_sha256"]
            )
            run["deterministic_preflight"]["suite_sha256"] = "9" * 64
            with (
                mock.patch("autofv.preflight.time.time", return_value=1_700_000_120),
                self.assertRaises(experiment.ContractError),
            ):
                preflight.authorize_external_action(run)

    def test_model_provider_action_fails_before_runner_without_preflight(self):
        runner = mock.Mock()
        state = {
            "run": {"provider_binding": {"binding_sha256": "1" * 64}},
            "run_round": runner,
        }
        request = {"request_id": "provider-action-001"}

        with self.assertRaisesRegex(
            experiment.ContractError, "requires deterministic preflight"
        ):
            model._invoke_model(state, request, checkpoint=False)
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
