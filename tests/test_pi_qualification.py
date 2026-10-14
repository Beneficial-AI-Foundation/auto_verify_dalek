"""Offline public qualification commands: synthetic metadata, no OAuth or live VM.

The default process boundary is denied in every test. One specific test replaces
only the Node entry with a fixed fake runtime while retaining real PiProcess IPC;
the cancellation canary is itself offline and exercises real OS kill/reap.
"""
from __future__ import annotations
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from autofv import contracts, pi_backend, pi_process, pi_qualification as q, preflight_runner, provider_config, runtime_profile
from tests.test_fvs_offline import packet

NODE = shutil.which("node")
RUNTIME = {"schema": "autofv-pi-runtime-identity/v1", "protocol_version": 1,
    "node_sha256": "1" * 64, "bridge_sha256": "2" * 64, "package_lock_sha256": "3" * 64,
    "packages": runtime_profile.PI_PACKAGES}


def result_for(payload):
    request = payload["request"]
    call = {"name": "check_lean", "arguments": {}}
    continuation = {"schema": "autofv-pi-continuation/v1", "request": request,
        "canonical_tool_id": request["request_id"] + "-tool", "tool_call": call,
        "native": {"tool_call_id": "call_1|fc_1", "content": [{"type": "toolCall"}], "response_id": "resp_test"}}
    return {"request_id": request["request_id"], "sequence": 1, "tool_call": call,
        "usage": {"input": 3, "cacheRead": 2, "cacheWrite": 1, "output": 4, "totalTokens": 10, "reasoning": 2},
        "provider_response_id": "resp_test", "observed_model": runtime_profile.PI_MODEL,
        "requested_effort": "xhigh", "observed_effort": None, "continuation": continuation}


@unittest.skipUnless(NODE, "Node executable unavailable")
class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provision = self.root / "provisioning.json"
        self.metadata = {"schema": "autofv-pi-provisioning/v1", "store_path": str(self.root / "DO_NOT_READ_CREDENTIAL.json"),
            "account_binding_sha256": "4" * 64, "device_id": "offline-fixture",
            "account_identity": "human-selected-login; not independently reported by SDK",
            "entitlement_validated": False, "model_dispatched": False}
        self.provision.write_bytes(contracts.canonical_json_bytes(self.metadata) + b"\n")
        self.provision.chmod(0o600)
        self.diagnostic = mock.patch.object(pi_process, "runtime_diagnostic", return_value={"runtime_identity": RUNTIME})
        self.diagnostic.start()
        self.addCleanup(self.diagnostic.stop)
        self.prepare = q.prepare(node=NODE, provisioning=self.provision, output=self.root / "bootstrap")
        self.bootstrap = self.prepare["bootstrap"]
        self.deadline = time.time_ns() // 1_000_000 + 120000
        self.process_guard = mock.patch.object(pi_process.PiProcess, "_spawn", side_effect=AssertionError("real SDK entry is forbidden"))
        self.process_guard.start()
        self.addCleanup(self.process_guard.stop)

    def args(self, action, *extra):
        return [action, "--bootstrap", self.bootstrap, "--approval-id", "fixture-" + action,
            "--deadline-epoch-ms", str(self.deadline), *extra]

    def command(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = q.main(argv)
        return code, json.loads(out.getvalue() or err.getvalue())

    def fake_process(self, callback=None):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.generate_one.side_effect = callback or result_for
        return process

    def probe(self, **kwargs):
        return q.probe(bootstrap_path=self.bootstrap, approval_id="fixture-probe", deadline_ms=self.deadline,
            approved=True, acknowledgements=copy.deepcopy(q.ACKNOWLEDGEMENTS), **kwargs)

    def test_prepare_reads_metadata_only_and_creates_private_key(self):
        self.assertFalse(Path(self.metadata["store_path"]).exists())
        self.assertFalse(self.prepare["model_dispatched"])
        self.assertFalse(self.prepare["credential_accessed"])
        root, bootstrap = q.load_bootstrap(self.bootstrap)
        self.assertEqual(len((root / "attestation.key").read_bytes()), 32)
        self.assertEqual((root / "attestation.key").stat().st_mode & 0o777, 0o600)
        q._verify(bootstrap, bootstrap, "bootstrap")

    def test_prepare_public_command_never_initializes_auth_or_model(self):
        code, value = self.command(["prepare", "--node", NODE, "--provisioning", str(self.provision),
            "--output", str(self.root / "another-bootstrap")])
        self.assertEqual(code, 0)
        self.assertFalse(value["model_dispatched"])
        self.assertFalse(Path(self.metadata["store_path"]).exists())

    def test_every_mutating_stage_requires_its_specific_approval(self):
        for action, extra in (("probe", []), ("qualify", ["--repo", str(self.root)])):
            code, value = self.command(self.args(action, *extra))
            self.assertEqual(code, 2)
            self.assertIn("explicit", value["error"])
        self.assertFalse((Path(self.bootstrap).parent / "approvals").exists())

    def test_probe_requires_all_three_policy_acknowledgements(self):
        code, value = self.command(self.args("probe", "--approve-one-live-request"))
        self.assertEqual(code, 2)
        self.assertIn("acknowledgements", value["error"])

    def test_probe_public_command_one_request_retains_actual_attestation(self):
        process = self.fake_process()
        argv = self.args("probe", "--approve-one-live-request", "--ack-no-server-output-cap",
            "--ack-unknown-subscription-cost", "--ack-best-effort-remote-abort")
        with mock.patch.object(pi_process, "PiProcess", return_value=process) as factory:
            code, value = self.command(argv)
            self.assertEqual(code, 0)
            self.assertEqual(value["new_model_requests"], 1)
            report = q._read(Path(value["report"]))
            self.assertEqual(report["raw_usage"], result_for(process.generate_one.call_args.args[0])["usage"])
            self.assertEqual(report["usage"]["input_tokens"], 6)
            self.assertEqual(report["usage"]["output_tokens"], 4)
            self.assertEqual(report["usage"]["reasoning_tokens"], 2)
            self.assertEqual(report["invocations_used"], 1)
            self.assertEqual(report["tool_callbacks_executed"], 0)
            self.assertIsNone(report["cost_usd"])
            self.assertFalse(report["monetary_cost_known"])
            code, replayed = self.command(argv)
            self.assertEqual(code, 0)
            self.assertEqual(replayed["new_model_requests"], 0)
            self.assertTrue(replayed["replayed"])
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(process.generate_one.call_count, 1)
        _, bootstrap = q.load_bootstrap(self.bootstrap)
        q.verify_artifact(bootstrap, value["entitlement"], "entitlement")
        with self.assertRaises((contracts.ContractError, provider_config.ProviderConfigError)):
            pi_backend.read_runtime_record(Path(value["report"]))

    def test_replay_after_original_deadline_returns_old_evidence_without_renewal(self):
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process()) as factory:
            first = self.probe()
            with mock.patch.object(q.time, "time_ns", return_value=(self.deadline + 5000) * 1_000_000):
                replay = self.probe()
            self.assertEqual(factory.call_count, 1)
        self.assertEqual(first["report"], replay["report"])
        self.assertEqual(q._read(Path(first["report"]))["grant"]["original_deadline_epoch_ms"], self.deadline)

    def test_timeout_burns_admission_and_never_retries(self):
        process = self.fake_process(lambda _: (_ for _ in ()).throw(pi_process.PiProcessError("request_timeout_uncertain")))
        with mock.patch.object(pi_process, "PiProcess", return_value=process) as factory:
            with self.assertRaises(pi_process.PiProcessError):
                self.probe()
            with self.assertRaisesRegex(contracts.ContractError, "never retry"):
                self.probe()
            self.assertEqual(factory.call_count, 1)
        location = next((Path(self.bootstrap).parent / "approvals").iterdir())
        journal = q._read(location / "probe-journal.json")
        self.assertEqual(journal["status"], "dispatched")
        self.assertEqual(journal["invocations_used"], 1)
        self.assertFalse((location / "entitlement.json").exists())

    def test_expired_probe_does_not_spawn_or_renew(self):
        self.deadline = time.time_ns() // 1_000_000 - 1
        with mock.patch.object(pi_process, "PiProcess") as process, self.assertRaisesRegex(contracts.ContractError, "deadline"):
            self.probe()
        process.assert_not_called()

    def test_probe_cannot_exceed_the_profile_request_timeout(self):
        self.deadline = time.time_ns() // 1_000_000 + 121000
        with mock.patch.object(pi_process, "PiProcess") as process, self.assertRaisesRegex(contracts.ContractError, "operation limit"):
            self.probe()
        process.assert_not_called()

    def test_bad_usage_after_dispatch_never_produces_pass(self):
        def invalid(payload):
            value = result_for(payload)
            value["usage"]["totalTokens"] = 0
            return value
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process(invalid)):
            with self.assertRaises(Exception):
                self.probe()
            with self.assertRaisesRegex(contracts.ContractError, "never retry"):
                self.probe()
        location = next((Path(self.bootstrap).parent / "approvals").iterdir())
        self.assertFalse((location / "entitlement.json").exists())

    def test_same_approval_cannot_change_deadline_or_purpose(self):
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process()):
            self.probe()
        self.deadline += 1
        with self.assertRaisesRegex(contracts.ContractError, "different purpose"):
            self.probe()
        root, bootstrap = q.load_bootstrap(self.bootstrap)
        with self.assertRaisesRegex(contracts.ContractError, "different purpose"):
            with q._approval(root, bootstrap, "fixture-probe", "experiment", self.deadline, max_invocations=1,
                acknowledgements=q.ACKNOWLEDGEMENTS):
                self.fail("approval purpose changed")

    def test_missing_private_journal_cannot_reset_an_existing_probe(self):
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process()) as process:
            result = self.probe()
            (Path(result["report"]).parent / "probe-journal.json").unlink()
            with self.assertRaisesRegex(contracts.ContractError, "journal is missing"):
                self.probe()
            self.assertEqual(process.call_count, 1)

    def test_modified_retained_report_rejected_on_replay(self):
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process()):
            result = self.probe()
        path = Path(result["report"])
        report = q._read(path)
        report["usage"]["input_tokens"] += 1
        q._write(path, report, replace=True)
        with self.assertRaisesRegex(contracts.ContractError, "evidence changed"):
            self.probe()

    def test_cancellation_check_exercises_actual_sdk_interception_and_real_os_boundary(self):
        root, bootstrap = q.load_bootstrap(self.bootstrap)
        with q._approval(root, bootstrap, "offline-cancel", "sealed_qualification", self.deadline) as (location, grant):
            report = q._cancel_check(bootstrap, location, grant)
        self.assertTrue(report["process_group_reaped"])
        self.assertTrue(report["callback_stopped"])
        self.assertEqual(report["canary"]["sdk_model_requests"], 0)
        self.assertEqual(report["canary"]["denied_fetch_routes"], 6)
        self.assertEqual(report["canary"]["intercepted_sdk_requests"], 1)
        self.assertFalse(report["scope"]["sidecar_os_network_confinement"])

    def test_public_qualify_uses_actual_wrapper_with_explicit_mocked_vm_boundary(self):
        # Synthetic presence only; Python qualification must not inspect its bytes.
        store_path = Path(self.metadata["store_path"])
        store_path.write_bytes(b"SYNTHETIC_NOT_A_CREDENTIAL")
        store_path.chmod(0o600)
        (self.root / "candidate").mkdir()
        from autofv import worker, worker_runtime, prepare_dalek
        lock = contracts.load_toolchain_lock()
        suite_body = {"schema": preflight_runner.RUNNER_SCHEMA, "checks": [
            {"name": name, "status": "passed", "detail": "production_path_exercised"}
            for name in preflight_runner._ALL_CHECKS]}
        suite = {**suite_body, "runner_sha256": q._sha(suite_body)}
        run = {"run_id": "mock-vm-qualification", "volume": "fixture-volume", "base_commit": "a" * 40,
            "worker_inventory": {"schema": "explicitly-mocked-external-vm"},
            "scored_container_receipt": {"schema": "explicitly-mocked-external-vm"},
            "control_bundle_sha256": "b" * 64}
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if "cat" in args:
                out = contracts.canonical_json_bytes(suite) + b"\n"
            elif "-c" in args:
                out = contracts.canonical_json_bytes({"schema": "autofv-pi-private-path-check/v1", "visible": [False] * 3}) + b"\n"
            else:
                out = b""
            return subprocess.CompletedProcess(args, 0, out, b"")
        with mock.patch.object(contracts, "validate_target", return_value=(self.root, {})), \
             mock.patch.object(prepare_dalek, "_scan_prepared"), \
             mock.patch.object(worker, "prepare_run", return_value=run) as prepare, \
             mock.patch.object(worker, "force_destroy_worker") as destroy, \
             mock.patch.object(worker_runtime, "_docker", side_effect=docker):
            # Target is separately mocked outside private bootstrap paths.
            with mock.patch.object(contracts, "validate_target", return_value=(self.root / "candidate", {})):
                code, value = self.command(self.args("qualify", "--repo", str(self.root / "candidate"), "--approve-local-sealed-checks"))
        self.assertEqual(code, 0, value)
        prepare.assert_called_once()
        destroy.assert_called_once_with(run)
        self.assertEqual(value["model_requests"], 0)
        _, bootstrap = q.load_bootstrap(self.bootstrap)
        artifact = q.verify_artifact(bootstrap, value["isolation"], "isolation")
        self.assertEqual(artifact["evidence"]["scope"], q.BOUNDARY_SCOPE)
        self.assertTrue(any("/volume/autofv-control/autofv/preflight_runner.py" in call for call in calls))
        self.assertTrue(any("/candidate" in call for call in calls))
        self.assertTrue(all(call[call.index("--network") + 1] == "none" for call in calls if "--network" in call))


    def fixture_artifacts(self):
        root, bootstrap = q.load_bootstrap(self.bootstrap)
        location = root / "offline-fixture-artifacts"
        location.mkdir(mode=0o700)
        result = {}
        for kind in ("isolation", "callback_cancellation"):
            report = location / (kind + "-report.json")
            q._write(report, {"schema": "explicitly-mocked-sealed-observation", "status": "passed",
                "runtime_identity_sha256": q._sha(bootstrap["runtime_identity"]), "scope": q.BOUNDARY_SCOPE})
            path = location / (kind + ".json")
            q._artifact(bootstrap, kind, report, path)
            result[kind] = str(path)
        with mock.patch.object(pi_process, "PiProcess", return_value=self.fake_process()):
            result["entitlement"] = self.probe()["entitlement"]
        config = {"schema": "autofv-run/v3", "model": runtime_profile.PI_MODEL,
            "role_profile": runtime_profile.PI_PROFILE_ID, "source_packet": packet(),
            "max_wall_seconds": 120, "max_cost_usd": None, "max_invocations": 2}
        path = root / "config.json"
        q._write(path, config)
        result["config"] = str(path)
        return result

    def test_public_grant_uses_separate_approval_and_returns_valid_runtime_record(self):
        artifacts = self.fixture_artifacts()
        args = self.args("grant", "--approve-experiment", "--ack-no-server-output-cap",
            "--ack-unknown-subscription-cost", "--ack-best-effort-remote-abort")
        for key, path in artifacts.items():
            args += ["--" + key.replace("_", "-"), path]
        with mock.patch.object(pi_process, "PiProcess") as process:
            code, value = self.command(args)
        self.assertEqual(code, 0, value)
        process.assert_not_called()
        record = pi_backend.read_runtime_record(value["runtime_record"])
        self.assertEqual(record["grant"]["max_invocations"], 2)
        self.assertEqual(record["grant"]["original_deadline_epoch_ms"], self.deadline)
        self.assertNotEqual(record["grant"]["approval_id"], "fixture-probe")
        self.assertFalse(Path(record["preflight_path"]).exists())
        # The same-run production preflight creates this later without circular run-ID binding.
        self.assertEqual(Path(record["preflight_path"]).parent.name, "run-preflight")
        code, replay = self.command(args)
        self.assertEqual(code, 0)
        self.assertEqual(replay["runtime_record"], value["runtime_record"])

    def test_grant_artifacts_pass_real_backend_and_same_worker_preflight_wiring(self):
        from autofv import agent_lane, provider_service
        artifacts = self.fixture_artifacts()
        config_path = artifacts.pop("config")
        result = q.grant_experiment(bootstrap_path=self.bootstrap, config_path=config_path,
            **artifacts, approval_id="fixture-live-run", deadline_ms=self.deadline, approved=True,
            acknowledgements=q.ACKNOWLEDGEMENTS)
        record = pi_backend.read_runtime_record(result["runtime_record"])
        config = q._read(Path(config_path))
        candidate = self.root / "production-source"
        candidate.mkdir()
        run_root = self.root / "production-run"
        run_root.mkdir(mode=0o700)
        run = {"run_id": "offline-qualified-integration", "input_root": str(candidate), "run_root": str(run_root),
            "evidence_dir": str(run_root / "evidence"), "base_commit": "a" * 40, "snapshot_sha256": "b" * 64,
            "lock": {"fixed_proxy": {"path": "/fixture", "proxy_id": "fixture-proxy", "route_id": "fixture-route"}}}
        self.addCleanup(pi_backend.release, run)
        self.addCleanup(provider_config.release_provider, run)
        with mock.patch.dict(os.environ, {"AUTOFV_RUN_TOKEN": "SYNTHETIC_TOKEN"}):
            public = pi_backend.configure(run, config, result["runtime_record"], tool_schemas=list(agent_lane._TOOL_SCHEMAS))
        # No patch on the qualification consumer: generated signed artifacts and
        # exact retained paths must pass production validation.
        pi_backend._qualification_artifacts(record, public)
        def sealed_vm_boundary(repo, config, destination, **kwargs):
            self.assertEqual(repo, candidate)
            self.assertEqual(config, config_path)
            self.assertIs(kwargs["_prepared_run"], run)
            Path(destination).mkdir(mode=0o700)
            q._write(Path(record["preflight_path"]), {"schema": "explicitly-mocked-external-vm-preflight"})
            q._write(Path(record["suite_artifact_path"]), {"schema": "explicitly-mocked-external-vm-suite"})
        with mock.patch.object(preflight_runner, "run_preflight", side_effect=sealed_vm_boundary) as preflight, \
             mock.patch.object(provider_service, "load_preflight_authorization") as authorize:
            pi_backend.authorize_prepared(run, repo=candidate, run_config=config_path)
            pi_backend.authorize_prepared(run, repo=candidate, run_config=config_path)
        preflight.assert_called_once()
        self.assertEqual(authorize.call_count, 2)
        self.assertTrue(Path(record["preflight_path"]).exists())
        self.assertEqual(run["subscription_journal"]["records"], [])

    def test_qualification_rejects_private_source_overlap_before_any_source_scan(self):
        from autofv import prepare_dalek
        root, bootstrap = q.load_bootstrap(self.bootstrap)
        with q._approval(root, bootstrap, "bad-source", "sealed_qualification", self.deadline) as (location, grant):
            with mock.patch.object(contracts, "validate_target", side_effect=AssertionError("source read forbidden")), \
                 mock.patch.object(prepare_dalek, "_scan_prepared", side_effect=AssertionError("source scan forbidden")), \
                 self.assertRaisesRegex(contracts.ContractError, "outside"):
                q._sealed_checks(bootstrap, self.root, location, grant)

    def test_grant_rejects_probe_approval_reuse_and_missing_artifacts(self):
        artifacts = self.fixture_artifacts()
        common = {"bootstrap_path": self.bootstrap, "config_path": artifacts.pop("config"),
            **artifacts, "deadline_ms": self.deadline, "approved": True,
            "acknowledgements": q.ACKNOWLEDGEMENTS}
        with self.assertRaisesRegex(contracts.ContractError, "different purpose"):
            q.grant_experiment(**common, approval_id="fixture-probe")
        Path(artifacts["isolation"]).unlink()
        with self.assertRaises(FileNotFoundError):
            q.grant_experiment(**common, approval_id="new-experiment")

    def test_changed_source_config_cannot_reuse_experiment_approval(self):
        artifacts = self.fixture_artifacts()
        common = {"bootstrap_path": self.bootstrap, "config_path": artifacts.pop("config"),
            **artifacts, "deadline_ms": self.deadline, "approved": True,
            "acknowledgements": q.ACKNOWLEDGEMENTS, "approval_id": "bound-config"}
        q.grant_experiment(**common)
        config_path = Path(common["config_path"])
        config = q._read(config_path)
        config["max_wall_seconds"] += 1
        q._write(config_path, config, replace=True)
        with self.assertRaisesRegex(contracts.ContractError, "different purpose"):
            q.grant_experiment(**common)

    def test_failed_sealed_qualification_never_signs_isolation_success(self):
        with mock.patch.object(q, "_sealed_checks", side_effect=contracts.ContractError("explicit mock sealed failure")):
            code, value = self.command(self.args("qualify", "--repo", str(self.root), "--approve-local-sealed-checks"))
        self.assertEqual(code, 2)
        self.assertIn("sealed failure", value["error"])
        root = Path(self.bootstrap).parent
        self.assertFalse(list(root.glob("approvals/*/isolation.json")))
        self.assertFalse(list(root.glob("approvals/*/callback_cancellation.json")))
        self.assertEqual(len(list(root.glob("approvals/*/callback-report.json"))), 1)

    def test_runtime_identity_drift_blocks_before_process(self):
        with mock.patch.object(pi_process, "runtime_diagnostic", return_value={"runtime_identity": {}}), \
             self.assertRaisesRegex(contracts.ContractError, "changed after bootstrap"):
            self.probe()

    def test_actual_ipc_probe_retains_real_process_observation(self):
        root = pi_process.runtime_path()
        entry = self.root / "intercepted-runtime.mjs"
        entry.write_text(f"import {{serve}} from {json.dumps((root / 'transport.mjs').as_uri())};\n"
            f"import {{fakeRuntime}} from {json.dumps((root / 'test/helpers.mjs').as_uri())};\n"
            f"import {{SDK_VERSIONS}} from {json.dumps((root / 'sdk-versions.mjs').as_uri())};\n"
            "serve({sdk:SDK_VERSIONS,createRuntime:async()=>fakeRuntime()});\n")
        def spawn(instance):
            return subprocess.Popen([str(instance.node), str(entry)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=instance.directory, env=pi_process.minimal_environment(instance.node, instance.directory),
                start_new_session=True, close_fds=True, shell=False, bufsize=0)
        with mock.patch.object(pi_process.PiProcess, "_spawn", spawn):
            result = self.probe()
            replayed = self.probe()
        report = q._read(Path(result["report"]))
        self.assertEqual(report["raw_usage"]["input"], 7)
        self.assertEqual(report["usage"]["input_tokens"], 12)
        self.assertEqual(report["provider_response_id"], "resp_fixture")
        self.assertTrue(replayed["replayed"])
        self.assertNotIn("PRIVATE_ENCRYPTED", Path(result["report"]).read_text())


if __name__ == "__main__":
    unittest.main()
