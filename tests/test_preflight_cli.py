from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import experiment, preflight_runner, provider_config, worker, worker_runtime


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/fixtures/diamond"
CONFIG = TARGET / "run.json"
LOCK = json.loads((ROOT / "docker/autofv/toolchain-lock.json").read_bytes())


def _environment(root: Path) -> Path:
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    values = {
        "AUTOFV_PROVIDER_ENDPOINT": "https://provider.invalid/v1/chat/completions",
        "AUTOFV_PROVIDER_MODEL": "preflight-model-v1",
        "AUTOFV_PROVIDER_API_KEY": "preflight-secret-canary",
        "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2.000000",
        "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "1.000000",
        "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "4.000000",
        "AUTOFV_RECEIPT_SIGNING_KEY_B64": base64.b64encode(key).decode(),
    }
    path = root / "provider.env"
    path.write_text("".join(f"{name}={value}\n" for name, value in values.items()))
    path.chmod(0o600)
    return path


def _run(root: Path) -> dict:
    fixed_sha = hashlib.sha256(experiment.canonical_json_bytes(LOCK["fixed_proxy"])).hexdigest()
    return {
        "run_id": "preflight-cli-run-001",
        "run_root": str(root / "run"),
        "evidence_dir": str(root / "run/evidence"),
        "volume": "preflight-volume",
        "base_commit": "1" * 40,
        "lock": copy.deepcopy(LOCK),
        "image_digest": LOCK["image"]["image_digest"],
        "worker_inventory_sha256": "2" * 64,
        "control_bundle_sha256": worker_runtime._control_manifest(LOCK)[0]["bundle_sha256"],
        "native_decide_policy_sha256": LOCK["native_decide_policy_sha256"],
        "fixed_proxy_sha256": fixed_sha,
        "events": [],
    }


def _runner_raw() -> bytes:
    checks = [
        {"name": name, "status": "passed", "detail": "production_path_exercised"}
        for name in preflight_runner._ALL_CHECKS
    ]
    body = {"schema": preflight_runner.RUNNER_SCHEMA, "checks": checks}
    value = {
        **body,
        "runner_sha256": hashlib.sha256(experiment.canonical_json_bytes(body)).hexdigest(),
    }
    return experiment.canonical_json_bytes(value) + b"\n"


class PreflightCliTests(unittest.TestCase):
    def test_parser_accepts_exact_preflight_command(self) -> None:
        args = experiment._parser().parse_args(
            [
                "preflight",
                "/tmp/repo",
                "--config",
                "/tmp/run.json",
                "--output",
                "/tmp/evidence",
                "--env-file",
                "/tmp/provider.env",
            ]
        )

        self.assertEqual(args.command, "preflight")
        self.assertEqual(args.repo, "/tmp/repo")
        self.assertEqual(args.config, "/tmp/run.json")
        self.assertEqual(args.output, "/tmp/evidence")
        self.assertEqual(args.env_file, "/tmp/provider.env")

    def test_provider_run_starts_listener_before_worker_policy_and_authorizes_same_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = _run(root)
            run["execution_tier"] = "simulation"
            env = root / "provider.env"
            selection = root / "selection.json"
            env.touch()
            selection.touch()
            events = []

            def prepare(*_args, before_worker=None, **_kwargs):
                if before_worker is not None:
                    before_worker(run)
                events.append("worker_policy")
                return run

            def configure(prepared, *_args, **_kwargs):
                prepared["provider_binding"] = {"model_id": "fixture-model-v1"}
                events.append("provider_configured")

            def start(_prepared):
                events.append(
                    "listener_started"
                    if "listener_started" not in events
                    else "listener_reattached"
                )

            def authorize(_prepared, *_args, **_kwargs):
                events.append("worker_authorized")

            with (
                mock.patch("autofv.worker.prepare_run", side_effect=prepare),
                mock.patch(
                    "autofv.experiment.preflight_runner.configure_prepared_provider",
                    side_effect=configure,
                    create=True,
                ) as configure_provider,
                mock.patch(
                    "autofv.experiment.preflight_runner.authorize_prepared_run",
                    side_effect=authorize,
                ) as authorize_run,
                mock.patch.object(
                    experiment, "_bind_provider_selection"
                ) as bind_selection,
                mock.patch.object(
                    experiment.provider_service, "start", side_effect=start
                ) as start_provider,
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH, "stream", return_value=[]
                ),
                mock.patch.object(experiment, "_checkpoint_if_enabled"),
                mock.patch.object(
                    experiment,
                    "_finish_attempt",
                    return_value={"outcome": "success"},
                ),
            ):
                result = experiment.run_experiment(
                    TARGET,
                    CONFIG,
                    env_file=env,
                    provider_selection=selection,
                )

            self.assertEqual(result["outcome"], "success")
            self.assertEqual(
                events,
                [
                    "provider_configured",
                    "listener_started",
                    "worker_policy",
                    "worker_authorized",
                    "listener_reattached",
                ],
            )
            configure_provider.assert_called_once_with(run, TARGET, env_file=env)
            authorize_run.assert_called_once_with(
                run,
                TARGET,
                CONFIG,
                Path(run["evidence_dir"]) / "provider-prerequisite",
                env_file=env,
                max_age_seconds=300,
            )
            bind_selection.assert_called_once_with(run, selection)
            self.assertEqual(start_provider.call_args_list, [mock.call(run), mock.call(run)])

    def test_provider_selection_binds_stable_identity_not_run_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "selection.json"
            model = {
                "model_id": "selected-model-v1",
                "endpoint": "https://provider.invalid/v1/chat/completions",
                "endpoint_sha256": "1" * 64,
                "parameters": {
                    "review_max_output_tokens": 4096,
                    "stream": False,
                    "temperature": 0,
                    "timeout_seconds": 30,
                    "tool_choice": "required",
                    "work_max_output_tokens": 8192,
                },
                "pricing": {
                    "cached_input_usd_per_million": "1.000000",
                    "currency": "USD",
                    "input_usd_per_million": "2.000000",
                    "output_usd_per_million": "4.000000",
                },
                "pricing_sha256": "2" * 64,
                "tool_schema_sha256": "3" * 64,
                "capability_sha256": "4" * 64,
                "fixed_proxy_sha256": "5" * 64,
                "proxy_id": "proxy-v1",
                "route_id": "route-v1",
            }
            selection = {
                "schema": "autofv-retained-model-selection/v1",
                "status": "selected",
                "selected_at": "2026-09-22T10:36:07.015Z",
                "selected_by": "human-operator",
                "decision": "select-model",
                "scope": {
                    "proof_smoke": True,
                    "full_retained_run": True,
                    "provider_request_authorized": False,
                    "spend_authorized": False,
                    "push_authorized": False,
                    "dynamic_routing_allowed": False,
                    "model_substitution_allowed": False,
                },
                "model": model,
                "accessibility_evidence": {},
                "constraints": [],
                "verification": {},
            }
            path.write_bytes(experiment.canonical_json_bytes(selection) + b"\n")
            binding = {**model, "capability_sha256": "6" * 64}
            run = {"provider_binding": binding, "events": []}

            experiment._bind_provider_selection(run, path)
            self.assertEqual(run["events"], ["provider_selected"])

            selection["model"]["pricing_sha256"] = "7" * 64
            path.write_bytes(experiment.canonical_json_bytes(selection) + b"\n")
            with self.assertRaises(experiment.ContractError):
                experiment._bind_provider_selection(
                    {"provider_binding": binding, "events": []}, path
                )

    def test_runner_result_rejects_unknown_or_failed_checks(self) -> None:
        value = json.loads(_runner_raw())
        for mutation in ("unknown", "failed"):
            candidate = copy.deepcopy(value)
            if mutation == "unknown":
                candidate["checks"][0]["name"] = "caller_asserted_success"
            else:
                candidate["checks"][0]["status"] = "failed"
            body = {"schema": candidate["schema"], "checks": candidate["checks"]}
            candidate["runner_sha256"] = hashlib.sha256(
                experiment.canonical_json_bytes(body)
            ).hexdigest()
            with self.subTest(mutation=mutation), self.assertRaises(experiment.ContractError):
                preflight_runner.validate_runner_result(
                    experiment.canonical_json_bytes(candidate) + b"\n"
                )

    def test_same_file_serialization_rejects_overlap(self) -> None:
        def concurrent_scheduler(graph, run_job, accept_job, **_kwargs):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(run_job, node) for node in ("Left", "Right")]
                results = [future.result() for future in futures]
            self.assertEqual(results, ["Left", "Right"])
            return {"Base", "Left", "Right", "Top"}

        with (
            mock.patch(
                "autofv.preflight_runner.graph_scheduler._schedule_proofs",
                side_effect=concurrent_scheduler,
            ),
            self.assertRaises(AssertionError),
        ):
            preflight_runner._same_file_serialization()

    def test_distinct_verifier_rejects_same_machine(self) -> None:
        machine_id = "1" * 32
        started = subprocess.CompletedProcess((), 0, b"", b"")
        observed = subprocess.CompletedProcess((), 0, f"{machine_id}\n".encode(), b"")
        with (
            mock.patch("subprocess.run", return_value=started),
            mock.patch("autofv.verifier._shell", return_value=observed),
            self.assertRaises(worker_runtime.WorkerError),
        ):
            preflight_runner._probe_distinct_verifier(
                {"agent_worker_id": f"lima:autofv-agent-template:{machine_id}"}
            )

    def test_failed_collection_still_lifts_the_source_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ok = subprocess.CompletedProcess((), 0, b"", b"")
            missing = subprocess.CompletedProcess((), 1, b"", b"")
            with (
                mock.patch.dict("os.environ", {"AUTOFV_RUN_TOKEN": "preflight-run-token"}),
                mock.patch("autofv.worker.prepare_run", return_value=_run(root)),
                mock.patch("autofv.preflight_runner._probe_distinct_verifier", return_value="lima:autofv-verifier:fixture"),
                mock.patch("autofv.worker.force_destroy_worker"),
                mock.patch("autofv.worker_runtime._docker", side_effect=[ok, missing, missing, ok]) as docker,
                self.assertRaisesRegex(experiment.ContractError, "result collection failed"),
            ):
                preflight_runner.run_preflight(TARGET, CONFIG, root / "bundle", env_file=_environment(root))
            self.assertEqual(docker.call_args_list[-1].args[-3:], ("-R", "u+w", "/volume/work/project"))

    def test_preflight_uses_one_sealed_runner_and_produces_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bundle"
            run = _run(root)
            env = _environment(root)
            completed = subprocess.CompletedProcess((), 0, b"", b"")
            collected = subprocess.CompletedProcess((), 0, _runner_raw(), b"")
            with (
                mock.patch.dict("os.environ", {"AUTOFV_RUN_TOKEN": "preflight-run-token"}),
                mock.patch("autofv.worker.prepare_run", return_value=run),
                mock.patch("autofv.preflight_runner._probe_distinct_verifier", return_value="lima:autofv-verifier:fixture"),
                mock.patch("autofv.worker.force_destroy_worker") as destroy,
                mock.patch("autofv.worker_runtime._docker", side_effect=[completed, completed, collected, completed]) as docker,
                mock.patch(
                    "autofv.provider_transport._open_upstream",
                    side_effect=AssertionError("provider dispatch forbidden"),
                ) as upstream,
            ):
                result = preflight_runner.run_preflight(
                    TARGET, CONFIG, output, env_file=env
                )

            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(list((output / "checks").glob("*.json"))), 18)
            preflight_runner.validate_preflight_bundle(
                output / "preflight-result.json", expected_source_head="1" * 40
            )
            self.assertEqual(docker.call_count, 4)
            self.assertEqual(docker.call_args_list[0].args[-3:], ("-R", "a-w", "/volume/work/project"))
            self.assertEqual(docker.call_args_list[3].args[-3:], ("-R", "u+w", "/volume/work/project"))
            runner_argv = docker.call_args_list[1].args
            self.assertEqual(
                runner_argv[runner_argv.index("--runtime") + 1],
                LOCK["tools"]["runsc"]["runtime_name"],
            )
            self.assertIn("--read-only", runner_argv)
            self.assertEqual(runner_argv[runner_argv.index("--network") + 1], "none")
            mounts = [
                runner_argv[index + 1]
                for index, item in enumerate(runner_argv[:-1])
                if item == "--mount"
            ]
            self.assertEqual(len(mounts), 2)
            self.assertEqual(
                mounts[0], "type=volume,src=preflight-volume,dst=/volume,volume-nocopy"
            )
            self.assertEqual(
                mounts[1],
                "type=volume,src=preflight-volume,dst=/dependencies,"
                "volume-subpath=dependencies,volume-nocopy,readonly",
            )
            self.assertFalse(any("type=bind" in mount for mount in mounts))
            destroy.assert_called_once_with(run)
            upstream.assert_not_called()
            retained = b"".join(
                path.read_bytes() for path in output.rglob("*") if path.is_file()
            )
            self.assertNotIn(b"preflight-secret-canary", retained)

    def test_prepared_run_authorization_retains_worker_and_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bundle"
            run = _run(root)
            manifest = json.loads((TARGET / "autofv.json").read_bytes())
            run["snapshot_sha256"] = worker.hash_tree(TARGET)
            run["manifest_sha256"] = hashlib.sha256(
                experiment.canonical_json_bytes(manifest)
            ).hexdigest()
            env = _environment(root)
            completed = subprocess.CompletedProcess((), 0, b"", b"")
            collected = subprocess.CompletedProcess((), 0, _runner_raw(), b"")
            try:
                with (
                    mock.patch.dict(
                        "os.environ", {"AUTOFV_RUN_TOKEN": "preflight-run-token"}
                    ),
                    mock.patch(
                        "autofv.preflight_runner._probe_distinct_verifier",
                        return_value="lima:autofv-verifier:fixture",
                    ),
                    mock.patch("autofv.worker.force_destroy_worker") as destroy,
                    mock.patch(
                        "autofv.worker_runtime._docker",
                        side_effect=[completed, completed, collected, completed],
                    ),
                ):
                    result = preflight_runner.authorize_prepared_run(
                        run,
                        TARGET,
                        CONFIG,
                        output,
                        env_file=env,
                        max_age_seconds=300,
                    )

                self.assertEqual(result["status"], "passed")
                self.assertIn("provider_binding", run)
                destroy.assert_not_called()
            finally:
                provider_config.abort_configuration(run)

    def test_bundle_validation_rejects_control_bundle_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bundle"
            run = _run(root)
            env = _environment(root)
            with (
                mock.patch.dict("os.environ", {"AUTOFV_RUN_TOKEN": "preflight-run-token"}),
                mock.patch("autofv.worker.prepare_run", return_value=run),
                mock.patch("autofv.preflight_runner._probe_distinct_verifier", return_value="lima:autofv-verifier:fixture"),
                mock.patch("autofv.worker.force_destroy_worker"),
                mock.patch(
                    "autofv.worker_runtime._docker",
                    side_effect=[
                        subprocess.CompletedProcess((), 0, b"", b""),
                        subprocess.CompletedProcess((), 0, b"", b""),
                        subprocess.CompletedProcess((), 0, _runner_raw(), b""),
                        subprocess.CompletedProcess((), 0, b"", b""),
                    ],
                ),
            ):
                preflight_runner.run_preflight(TARGET, CONFIG, output, env_file=env)
            with (
                mock.patch(
                    "autofv.worker_runtime._control_manifest",
                    return_value=({"bundle_sha256": "f" * 64}, []),
                ),
                self.assertRaises(experiment.ContractError),
            ):
                preflight_runner.validate_preflight_bundle(
                    output / "preflight-result.json"
                )

    def test_reconstructed_validator_passes_independent_run_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authorization = root / "provider-authorization.json"
            authorization.write_text(json.dumps({"run_id": "preflight-run-001"}))
            bundle = {
                "artifacts": {"authorization": str(authorization)},
                "identities": {"provider_identity_sha256": "a" * 64},
            }
            with (
                mock.patch(
                    "autofv.preflight_runner.validate_preflight_bundle",
                    return_value=bundle,
                ),
                mock.patch("autofv.contracts.load_toolchain_lock", return_value=LOCK),
                mock.patch(
                    "autofv.provider_config.configure_provider",
                    return_value={"binding_sha256": "a" * 64},
                ),
                mock.patch(
                    "autofv.provider_service.validate_pinned_preflight",
                    return_value={"preflight_sha256": "b" * 64},
                ) as validate,
                mock.patch("autofv.provider_config.abort_configuration") as abort,
            ):
                result = preflight_runner.validate_reconstructed_provider_preflight(
                    root / "provider-preflight.json",
                    bundle_path=root / "preflight-result.json",
                    env_file=root / "provider.env",
                )

            self.assertEqual(result["status"], "passed")
            reconstructed = validate.call_args.kwargs["run"]
            self.assertEqual(reconstructed["run_id"], "preflight-run-001")
            validate.assert_called_once_with(
                root / "provider-preflight.json", run=reconstructed
            )
            abort.assert_called_once_with(reconstructed)

    def test_bundle_validation_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "bundle"
            run = _run(root)
            env = _environment(root)
            with (
                mock.patch.dict("os.environ", {"AUTOFV_RUN_TOKEN": "preflight-run-token"}),
                mock.patch("autofv.worker.prepare_run", return_value=run),
                mock.patch("autofv.preflight_runner._probe_distinct_verifier", return_value="lima:autofv-verifier:fixture"),
                mock.patch("autofv.worker.force_destroy_worker"),
                mock.patch(
                    "autofv.worker_runtime._docker",
                    side_effect=[
                        subprocess.CompletedProcess((), 0, b"", b""),
                        subprocess.CompletedProcess((), 0, b"", b""),
                        subprocess.CompletedProcess((), 0, _runner_raw(), b""),
                        subprocess.CompletedProcess((), 0, b"", b""),
                    ],
                ),
            ):
                preflight_runner.run_preflight(TARGET, CONFIG, output, env_file=env)
            suite = output / "retained-suite.json"
            suite.write_bytes(suite.read_bytes() + b" ")
            with self.assertRaises(experiment.ContractError):
                preflight_runner.validate_preflight_bundle(output / "preflight-result.json")


class SealedRunnerSurfaceTests(unittest.TestCase):
    """The in-container runner sees only the control bundle and a prepared volume."""

    def test_runner_imports_from_the_control_bundle_alone(self) -> None:
        members = worker_runtime._control_manifest(preflight_runner.load_toolchain_lock())[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, raw, _mode in members:
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_bytes(raw)
            completed = subprocess.run(
                (sys.executable, "-I", str(root / "autofv/preflight_runner.py"), "--help"),
                capture_output=True, text=True, cwd=temporary,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr[-500:])

    def _project(self, root: Path) -> Path:
        project = root / "project"
        (project / "Src").mkdir(parents=True)
        (project / "Src/A.lean").write_text("theorem a : True := trivial\n")
        (project / ".lake/build").mkdir(parents=True)
        (project / ".lake/build/A.olean").write_bytes(b"token = abcdefgh12345678")
        (project / ".lake/packages").symlink_to("/volume/dependencies/packages")
        return project

    def test_prepared_project_passes_the_source_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(Path(temporary))
            with mock.patch.object(preflight_runner, "PROJECT_ROOT", project):
                preflight_runner._tree_has_no_symlinks()
                preflight_runner._secret_scan()
                preflight_runner._spoiler_scan()

    def test_every_check_passes_on_the_host_but_those_needing_the_worker(self) -> None:
        # Only these read worker-volume paths the host cannot supply.
        worker_only = {"tool_schema_equality", "candidate_scope"}
        failed = []
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(Path(temporary))
            with mock.patch.object(
                preflight_runner, "_lock", preflight_runner.load_toolchain_lock
            ), mock.patch.object(preflight_runner, "PROJECT_ROOT", project):
                for name, check in preflight_runner._CHECKS.items():
                    if name in worker_only:
                        continue
                    try:
                        check()
                    except BaseException as exc:
                        failed.append(f"{name}: {exc!r}")
        self.assertEqual(failed, [])

    def test_a_result_names_every_failed_check(self) -> None:
        failing = {"candidate_trust_scope_rejected": "AssertionError", "candidate_scope": "OSError"}
        checks = [
            {"name": name, "status": "failed", "detail": failing[name]}
            if name in failing
            else {"name": name, "status": "passed", "detail": "production_path_exercised"}
            for name in preflight_runner._ALL_CHECKS
        ]
        body = {"schema": preflight_runner.RUNNER_SCHEMA, "checks": checks}
        value = {**body, "runner_sha256": hashlib.sha256(
            preflight_runner.canonical_json_bytes(body)).hexdigest()}
        with self.assertRaisesRegex(
            preflight_runner.ContractError,
            "failed: candidate_trust_scope_rejected:AssertionError,candidate_scope:OSError$",
        ):
            preflight_runner.validate_runner_result(
                preflight_runner.canonical_json_bytes(value) + b"\n"
            )

    def test_source_symlinks_and_a_foreign_dependency_link_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(Path(temporary))
            with mock.patch.object(preflight_runner, "PROJECT_ROOT", project):
                (project / "Src/B.lean").symlink_to("/etc/passwd")
                with self.assertRaises(AssertionError):
                    preflight_runner._tree_has_no_symlinks()
                (project / "Src/B.lean").unlink()
                (project / ".lake/packages").unlink()
                (project / ".lake/packages").symlink_to("/elsewhere")
                with self.assertRaises(AssertionError):
                    preflight_runner._tree_has_no_symlinks()


if __name__ == "__main__":
    unittest.main()
