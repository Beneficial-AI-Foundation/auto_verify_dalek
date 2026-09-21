from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import experiment, preflight_runner, provider_config, worker_runtime


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
                mock.patch("autofv.worker_runtime._docker", side_effect=[completed, completed, collected]) as docker,
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
            self.assertEqual(docker.call_count, 3)
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
            self.assertEqual(len(mounts), 1)
            self.assertNotIn("type=bind", mounts[0])
            destroy.assert_called_once_with(run)
            upstream.assert_not_called()
            retained = b"".join(
                path.read_bytes() for path in output.rglob("*") if path.is_file()
            )
            self.assertNotIn(b"preflight-secret-canary", retained)

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
                    ],
                ),
            ):
                preflight_runner.run_preflight(TARGET, CONFIG, output, env_file=env)
            suite = output / "retained-suite.json"
            suite.write_bytes(suite.read_bytes() + b" ")
            with self.assertRaises(experiment.ContractError):
                preflight_runner.validate_preflight_bundle(output / "preflight-result.json")


if __name__ == "__main__":
    unittest.main()
