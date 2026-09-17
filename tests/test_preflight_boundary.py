from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from autofv import (
    experiment,
    preflight,
    provider_config,
    provider_service,
    provider_transport,
    worker_proxy,
)
from tests.test_provider_service import (
    LOCK,
    RUN_TOKEN,
    _InertServer,
    _environment,
    _messages,
    _request,
    _run,
    _tools,
)


class PreflightBoundaryTests(unittest.TestCase):
    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            provider_service.release(
                {"provider_binding_sha256": binding.public["binding_sha256"]}
            )

    def _configured_live(self, root: Path) -> tuple[dict, dict]:
        run = _run(root)
        run.update(
            {
                "execution_tier": "sealed_runsc",
                "image_digest": LOCK["image"]["image_digest"],
                "worker_inventory_sha256": "2" * 64,
                "native_decide_policy_sha256": LOCK[
                    "native_decide_policy_sha256"
                ],
            }
        )
        with mock.patch.dict(
            os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
        ), mock.patch(
            "autofv.provider_service._serve", return_value=_InertServer()
        ):
            worker_proxy.configure_provider(
                run,
                env_path=_environment(
                    root, endpoint="https://provider.example/v1/chat/completions"
                ),
                tool_schemas=_tools(),
            )
        messages = _messages()
        request = _request(messages)
        worker_proxy.stage_provider_messages(run, request, messages)
        return run, request

    def _passed_record_outcome(
        self,
        artifact_dir: Path,
        *,
        name: str,
        check_id: str,
        identities: dict,
        source_head: str,
        execution_class: str,
        applicability: str,
    ) -> bytes:
        path = artifact_dir / "record-only-passed.json"
        preflight.write_check_outcome(
            path,
            check_name=name,
            check_id=check_id,
            status="passed",
            origin="trusted_runner",
            execution_class=execution_class,
            applicability=applicability,
            identities=identities,
            source_head=source_head,
        )
        return path.read_bytes()

    def _write_provider_preflight(
        self,
        root: Path,
        run: dict,
        *,
        completed_at_unix: int,
        max_age_seconds: int = 300,
        applicability: str = "applicable_sealed_runtime",
        evidence_kind: str = "sealed_runtime",
        outcome_status: str = "passed",
        outcome_origin: str = "trusted_runner",
        outcome_identity_override: dict | None = None,
        retained_identity_override: dict | None = None,
        load_authorization: bool = True,
    ) -> dict:
        binding = run["provider_binding"]
        identities = {
            "image_digest": run["image_digest"],
            "runtime_sha256": run["worker_inventory_sha256"],
            "native_decide_policy_sha256": run["native_decide_policy_sha256"],
            "tool_schema_sha256": binding["tool_schema_sha256"],
            "provider_identity_sha256": binding["binding_sha256"],
        }
        retained_identities = retained_identity_override or identities
        outcome_identities = outcome_identity_override or retained_identities
        artifact_dir = root / "retained-checks"
        artifact_dir.mkdir()
        case_paths = {}
        gate_paths = {}
        for prefix, names, paths in (
            ("case", experiment.DETERMINISTIC_PREFLIGHT_CASES, case_paths),
            ("gate", experiment.DETERMINISTIC_PREFLIGHT_GATES, gate_paths),
        ):
            for index, name in enumerate(names):
                check_id = f"tests.test_preflight_boundary::{prefix}_{name}"
                path = artifact_dir / f"{prefix}-{index:02d}.json"
                preflight.write_check_outcome(
                    path,
                    check_name=name,
                    check_id=check_id,
                    status=outcome_status if index == 0 and prefix == "case" else "passed",
                    origin=outcome_origin,
                    execution_class=evidence_kind,
                    applicability=applicability,
                    identities=outcome_identities,
                    source_head=run["base_commit"],
                )
                paths[name] = path
        suite_path = root / "retained-suite.json"
        preflight.write_retained_suite_result(
            suite_path,
            case_outcomes=case_paths,
            gate_outcomes=gate_paths,
            identities=retained_identities,
            source_head=run["base_commit"],
            completed_at_unix=completed_at_unix,
        )
        suite_raw = suite_path.read_bytes()
        suite_sha256 = hashlib.sha256(suite_raw).hexdigest()

        def evidence(paths):
            return {
                name: experiment.named_check_evidence(
                    f"tests.test_preflight_boundary::{prefix}_{name}",
                    (
                        path.read_bytes()
                        if not (
                            prefix == "case"
                            and name == experiment.DETERMINISTIC_PREFLIGHT_CASES[0]
                            and outcome_status != "passed"
                        )
                        else self._passed_record_outcome(
                            artifact_dir,
                            name=name,
                            check_id=f"tests.test_preflight_boundary::{prefix}_{name}",
                            identities=outcome_identities,
                            source_head=run["base_commit"],
                            execution_class=evidence_kind,
                            applicability=applicability,
                        )
                    ),
                    suite_sha256=suite_sha256,
                    evidence_kind=evidence_kind,
                    applicability=applicability,
                )
                for prefix, paths in (("case", paths),)
                for name, path in paths.items()
            }

        cases = evidence(case_paths)
        gates = {
            name: experiment.named_check_evidence(
                f"tests.test_preflight_boundary::gate_{name}",
                path.read_bytes(),
                suite_sha256=suite_sha256,
                evidence_kind=evidence_kind,
                applicability=applicability,
            )
            for name, path in gate_paths.items()
        }
        path = root / "deterministic-preflight.json"
        record = experiment.write_deterministic_preflight(
            path,
            suite_sha256=suite_sha256,
            case_evidence=cases,
            gate_evidence=gates,
            identities=identities,
            zero_secret_scan_sha256="7" * 64,
            source_head=run["base_commit"],
            completed_at_unix=completed_at_unix,
        )
        if load_authorization:
            provider_service.load_preflight_authorization(
                run,
                preflight_path=path,
                suite_artifact_path=suite_path,
                max_age_seconds=max_age_seconds,
            )
        return {
            "record": record,
            "suite_path": suite_path,
            "case_paths": case_paths,
            "gate_paths": gate_paths,
        }

    def test_named_check_evidence_rejects_failed_or_mismatched_output(self) -> None:
        suite_sha256 = hashlib.sha256(b"named outcome suite").hexdigest()
        for artifact in (
            experiment.canonical_json_bytes(
                {
                    "schema": preflight.CHECK_OUTCOME_SCHEMA,
                    "check_id": "tests.test_preflight_boundary::named_check",
                    "status": "failed",
                }
            )
            + b"\n",
            experiment.canonical_json_bytes(
                {
                    "schema": preflight.CHECK_OUTCOME_SCHEMA,
                    "check_id": "tests.test_preflight_boundary::some_other_check",
                    "status": "passed",
                }
            )
            + b"\n",
            (
                b"test_named_check (tests.test_preflight_boundary.PreflightBoundaryTests) "
                b"... FAIL\n\nFAILED (failures=1)\n"
            ),
        ):
            with self.subTest(artifact=artifact), self.assertRaisesRegex(
                experiment.ContractError, "outcome"
            ):
                experiment.named_check_evidence(
                    "tests.test_preflight_boundary::named_check",
                    artifact,
                    suite_sha256=suite_sha256,
                    evidence_kind="sealed_runtime",
                    applicability="applicable_sealed_runtime",
                )

    def test_provider_authorization_derives_current_authenticated_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, _request_value = self._configured_live(root)
            retained = self._write_provider_preflight(
                root, run, completed_at_unix=int(time.time())
            )
            binding = provider_config.provider_binding(run)
            self.assertIsNotNone(binding)
            authorized = preflight.authorize_provider_action(run, binding.public)
            self.assertEqual(authorized, retained["record"])

            run["worker_inventory_sha256"] = "6" * 64
            with self.assertRaisesRegex(experiment.ContractError, "identity"):
                preflight.authorize_provider_action(run, binding.public)

    def test_simulated_evidence_cannot_authorize_provider_spend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, _request_value = self._configured_live(root)
            with self.assertRaisesRegex(
                provider_transport.ProviderError, "loading"
            ):
                self._write_provider_preflight(
                    root,
                    run,
                    completed_at_unix=int(time.time()),
                    applicability="simulated_static",
                    evidence_kind="unittest",
                    outcome_origin="synthetic_fixture",
                )

    def test_loader_rejects_failed_or_skipped_required_suite(self) -> None:
        for status in ("failed", "error", "skipped"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run, _request_value = self._configured_live(root)
                with self.assertRaisesRegex(
                    provider_transport.ProviderError, "loading"
                ):
                    self._write_provider_preflight(
                        root,
                        run,
                        completed_at_unix=int(time.time()),
                        outcome_status=status,
                    )

    def test_loader_rejects_missing_or_tampered_referenced_artifact(self) -> None:
        for mutation in ("missing", "tampered", "forged_failed_metadata"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run, _request_value = self._configured_live(root)
                retained = self._write_provider_preflight(
                    root,
                    run,
                    completed_at_unix=int(time.time()),
                    load_authorization=False,
                )
                artifact = next(iter(retained["case_paths"].values()))
                if mutation == "missing":
                    artifact.unlink()
                elif mutation == "tampered":
                    artifact.write_bytes(artifact.read_bytes() + b"tampered\n")
                else:
                    failed = b"FAILED\n"
                    artifact.write_bytes(failed)
                    suite = json.loads(retained["suite_path"].read_bytes())
                    name = next(iter(retained["case_paths"]))
                    suite["cases"][name]["artifact_sha256"] = hashlib.sha256(
                        failed
                    ).hexdigest()
                    suite["cases"][name]["artifact_size"] = len(failed)
                    body = {
                        key: value
                        for key, value in suite.items()
                        if key != "suite_sha256"
                    }
                    suite["suite_sha256"] = hashlib.sha256(
                        experiment.canonical_json_bytes(body)
                    ).hexdigest()
                    retained["suite_path"].write_bytes(
                        experiment.canonical_json_bytes(suite) + b"\n"
                    )
                with self.assertRaisesRegex(
                    provider_transport.ProviderError, "loading"
                ):
                    provider_service.load_preflight_authorization(
                        run,
                        preflight_path=root / "deterministic-preflight.json",
                        suite_artifact_path=retained["suite_path"],
                        max_age_seconds=300,
                    )

    def test_loader_rejects_mismatched_identity_or_static_classification(self) -> None:
        for mutation in ("identity", "static"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run, _request_value = self._configured_live(root)
                binding = run["provider_binding"]
                mismatched = {
                    "image_digest": run["image_digest"],
                    "runtime_sha256": "6" * 64,
                    "native_decide_policy_sha256": run[
                        "native_decide_policy_sha256"
                    ],
                    "tool_schema_sha256": binding["tool_schema_sha256"],
                    "provider_identity_sha256": binding["binding_sha256"],
                }
                with self.assertRaisesRegex(
                    provider_transport.ProviderError, "loading"
                ):
                    self._write_provider_preflight(
                        root,
                        run,
                        completed_at_unix=int(time.time()),
                        evidence_kind=(
                            "static_policy" if mutation == "static" else "sealed_runtime"
                        ),
                        applicability=(
                            "simulated_static"
                            if mutation == "static"
                            else "applicable_sealed_runtime"
                        ),
                        retained_identity_override=(
                            mismatched if mutation == "identity" else None
                        ),
                    )

    def test_direct_provider_service_call_fails_before_transport_without_authorization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, request = self._configured_live(root)
            transport = mock.Mock()

            with mock.patch.object(
                provider_transport, "provider_round", transport
            ), self.assertRaisesRegex(
                provider_transport.ProviderError, "preflight"
            ):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)

            transport.assert_not_called()
            journal = next((root / "evidence" / "provider-journal").glob("*.json"))
            self.assertEqual(json.loads(journal.read_bytes())["status"], "reserved")

    def test_direct_provider_service_rejects_stale_or_tampered_authorization(
        self,
    ) -> None:
        for mutation in ("stale", "signed_tamper"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run, request = self._configured_live(root)
                now = int(time.time())
                self._write_provider_preflight(
                    root,
                    run,
                    completed_at_unix=now,
                    max_age_seconds=300,
                )
                if mutation == "signed_tamper":
                    run["deterministic_preflight"]["suite_sha256"] = "6" * 64
                transport = mock.Mock()
                clock = (
                    mock.patch("autofv.preflight.time.time", return_value=now + 301)
                    if mutation == "stale"
                    else contextlib.nullcontext()
                )

                with clock, mock.patch.object(
                    provider_transport, "provider_round", transport
                ), self.assertRaisesRegex(
                    provider_transport.ProviderError, "preflight"
                ):
                    provider_service.dispatch(run, request, run_token=RUN_TOKEN)

                transport.assert_not_called()

    def test_direct_provider_service_accepts_current_sealed_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, request = self._configured_live(root)
            self._write_provider_preflight(
                root, run, completed_at_unix=int(time.time())
            )
            transport = mock.Mock(side_effect=RuntimeError("transport reached"))

            with mock.patch.object(
                provider_transport, "provider_round", transport
            ), self.assertRaisesRegex(RuntimeError, "transport reached"):
                provider_service.dispatch(run, request, run_token=RUN_TOKEN)

            transport.assert_called_once_with(run, request)

    def test_trusted_provider_setup_loads_evidence_before_dispatch(self) -> None:
        for age in (0, 301):
            with self.subTest(age=age), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run, request = self._configured_live(root)
                self._write_provider_preflight(
                    root, run, completed_at_unix=int(time.time()) - age,
                    load_authorization=False,
                )
                transport = mock.Mock(side_effect=RuntimeError("transport reached"))
                with mock.patch.object(provider_transport, "provider_round", transport):
                    with self.assertRaisesRegex(provider_transport.ProviderError, "preflight"):
                        provider_service.dispatch(run, request, run_token=RUN_TOKEN)
                    transport.assert_not_called()
                    # Reconstruct the same authenticated binding, as on recovery,
                    # after collecting identity-bound deterministic evidence.
                    provider_service.release(run)
                    with mock.patch.dict(os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}), mock.patch(
                        "autofv.provider_service._serve", return_value=_InertServer()
                    ):
                        setup = lambda: worker_proxy.configure_provider(
                            run, env_path=root / "providers.env",
                            tool_schemas=_tools(),
                            preflight_path=root / "deterministic-preflight.json",
                            suite_artifact_path=root / "retained-suite.json",
                            preflight_max_age_seconds=300,
                        )
                        if age:
                            with self.assertRaisesRegex(worker_proxy.WorkerError, "preflight"):
                                setup()
                            transport.assert_not_called()
                            continue
                        setup()
                    worker_proxy.stage_provider_messages(run, request, _messages())
                    with self.assertRaisesRegex(RuntimeError, "transport reached"):
                        provider_service.dispatch(run, request, run_token=RUN_TOKEN)
                    transport.assert_called_once_with(run, request)


if __name__ == "__main__":
    unittest.main()
