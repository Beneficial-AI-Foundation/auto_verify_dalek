"""Host-only sleep/clock regressions; subprocesses and reference inputs are synthetic."""
from pathlib import Path
from decimal import Decimal
import asyncio
import copy
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from autofv import contracts, experiment, fvs_profile, model, preflight_runner, run_state, worker, worker_runtime
from tests import test_fvs_preflight as preflight_fixtures


class WorkerDeadlineTests(unittest.TestCase):
    def test_epoch_jump_expires_and_reaps_real_child(self):
        children = []
        spawn = subprocess.Popen
        counter = time.perf_counter
        def capture(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child
        epoch = iter((100.0, 31100.0))
        start = counter()
        with mock.patch.object(worker_runtime.subprocess, "Popen", side_effect=capture), \
             mock.patch.object(worker_runtime.time, "time", side_effect=lambda: next(epoch, 31100.0)):
            with self.assertRaisesRegex(RuntimeError, "timed out.*monotonic.*epoch"):
                worker_runtime.bounded_run((sys.executable, "-c", "import time; time.sleep(30)"),
                    input_bytes=None, timeout=5, error=RuntimeError, what="synthetic sleep", limit=1024)
        self.assertLess(counter() - start, 1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)

    def test_backward_epoch_cannot_extend_monotonic_timeout(self):
        mono, epoch = iter((100.0, 106.0)), iter((100.0, 50.0))
        with mock.patch.object(worker_runtime.time, "monotonic", side_effect=lambda: next(mono, 106.0)), \
             mock.patch.object(worker_runtime.time, "time", side_effect=lambda: next(epoch, 50.0)):
            with self.assertRaisesRegex(RuntimeError, "6.000s monotonic / -50.000s epoch"):
                worker_runtime.bounded_run((sys.executable, "-c", "import time; time.sleep(30)"),
                    input_bytes=None, timeout=5, error=RuntimeError, what="synthetic rollback", limit=1024)

    def test_handoff_refuses_after_sleep_without_arming_alarm(self):
        state = {"run": {}, "config": {"max_wall_seconds": 1800}, "wall_seconds_used": Decimal(0),
            "finalization_reserve_seconds": Decimal(5), "wall_started_monotonic_ns": 1_000_000_000,
            "wall_started_epoch_ns": 101_000_000_000}
        with mock.patch.object(preflight_runner.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(preflight_runner.signal, "signal"), \
             mock.patch.object(preflight_runner.signal, "setitimer") as alarm, \
             mock.patch.object(run_state.time, "monotonic_ns", return_value=4_000_000_000), \
             mock.patch.object(run_state.time, "time_ns", return_value=31101_000_000_000):
            with self.assertRaises(contracts.ContractError):
                with preflight_runner._preflight_deadline(state):
                    self.fail("Sleep-exhausted handoff entered")
        alarm.assert_not_called()
        self.assertGreaterEqual(state["wall_seconds_used"], 31000)

    def test_failure_does_not_recharge_existing_accounting_anchors(self):
        run = {"run_id": "synthetic-existing"}
        state = {"run": run, "wall_seconds_used": Decimal(500),
                 "wall_started_monotonic_ns": 501_000_000_000,
                 "wall_started_epoch_ns": 601_000_000_000}
        with mock.patch.object(experiment.time, "monotonic_ns", return_value=701_000_000_000), \
             mock.patch.object(experiment.time, "time_ns", return_value=801_000_000_000), \
             mock.patch.object(experiment.results, "persist_l0_sources"), \
             mock.patch.object(experiment.results, "render_attempt", side_effect=lambda run, state, **kwargs:
                ({"wall": state["wall_seconds_used"]}, {})), \
             mock.patch.object(experiment.results, "persist_attempt"):
            result = experiment._persist_unallocated_attempt({}, Path("synthetic-target"), Path("synthetic-config"),
                1_000_000_000, wall_started_epoch=101_000_000_000, outcome="infrastructure_failed",
                reason="synthetic", detail=RuntimeError("synthetic failure"), existing_run=run, existing_state=state)
        self.assertEqual(result["wall"], Decimal(700))
        self.assertEqual(state["wall_seconds_used"], Decimal(500))
        self.assertEqual(state["wall_started_monotonic_ns"], 501_000_000_000)


class HelperMilestoneTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.epoch = 1000.0
        for name, value in [("monotonic", lambda: self.now), ("time", lambda: self.epoch),
                            ("monotonic_ns", lambda: int(self.now * 1e9)),
                            ("time_ns", lambda: int(self.epoch * 1e9))]:
            patcher = mock.patch.object(time, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # 600s pre-CLI preparation plus 700s inside the invocation are already charged.
        self.state = {"run": {"execution_mode": "proof_only", "preparation_manifest": {}},
            "config": {"schema": "autofv-run/v2", "role_profile": fvs_profile.PROFILE_ID, "max_wall_seconds": 3600},
            "wall_seconds_used": Decimal(1300), "wall_started_monotonic_ns": int(self.now * 1e9),
            "wall_started_epoch_ns": int(self.epoch * 1e9), "finalization_reserve_seconds": Decimal(5)}

    def advance(self, seconds):
        self.now += seconds
        self.epoch += seconds

    def test_preparation_counts_and_provider_timeout_is_clamped_without_config_mutation(self):
        config = copy.deepcopy(self.state["config"])
        with run_state.helper_work_budget(self.state, 2100):
            self.assertEqual(worker_runtime.work_timeout(1200), 200)
            self.advance(180)
            self.assertEqual(model._provider_timeout_seconds(self.state), 20)
            self.assertEqual(worker_runtime.work_timeout(1200), 20)
        self.assertEqual(self.state["config"], config)
        self.assertEqual(self.state["finalization_reserve_seconds"], 5)
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())
        # Starting the next scope charges elapsed time; it does not restart either clock.
        with run_state.helper_work_budget(self.state, 1200):
            self.assertEqual(worker_runtime.work_timeout(1200), 920)

    def test_first_submission_cutoff_refuses_new_work_and_restores_scope(self):
        with mock.patch.object(worker_runtime.subprocess, "Popen", side_effect=AssertionError("late spawn")) as spawn:
            with self.assertRaises(contracts.BudgetExhausted):
                with run_state.helper_work_budget(self.state, 2100):
                    self.advance(201)
                    worker_runtime.bounded_run(("unused",), None, 1200,
                        error=RuntimeError, what="synthetic", limit=1024)
            spawn.assert_not_called()
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())
        with self.assertRaises(contracts.BudgetExhausted):
            with run_state.helper_work_budget(self.state, 2100):
                self.fail("Expired submission milestone was reset")

    def test_nested_scopes_do_not_extend_and_verifier_keeps_reserved_capacity(self):
        with run_state.helper_work_budget(self.state, 2100):
            with run_state.helper_work_budget(self.state, 1200):
                self.assertEqual(worker_runtime.work_timeout(1200), 200)
        # Generation finished with 1201s left, just before its admission cutoff.
        self.advance(1099)
        with run_state.helper_work_budget(self.state, 1200):
            self.assertEqual(worker_runtime.work_timeout(1200), 1)
        with run_state.helper_work_budget(self.state, 300):
            self.assertEqual(worker_runtime.work_timeout(1200), 901)
        self.advance(2)
        with self.assertRaises(contracts.BudgetExhausted):
            with run_state.helper_work_budget(self.state, 1200):
                self.fail("Late verification admission")
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())

    def test_sleep_counts_and_lower_limits_are_not_raised(self):
        with self.assertRaises(contracts.BudgetExhausted):
            with run_state.helper_work_budget(self.state, 2100):
                self.epoch += 201  # monotonic clock did not advance during simulated sleep
                run_state._check_wall_budget(self.state)
        self.state["config"]["max_wall_seconds"] = 1800
        with self.assertRaises(contracts.BudgetExhausted):
            with run_state.helper_work_budget(self.state, 2100):
                self.fail("Raised a smaller existing allowance")

    def test_async_tool_inherits_deadline_and_non_smoke_path_is_unchanged(self):
        async def tool():
            return await asyncio.to_thread(worker_runtime.work_timeout, 1200)
        with run_state.helper_work_budget(self.state, 2100):
            self.assertEqual(asyncio.run(tool()), 200)
        self.state["run"]["execution_mode"] = "full"
        with run_state.helper_work_budget(self.state, 2100):
            self.assertEqual(worker_runtime.work_timeout(1200), 1200)


class HelperOwnedProcessTests(unittest.TestCase):
    def test_scoped_work_deadline_reaps_real_owned_child(self):
        children = []
        spawn = subprocess.Popen
        def capture(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child
        with mock.patch.object(worker_runtime.subprocess, "Popen", side_effect=capture):
            with self.assertRaises(contracts.BudgetExhausted):
                with worker_runtime.work_deadline(0.15, wall_limit=Decimal(1500)):
                    worker_runtime.bounded_run((sys.executable, "-c", "import time; time.sleep(30)"),
                        None, 1200, error=RuntimeError, what="synthetic helper", limit=1024)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())


class EarlyFailureDeadlineTests(unittest.TestCase):
    bound_packet = preflight_fixtures.PreparedFvsPreflightTests.bound_packet
    inputs = preflight_fixtures.PreparedFvsPreflightTests.inputs
    exercise = preflight_fixtures.PreparedFvsPreflightTests.exercise

    def setUp(self):
        preflight_fixtures.PreparedFvsPreflightTests.setUp(self)

    def test_controller_seed_failure_retains_original_epoch(self, *, outer_elapsed_seconds=0):
        self.inputs()
        self.prepared_inputs = (*self.prepared_inputs[:3],
            {k: str(v) for k, v in self.prepared_inputs[3].items()})
        for name in ("preparation_manifest", "probe_rust_evidence", "probe_aeneas_evidence", "dependency_cache"):
            self.options[name].touch()
        reference = self.root / "synthetic-reference.json"
        reference.write_text("{}")
        clocks = {"mono": 1_000_000_000, "epoch": 101_000_000_000}
        captured = []
        def controller(repo, config_path, output, **options):
            options.pop("check_model_accessibility", None)
            return experiment.run_experiment(repo, config_path, output_root=self.root / "attempts",
                verifier_reference=reference, execution_mode="proof_only", fresh_pair_preflight=True,
                budget_started_epoch_ns=clocks["epoch"] - outer_elapsed_seconds * 1_000_000_000, **options)
        def seed(*_args):
            clocks["mono"] += 890_000_000_000
            clocks["epoch"] += 31885_000_000_000
            raise worker.WorkerError("synthetic seed timeout")
        def render(run, state, **kwargs):
            captured.append(dict(state))
            return {"outcome": kwargs["outcome"], "wall": str(state["wall_seconds_used"])}, {}
        with mock.patch.object(preflight_runner, "run_fvs_preflight", side_effect=controller), \
             mock.patch.object(experiment.verifier, "bind_prepared_reference", return_value={"synthetic": True}), \
             mock.patch.object(experiment.verifier.counterexample, "external_reference_identity", return_value={"synthetic": True}), \
             mock.patch.object(experiment.results, "render_attempt", side_effect=render), \
             mock.patch.object(experiment.results, "persist_attempt"), \
             mock.patch.object(experiment.results, "persist_l0_sources"), \
             mock.patch.object(experiment.time, "monotonic_ns", side_effect=lambda: clocks["mono"]), \
             mock.patch.object(experiment.time, "time_ns", side_effect=lambda: clocks["epoch"]):
            result = self.exercise(patches=[mock.patch.object(worker, "seed_dependency_cache", side_effect=seed)])
        self.destroy_mock.assert_called_once()
        self.fetch_mock.assert_not_called()
        self.assertEqual(len(captured), 1)
        self.assertEqual(Decimal(result["wall"]), Decimal(31885 + outer_elapsed_seconds))
        original_epoch = (101 - outer_elapsed_seconds) * 1_000_000_000
        self.assertEqual(captured[0]["run"]["budget_started_epoch_ns"], original_epoch)
        self.assertEqual(run_state._checkpoint_identities(captured[0]["run"])["budget_started_epoch_ns"], original_epoch)

    def test_pre_cli_preparation_is_counted_on_actual_controller_failure_path(self):
        self.test_controller_seed_failure_retains_original_epoch(outer_elapsed_seconds=60)

    def test_expired_outer_clock_stops_before_worker_allocation(self):
        self.inputs()
        for name in ("preparation_manifest", "probe_rust_evidence", "probe_aeneas_evidence", "dependency_cache"):
            self.options[name].touch()
        reference = self.root / "synthetic-reference.json"
        reference.write_text("{}")
        with mock.patch.object(experiment.time, "time_ns", return_value=10_000_000_000_000), \
             mock.patch.object(worker, "prepare_run") as prepare, \
             mock.patch.object(experiment, "_persist_unallocated_attempt",
                               return_value={"outcome": "budget_exhausted"}) as persist:
            result = experiment.run_experiment(self.target, self.config_path, output_root=self.root / "attempts",
                verifier_reference=reference, execution_mode="proof_only", fresh_pair_preflight=True,
                budget_started_epoch_ns=1, **self.options)
        prepare.assert_not_called()
        self.assertEqual(result["outcome"], "budget_exhausted")
        self.assertEqual(persist.call_args.kwargs["wall_started_epoch"], 1)
        self.assertEqual(persist.call_args.kwargs["reason"], "wall_budget_exhausted")

    def test_outer_clock_cannot_be_future_malformed_or_used_to_reset_resume(self):
        kwargs = dict(env_file="unused", execution_mode="proof_only", fresh_pair_preflight=True,
                      preparation_manifest="unused", probe_rust_evidence="unused",
                      probe_aeneas_evidence="unused", dependency_cache="unused")
        with mock.patch.object(experiment.time, "time_ns", return_value=100), \
             mock.patch.object(experiment.results, "validate_output_root") as validate:
            for value in (True, "1", 0, -1, 101):
                with self.subTest(value=value), self.assertRaisesRegex(contracts.ContractError, "outer budget clock"):
                    experiment.run_experiment("unused", "unused", budget_started_epoch_ns=value, **kwargs)
            with self.assertRaises(contracts.ContractError):
                experiment.run_experiment("unused", "unused", budget_started_epoch_ns=1, resume_from="unused", **kwargs)
            with self.assertRaisesRegex(contracts.ContractError, "outer budget clock"):
                experiment.run_experiment("unused", "unused", budget_started_epoch_ns=1)
            validate.assert_not_called()

    def test_cli_forwards_original_outer_epoch_without_replacing_config(self):
        argv = ["autofv", "run", "/target", "--config", "/config", "--env-file", "/env",
                "--fresh-pair-preflight", "--execution-mode", "proof-only",
                "--preparation-manifest", "/manifest", "--preparation-evidence", "/probes",
                "--preparation-cache", "/cache", "--verifier-reference", "/reference",
                "--budget-started-epoch-ns", "123"]
        with mock.patch.object(sys, "argv", argv), mock.patch("builtins.print"), \
             mock.patch.object(experiment, "run_experiment", return_value={"outcome": "success"}) as run:
            experiment.main()
        self.assertEqual(run.call_args.args, ("/target", "/config"))
        self.assertEqual(run.call_args.kwargs["budget_started_epoch_ns"], 123)
        self.assertTrue(run.call_args.kwargs["fresh_pair_preflight"])


if __name__ == "__main__":
    unittest.main()
