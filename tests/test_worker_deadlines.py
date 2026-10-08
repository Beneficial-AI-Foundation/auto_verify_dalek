"""Host-only sleep/clock regressions; subprocesses and reference inputs are synthetic."""
from pathlib import Path
from decimal import Decimal
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from autofv import contracts, experiment, preflight_runner, run_state, worker, worker_runtime
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


class EarlyFailureDeadlineTests(unittest.TestCase):
    bound_packet = preflight_fixtures.PreparedFvsPreflightTests.bound_packet
    inputs = preflight_fixtures.PreparedFvsPreflightTests.inputs
    exercise = preflight_fixtures.PreparedFvsPreflightTests.exercise

    def setUp(self):
        preflight_fixtures.PreparedFvsPreflightTests.setUp(self)

    def test_controller_seed_failure_retains_original_epoch(self):
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
                verifier_reference=reference, execution_mode="proof_only", fresh_pair_preflight=True, **options)
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
        self.assertEqual(Decimal(result["wall"]), Decimal(31885))


if __name__ == "__main__":
    unittest.main()
