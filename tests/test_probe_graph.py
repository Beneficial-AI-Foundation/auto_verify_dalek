import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import experiment, probes, results, worker


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/fixtures/diamond"
RUST_PATH = ROOT / "tests/fixtures/probes/diamond-rust.json"
AENEAS_PATH = ROOT / "tests/fixtures/probes/diamond-aeneas.json"
TARGET_RUST = "probe:autofv-diamond/0.1.0/top()"
TOP = "probe:Diamond.top"
LEFT = "probe:Diamond.left"
RIGHT = "probe:Diamond.right"
TOP_SPEC = "probe:Diamond.top_spec"


def _bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class ProbeGraphTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((TARGET / "autofv.json").read_text())
        self.rust_raw = RUST_PATH.read_bytes()
        self.aeneas_raw = AENEAS_PATH.read_bytes()
        self.rust = json.loads(self.rust_raw)
        self.aeneas = json.loads(self.aeneas_raw)

    def parse(self, *, rust=None, aeneas=None):
        return probes.parse_probe_bytes(
            self.manifest,
            self.rust_raw if rust is None else _bytes(rust),
            self.aeneas_raw if aeneas is None else _bytes(aeneas),
        )

    def test_golden_graph_keeps_consumer_direction_and_bottom_up_batches(self):
        graph = self.parse()

        self.assertEqual(graph["frozen_targets"], [TOP])
        self.assertEqual(graph["supplied_specs"], {TOP: TOP_SPEC})
        self.assertEqual(graph["selected_nodes"], [LEFT, RIGHT, TOP])
        self.assertEqual(
            graph["term_dependencies"], [[TOP, LEFT], [TOP, RIGHT]]
        )
        self.assertEqual(graph["type_dependencies"], [[TOP_SPEC, TOP]])
        self.assertEqual(graph["contract_order"], [TOP, LEFT, RIGHT])
        self.assertEqual(graph["proof_batches"], [[LEFT, RIGHT], [TOP]])

    def test_target_report_keeps_public_metadata_separate_from_graph_tops(self):
        renderer = getattr(probes, "render_target_report", None)
        self.assertIsNotNone(renderer, "canonical target report renderer is missing")

        report = json.loads(renderer(self.parse()))
        self.assertEqual(
            set(report),
            {"schema", "inputs", "tools", "graph_tops", "declarations", "diagnostics"},
        )
        self.assertEqual(report["schema"], "target-report/v1")
        self.assertEqual(report["graph_tops"], [TARGET_RUST])
        self.assertEqual(
            report["inputs"],
            {
                "probe_aeneas_sha256": hashlib.sha256(self.aeneas_raw).hexdigest(),
                "probe_rust_sha256": hashlib.sha256(self.rust_raw).hexdigest(),
            },
        )
        self.assertEqual(
            report["tools"],
            {
                "probe_aeneas": self.aeneas["tool"],
                "probe_rust": self.rust["tool"],
            },
        )
        top = report["declarations"][TARGET_RUST]
        self.assertIs(top["public_api"], True)
        self.assertEqual(top["declaration"], TOP)
        self.assertEqual(top["primary_spec"], TOP_SPEC)
        self.assertEqual(top["directed_closure"], [LEFT, RIGHT, TOP])
        self.assertEqual(
            top["source"], {"path": "src/lib.rs", "lines": [9, 11]}
        )
        self.assertEqual(report["diagnostics"], [])

    def test_target_report_is_canonical_and_does_not_infer_public_metadata(self):
        graph = self.parse()
        expected = probes.render_target_report(graph)

        def reverse_objects(value):
            if isinstance(value, dict):
                return {
                    key: reverse_objects(item)
                    for key, item in reversed(tuple(value.items()))
                }
            if isinstance(value, list):
                return [reverse_objects(item) for item in value]
            return value

        self.assertEqual(
            probes.render_target_report(reverse_objects(graph)), expected
        )

        rust = copy.deepcopy(self.rust)
        del rust["data"][TARGET_RUST]["is-public-api"]
        report = json.loads(probes.render_target_report(self.parse(rust=rust)))
        self.assertIsNone(report["declarations"][TARGET_RUST]["public_api"])

    def test_inspection_source_and_edge_evidence_is_required(self):
        missing_locations = copy.deepcopy(self.rust)
        del missing_locations["data"][TARGET_RUST]["dependencies-with-locations"]
        with self.assertRaisesRegex(
            probes.ProbeError, "project_rust_fields_missing"
        ):
            self.parse(rust=missing_locations)

        missing_source_identity = copy.deepcopy(self.rust)
        del missing_source_identity["source"]
        with self.assertRaisesRegex(
            probes.ProbeError, "probe_rust_source_identity_missing"
        ):
            self.parse(rust=missing_source_identity)

        malformed_source_identity = copy.deepcopy(self.rust)
        malformed_source_identity["source"] = []
        with self.assertRaisesRegex(
            probes.ProbeError, "probe_rust_source_identity_missing"
        ):
            self.parse(rust=malformed_source_identity)

        mismatched_source_identity = copy.deepcopy(self.aeneas)
        mismatched_source_identity["inputs"][0]["source"]["package"] = "other"
        with self.assertRaisesRegex(
            probes.ProbeError, "probe_input_source_identity_mismatch"
        ):
            self.parse(aeneas=mismatched_source_identity)

    def test_cycle_diagnostic_names_members_edges_and_source_locations(self):
        cycle = copy.deepcopy(self.aeneas)
        cycle["data"][LEFT]["dependencies"] = [TOP]
        cycle["data"][LEFT]["term-dependencies"] = [TOP]

        with self.assertRaises(probes.ProbeError) as raised:
            self.parse(aeneas=cycle)

        diagnostic = str(raised.exception)
        for expected in (
            "unsupported_dependency_cycle",
            LEFT,
            TOP,
            "Diamond/Left.lean",
            "Diamond/Top.lean",
            '"edges"',
            '"members"',
            '"sources"',
        ):
            self.assertIn(expected, diagnostic)

    def test_wrong_envelopes_and_incomplete_target_truth_fail_closed(self):
        cases = []

        wrong_schema = copy.deepcopy(self.aeneas)
        wrong_schema["schema"] = "probe-aeneas/unknown"
        cases.append(("schema", "probe_aeneas_schema_mismatch", None, wrong_schema))

        wrong_tool = copy.deepcopy(self.rust)
        wrong_tool["tool"]["version"] = "0.9.0"
        cases.append(("tool", "probe_rust_tool_mismatch", wrong_tool, None))

        missing_target = copy.deepcopy(self.rust)
        del missing_target["data"][TARGET_RUST]
        cases.append(("target", "manifest_target_missing", missing_target, None))

        missing_translation = copy.deepcopy(self.aeneas)
        del missing_translation["data"][TARGET_RUST]["translation-name"]
        cases.append(
            ("translation", "manifest_target_translation_missing", None, missing_translation)
        )

        missing_spec = copy.deepcopy(self.aeneas)
        del missing_spec["data"][TOP]["primary-spec"]
        cases.append(("primary spec", "manifest_primary_spec_mismatch", None, missing_spec))

        missing_source = copy.deepcopy(self.aeneas)
        del missing_source["data"][LEFT]["code-path"]
        cases.append(("source", "selected_lean_fields_missing", None, missing_source))

        missing_status = copy.deepcopy(self.aeneas)
        del missing_status["data"][LEFT]["verification-status"]
        cases.append(("status", "selected_lean_fields_missing", None, missing_status))

        for name, reason, rust, aeneas in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                probes.ProbeError, reason
            ):
                self.parse(rust=rust, aeneas=aeneas)

        with self.assertRaisesRegex(probes.ProbeError, "invalid_probe_aeneas"):
            probes.parse_probe_bytes(self.manifest, self.rust_raw, b"{broken")

    def test_missing_failed_untracked_and_cyclic_dependencies_fail_closed(self):
        cases = []

        missing_term = copy.deepcopy(self.aeneas)
        missing_term["data"][TOP]["term-dependencies"].remove(LEFT)
        cases.append(("missing edge", "selected_dependency_edge_missing", missing_term))

        unknown_term = copy.deepcopy(self.aeneas)
        unknown_term["data"][TOP]["term-dependencies"].append("probe:Diamond.unknown")
        cases.append(("unknown term", "selected_term_dependency_missing", unknown_term))

        unknown_type = copy.deepcopy(self.aeneas)
        unknown_type["data"][TOP_SPEC]["type-dependencies"] = ["probe:Diamond.unknown"]
        cases.append(("unknown type", "selected_type_dependency_missing", unknown_type))

        failed = copy.deepcopy(self.aeneas)
        failed["data"][LEFT]["verification-status"] = "failed"
        cases.append(("failed", "selected_dependency_failed", failed))

        untracked = copy.deepcopy(self.aeneas)
        untracked["data"][LEFT]["is-relevant"] = False
        cases.append(("untracked", "selected_lean_atom_not_schedulable", untracked))

        cycle = copy.deepcopy(self.aeneas)
        cycle["data"][LEFT]["dependencies"] = [TOP]
        cycle["data"][LEFT]["term-dependencies"] = [TOP]
        cases.append(("cycle", "unsupported_dependency_cycle", cycle))

        unsafe_source = copy.deepcopy(self.aeneas)
        unsafe_source["data"][RIGHT]["code-path"] = "../outside.lean"
        cases.append(("unsafe source", "selected_lean_source_invalid", unsafe_source))

        for name, reason, aeneas in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                probes.ProbeError, reason
            ):
                self.parse(aeneas=aeneas)

    def test_order_duplicates_timestamps_and_cross_language_edges_do_not_change_graph(self):
        baseline = self.parse()

        def reverse_objects(value):
            if isinstance(value, dict):
                return {
                    key: reverse_objects(item)
                    for key, item in reversed(tuple(value.items()))
                }
            if isinstance(value, list):
                return [reverse_objects(item) for item in reversed(value)]
            return value

        rust = reverse_objects(self.rust)
        aeneas = reverse_objects(self.aeneas)
        rust["timestamp"] = "2099-01-01T00:00:00Z"
        aeneas["timestamp"] = "2099-01-01T00:00:00Z"
        aeneas["data"][TOP]["term-dependencies"] += [LEFT, RIGHT]
        aeneas["data"][TOP]["dependencies"] += [TARGET_RUST, TARGET_RUST]
        changed = self.parse(rust=rust, aeneas=aeneas)

        self.assertEqual(changed["graph_sha256"], baseline["graph_sha256"])
        self.assertEqual(changed["term_dependencies"], baseline["term_dependencies"])
        self.assertEqual(changed["proof_batches"], baseline["proof_batches"])
        self.assertNotEqual(changed["probe_rust_sha256"], baseline["probe_rust_sha256"])
        self.assertNotEqual(
            changed["probe_aeneas_sha256"], baseline["probe_aeneas_sha256"]
        )

    def test_probe_failures_emit_a_result_before_any_model_call(self):
        mutations = []

        missing_edge = copy.deepcopy(self.aeneas)
        missing_edge["data"][TOP]["term-dependencies"].remove(LEFT)
        mutations.append(("missing edge", _bytes(missing_edge)))

        failed = copy.deepcopy(self.aeneas)
        failed["data"][LEFT]["verification-status"] = "failed"
        mutations.append(("failed dependency", _bytes(failed)))

        cycle = copy.deepcopy(self.aeneas)
        cycle["data"][LEFT]["dependencies"] = [TOP]
        cycle["data"][LEFT]["term-dependencies"] = [TOP]
        mutations.append(("cycle", _bytes(cycle)))

        for name, aeneas_raw in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                calls = []
                persisted = []

                def prepare(target, manifest, lock):
                    return {
                        "run_id": f"probe-failure-{name}",
                        "run_root": tmp,
                        "project_dir": str(TARGET),
                        "evidence_dir": str(Path(tmp) / "evidence"),
                        "volume": "unused-test-volume",
                        "agent_worker_id": "simulation",
                        "execution_tier": "simulation",
                        "cost_classification": "synthetic_fixture",
                        "snapshot_sha256": worker.hash_tree(TARGET),
                        "manifest_sha256": hashlib.sha256(
                            experiment.canonical_json_bytes(manifest)
                        ).hexdigest(),
                        "image_digest": lock["image"]["image_digest"],
                        "control_bundle_sha256": "1" * 64,
                        "base_commit": "2" * 40,
                        "events": ["validated"],
                    }

                with (
                    mock.patch.object(worker, "prepare_run", prepare),
                    mock.patch.object(
                        worker,
                        "run_probes",
                        return_value=(self.rust_raw, aeneas_raw),
                    ),
                    mock.patch.object(
                        results,
                        "persist_attempt",
                        side_effect=lambda run, result, receipt: persisted.append(
                            (result, receipt)
                        ),
                    ),
                ):
                    result = experiment.run_experiment(
                        TARGET,
                        TARGET / "run.json",
                        run_round=lambda request: calls.append(request),
                    )

                self.assertEqual(result["outcome"], "verification_failed")
                self.assertEqual(result["termination_reason"], "probe_failed")
                self.assertEqual(result["proxy_requests"], 0)
                self.assertEqual(calls, [])
                self.assertEqual(len(persisted), 1)
                self.assertEqual(
                    persisted[0][0]["outcome"], "verification_failed"
                )

    def test_raw_probe_files_survive_parse_failure(self):
        bad_aeneas = copy.deepcopy(self.aeneas)
        del bad_aeneas["data"][TOP]["verification-status"]
        bad_raw = _bytes(bad_aeneas)

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            evidence = Path(tmp) / "evidence"
            project.mkdir()
            shutil.copyfile(TARGET / "autofv.json", project / "autofv.json")

            def launch(argv, **kwargs):
                output = Path(argv[-1])
                output.write_bytes(self.rust_raw if argv[0] == "probe-rust" else bad_raw)
                return subprocess.CompletedProcess(argv, 0)

            with mock.patch.object(subprocess, "run", side_effect=launch):
                with self.assertRaises(probes.ProbeError):
                    probes.run_probes(project, evidence)

            self.assertEqual((evidence / "probe-rust.json").read_bytes(), self.rust_raw)
            self.assertEqual((evidence / "probe-aeneas.json").read_bytes(), bad_raw)

    def test_allocated_worker_launch_failure_persists_non_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = experiment.load_toolchain_lock()
            manifest = json.loads((TARGET / "autofv.json").read_text())
            with (
                mock.patch.object(worker.tempfile, "mkdtemp", return_value=tmp),
                mock.patch.object(
                    subprocess,
                    "run",
                    side_effect=FileNotFoundError("limactl is unavailable"),
                ),
                self.assertRaises(worker.WorkerError) as raised,
            ):
                worker.prepare_run(TARGET, manifest, lock)

            failure = raised.exception
            run = failure.run
            self.assertIsNotNone(run)
            self.assertEqual(run["events"], ["validated"])
            persisted = []
            calls = []
            with (
                mock.patch.object(worker, "prepare_run", side_effect=failure),
                mock.patch.object(
                    results,
                    "persist_attempt",
                    side_effect=lambda prepared, result, receipt: persisted.append(
                        (prepared, result, receipt)
                    ),
                ),
            ):
                result = experiment.run_experiment(
                    TARGET,
                    TARGET / "run.json",
                    run_round=lambda request: calls.append(request),
                )

            self.assertEqual(result["outcome"], "infrastructure_failed")
            self.assertEqual(
                result["termination_reason"], "worker_preparation_failed"
            )
            self.assertIn("limactl is unavailable", result["termination_detail"])
            self.assertEqual(calls, [])
            self.assertEqual(len(persisted), 1)
            self.assertEqual(
                persisted[0][1]["outcome"], "infrastructure_failed"
            )

    def test_non_success_result_makes_the_public_cli_exit_one(self):
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "autofv",
                    "run",
                    "--target",
                    str(TARGET),
                    "--run-config",
                    str(TARGET / "run.json"),
                ],
            ),
            mock.patch.object(
                experiment,
                "run_experiment",
                return_value={"outcome": "failure"},
            ),
            mock.patch("builtins.print"),
            self.assertRaises(SystemExit) as stopped,
        ):
            experiment.main()

        self.assertEqual(stopped.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
