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

from autofv import experiment, graph_scheduler, probes, results, worker


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests/fixtures/diamond"
RUST_PATH = ROOT / "tests/fixtures/probes/diamond-rust.json"
AENEAS_PATH = ROOT / "tests/fixtures/probes/diamond-aeneas.json"
TARGET_RUST = "probe:autofv-diamond/0.1.0/top()"
TOP = "probe:Diamond.top"
LEFT = "probe:Diamond.left"
RIGHT = "probe:Diamond.right"
TOP_SPEC = "probe:Diamond.top_spec"
SIBLING_RUST = "probe:autofv-diamond/0.1.0/sibling()"
SIBLING = "probe:Diamond.sibling"
SIBLING_SPEC = "probe:Diamond.sibling_spec"


def _bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class ProgressiveSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "selected_nodes": ["probe:root", "probe:leaf_a", "probe:leaf_b"],
            "term_dependencies": [["probe:root", "probe:leaf_a"],
                                  ["probe:root", "probe:leaf_b"]],
        }

    def test_preferred_leaf_stops_only_on_confirmed_acceptance(self):
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            self.graph,
            lambda node: attempted.append(node) or node,
            lambda node, _job: node == "probe:leaf_a",
            preferred_leaf="probe:leaf_b",
            stop_after_accept=True,
        )
        self.assertEqual(attempted, ["probe:leaf_b", "probe:leaf_a"])
        self.assertEqual(accepted, {"probe:leaf_a"})
        self.assertNotIn("probe:root", attempted)

    def test_full_mode_releases_root_only_after_both_leaves(self):
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            self.graph,
            lambda node: attempted.append(node) or node,
            lambda node, _job: True,
        )
        self.assertEqual(accepted, set(self.graph["selected_nodes"]))
        self.assertEqual(attempted[-1], "probe:root")

    def test_rejects_nonleaf_preference_before_running_jobs(self):
        attempted = []
        with self.assertRaisesRegex(graph_scheduler.ContractError, "not dependency-ready"):
            graph_scheduler._schedule_progressive(
                self.graph, lambda node: attempted.append(node),
                lambda _node, _job: True, preferred_leaf="probe:root"
            )
        self.assertEqual(attempted, [])

    def test_restart_releases_only_dependents_of_confirmed_nodes(self):
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            self.graph,
            lambda node: attempted.append(node) or node,
            lambda _node, _job: True,
            accepted_nodes=["probe:leaf_a"],
        )
        self.assertEqual(attempted, ["probe:leaf_b", "probe:root"])
        self.assertEqual(accepted, set(self.graph["selected_nodes"]))

    def test_rejects_inconsistent_restarted_acceptance_before_jobs(self):
        attempted = []
        with self.assertRaisesRegex(graph_scheduler.ContractError, "dependency-closed"):
            graph_scheduler._schedule_progressive(
                self.graph, lambda node: attempted.append(node),
                lambda _node, _job: True, accepted_nodes=["probe:root"]
            )
        self.assertEqual(attempted, [])

    def test_failed_leaf_does_not_release_consumer(self):
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            self.graph,
            lambda node: attempted.append(node) or node,
            lambda node, _job: node == "probe:leaf_a",
        )
        self.assertEqual(attempted, ["probe:leaf_a", "probe:leaf_b"])
        self.assertEqual(accepted, {"probe:leaf_a"})

    def test_shared_helper_is_proved_once_before_both_consumers(self):
        graph = {
            "selected_nodes": ["probe:root", "probe:left", "probe:right", "probe:shared"],
            "term_dependencies": [["probe:root", "probe:left"], ["probe:root", "probe:right"],
                                  ["probe:left", "probe:shared"], ["probe:right", "probe:shared"]],
        }
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            graph, lambda node: attempted.append(node) or node, lambda _node, _job: True,
        )
        self.assertEqual(attempted, ["probe:shared", "probe:left", "probe:right", "probe:root"])
        self.assertEqual(accepted, set(graph["selected_nodes"]))

    def test_failed_leaf_blocks_only_its_consumer_while_sibling_continues(self):
        attempted = []
        accepted = graph_scheduler._schedule_progressive(
            self.graph,
            lambda node: attempted.append(node) or node,
            lambda node, _job: node != "probe:leaf_a",
        )
        self.assertEqual(attempted, ["probe:leaf_a", "probe:leaf_b"])
        self.assertEqual(accepted, {"probe:leaf_b"})

    def test_restart_never_retries_previously_accepted_smoke_leaf(self):
        attempted = []
        with self.assertRaisesRegex(graph_scheduler.ContractError, "not dependency-ready"):
            graph_scheduler._schedule_progressive(
                self.graph, lambda node: attempted.append(node),
                lambda _node, _job: True, accepted_nodes=["probe:leaf_a"],
                preferred_leaf="probe:leaf_a", stop_after_accept=True,
            )
        self.assertEqual(attempted, [])


class ProbeGraphTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((TARGET / "autofv.json").read_text())
        self.rust_raw = RUST_PATH.read_bytes()
        self.aeneas_raw = AENEAS_PATH.read_bytes()
        self.rust = json.loads(self.rust_raw)
        self.aeneas = json.loads(self.aeneas_raw)

    def test_prepared_input_binding_uses_external_probe_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            shutil.copytree(TARGET, target)
            manifest = json.loads((target / "autofv.json").read_text())
            graph = probes.parse_probe_bytes(
                manifest, RUST_PATH.read_bytes(), AENEAS_PATH.read_bytes()
            )
            files = [
                {
                    "path": name,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
                for name, raw, _mode in worker._runtime._tree_files(target)
            ]
            body = {
                "schema": "preparation-manifest/v1",
                "mode": "small",
                "source": {
                    "repository": "https://example.invalid/source.git",
                    "revision": "1" * 40,
                    "tree_sha256": "2" * 64,
                },
                "probes": {
                    name: {
                        "repository": f"https://example.invalid/{name}.git",
                        "revision": digit * 40,
                        "tree_sha256": digit * 64,
                        "version": "1.0.0",
                    }
                    for name, digit in (
                        ("probe-rust", "3"),
                        ("probe-aeneas", "4"),
                        ("probe-lean", "5"),
                    )
                },
                "target_report_sha256": hashlib.sha256(
                    probes.render_target_report(graph)
                ).hexdigest(),
                "probe_identities_sha256": "6" * 64,
                "roots": graph["frozen_targets"],
                "closures": {
                    root: graph["selected_nodes"]
                    for root in graph["frozen_targets"]
                },
                "retained_declarations": sorted(
                    set(graph["selected_nodes"])
                    | set(graph["supplied_specs"].values())
                ),
                "files": files,
                "tree_sha256": hashlib.sha256(
                    experiment.canonical_json_bytes(files)
                ).hexdigest(),
                "gates": {
                    name: "passed"
                    for name in (
                        "build",
                        "provenance",
                        "reproducibility",
                        "secret_scan",
                        "spoiler_scan",
                        "symlink_scan",
                    )
                },
            }
            preparation = {
                **body,
                "manifest_sha256": hashlib.sha256(
                    experiment.canonical_json_bytes(body)
                ).hexdigest(),
            }
            preparation_path = Path(tmp) / "preparation.json"
            preparation_path.write_bytes(
                experiment.canonical_json_bytes(preparation) + b"\n"
            )
            dependency_cache = Path(tmp) / "dependency-cache.tar.zst"
            dependency_cache.write_bytes(b"test dependency cache")

            observed, observed_graph, receipt, sources = (
                experiment._load_prepared_inputs(
                    target.resolve(),
                    manifest,
                    preparation_path.resolve(),
                    RUST_PATH.resolve(),
                    AENEAS_PATH.resolve(),
                    dependency_cache.resolve(),
                    execution_mode="proof_only",
                )
            )

            self.assertEqual(observed, preparation)
            self.assertEqual(observed_graph, graph)
            self.assertEqual(receipt["execution_mode"], "proof_only")
            self.assertEqual(
                receipt["dependency_cache_sha256"],
                hashlib.sha256(dependency_cache.read_bytes()).hexdigest(),
            )
            self.assertEqual(sources["probe-rust"], str(RUST_PATH.resolve()))

    def test_proof_source_path_uses_the_supplied_spec_file(self):
        graph = {
            "supplied_specs": {"probe:target": "probe:target_spec"},
            "source_paths": {
                "probe:target": "Generated/Funs.lean",
                "probe:target_spec": "Specs/Target.lean",
                "probe:helper": "Generated/Funs.lean",
            },
        }
        self.assertEqual(
            probes.proof_source_path(graph, "probe:target"), "Specs/Target.lean"
        )
        self.assertEqual(
            probes.proof_source_path(graph, "probe:helper"), "Generated/Funs.lean"
        )

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
        self.assertEqual(report["schema"], "target-report/v2")
        self.assertEqual(report["graph_tops"], [TOP])
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
        top = report["declarations"][TOP]
        self.assertEqual(top["rust_function"], TARGET_RUST)
        self.assertIs(top["public_api"], True)
        self.assertEqual(top["primary_spec"], TOP_SPEC)
        self.assertEqual(top["directed_closure"], [LEFT, RIGHT, TOP])
        self.assertEqual(
            top["source"], {"path": "Diamond/Top.lean", "lines": [6, 7]}
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
        self.assertIsNone(report["declarations"][TOP]["public_api"])

    def test_each_top_gets_its_directed_closure_not_shared_consumers(self):
        rust = copy.deepcopy(self.rust)
        sibling_rust = copy.deepcopy(rust["data"][TARGET_RUST])
        sibling_rust.update(
            {
                "dependencies": ["probe:autofv-diamond/0.1.0/left()"],
                "dependencies-with-locations": [
                    sibling_rust["dependencies-with-locations"][0]
                ],
                "display-name": "sibling",
                "is-public": False,
                "is-public-api": False,
                "rust-qualified-name": "autofv_diamond::sibling",
            }
        )
        rust["data"][SIBLING_RUST] = sibling_rust

        aeneas = copy.deepcopy(self.aeneas)
        merged_sibling = copy.deepcopy(aeneas["data"][TARGET_RUST])
        merged_sibling.update(
            {
                "dependencies": [
                    LEFT,
                    "probe:autofv-diamond/0.1.0/left()",
                ],
                "display-name": "sibling",
                "is-public": False,
                "is-public-api": False,
                "rust-qualified-name": "autofv_diamond::sibling",
                "translation-name": SIBLING,
            }
        )
        sibling = copy.deepcopy(aeneas["data"][TOP])
        sibling.update(
            {
                "dependencies": [
                    LEFT,
                    "probe:autofv-diamond/0.1.0/left()",
                ],
                "display-name": "sibling",
                "primary-spec": SIBLING_SPEC,
                "specs": [SIBLING_SPEC],
                "term-dependencies": [LEFT],
            }
        )
        sibling_spec = copy.deepcopy(aeneas["data"][TOP_SPEC])
        sibling_spec.update(
            {
                "dependencies": [SIBLING, SIBLING_RUST],
                "display-name": "sibling_spec",
                "term-dependencies": [SIBLING],
                "type-dependencies": [SIBLING],
            }
        )
        aeneas["data"].update(
            {
                SIBLING_RUST: merged_sibling,
                SIBLING: sibling,
                SIBLING_SPEC: sibling_spec,
            }
        )

        report = json.loads(
            probes.render_target_report(self.parse(rust=rust, aeneas=aeneas))
        )
        self.assertEqual(report["graph_tops"], sorted([SIBLING, TOP]))
        self.assertIs(report["declarations"][SIBLING]["public_api"], False)
        self.assertEqual(
            report["declarations"][SIBLING]["directed_closure"],
            [LEFT, SIBLING],
        )
        self.assertEqual(
            report["declarations"][TOP]["directed_closure"],
            [LEFT, RIGHT, TOP],
        )

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

    def test_long_acyclic_closure_does_not_depend_on_python_recursion(self):
        nodes = {f"node-{index:04d}" for index in range(1_500)}
        edges = [
            (f"node-{index:04d}", f"node-{index + 1:04d}")
            for index in range(1_499)
        ]

        contract_order, proof_batches = probes._topological_orders(
            nodes, edges, ["node-0000"]
        )

        self.assertEqual(len(contract_order), 1_500)
        self.assertEqual(contract_order[:2], ["node-0000", "node-0001"])
        self.assertEqual(proof_batches[0], ["node-1499"])
        self.assertEqual(proof_batches[-1], ["node-0000"])

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

    def test_probe_tool_versions_require_an_exact_supported_profile(self):
        rust = copy.deepcopy(self.rust)
        aeneas = copy.deepcopy(self.aeneas)
        rust["tool"]["version"] = "0.11.0"
        aeneas["tool"]["version"] = "0.20.0"

        graph = self.parse(rust=rust, aeneas=aeneas)
        self.assertEqual(
            graph["target_report"]["tools"],
            {
                "probe_rust": {
                    "name": "probe-rust",
                    "version": "0.11.0",
                    "command": "extract",
                },
                "probe_aeneas": {
                    "name": "probe-aeneas",
                    "version": "0.20.0",
                    "command": "extract",
                },
            },
        )

        for name, rust_version, aeneas_version in (
            ("old rust with new aeneas", "0.10.0", "0.20.0"),
            ("new rust with old aeneas", "0.11.0", "0.19.0"),
        ):
            mixed_rust = copy.deepcopy(self.rust)
            mixed_aeneas = copy.deepcopy(self.aeneas)
            mixed_rust["tool"]["version"] = rust_version
            mixed_aeneas["tool"]["version"] = aeneas_version
            with self.subTest(name=name), self.assertRaisesRegex(
                probes.ProbeError, "probe_tool_profile_mismatch"
            ):
                self.parse(rust=mixed_rust, aeneas=mixed_aeneas)

        unknown_aeneas = copy.deepcopy(self.aeneas)
        unknown_aeneas["tool"]["version"] = "0.21.0"
        with self.assertRaisesRegex(probes.ProbeError, "probe_aeneas_tool_mismatch"):
            self.parse(aeneas=unknown_aeneas)

    def test_preparation_profile_is_source_only_and_matches_parser(self):
        lock = json.loads(
            (ROOT / "docker/autofv/toolchain-lock.json").read_text(encoding="utf-8")
        )
        sources = lock["preparation_probe_sources"]
        profile = sources["wire_profile"]

        self.assertEqual(sources["artifact_kind"], "source-identities-only")
        self.assertIs(sources["binaries_in_existing_image"], False)
        self.assertIn(
            (profile["probe-rust"], profile["probe-aeneas"]),
            probes.PROBE_TOOL_VERSION_PROFILES,
        )
        self.assertEqual(
            set(sources["sources"]),
            {"probe-aeneas", "probe-rust", "probe-lean"},
        )

    def test_zero_dependency_atoms_may_omit_empty_location_arrays(self):
        atom = copy.deepcopy(
            self.rust["data"]["probe:autofv-diamond/0.1.0/left()"]
        )
        atom["dependencies"] = []
        del atom["dependencies-with-locations"]

        selected = probes._project_rust_atom(
            "probe:autofv-diamond/0.1.0/left()", atom
        )
        self.assertIs(selected, atom)

        atom["dependencies"] = ["probe:missing/dependency()"]
        with self.assertRaisesRegex(
            probes.ProbeError, "project_rust_fields_missing"
        ):
            probes._project_rust_atom(
                "probe:autofv-diamond/0.1.0/left()", atom
            )

    def test_graph_tops_are_bounded_to_the_aeneas_translation_graph(self):
        rust = copy.deepcopy(self.rust)
        aeneas = copy.deepcopy(self.aeneas)
        consumer = "probe:autofv-diamond/0.1.0/rust_only_consumer()"
        rust_consumer = copy.deepcopy(rust["data"][TARGET_RUST])
        rust_consumer.update(
            {
                "dependencies": [TARGET_RUST],
                "dependencies-with-locations": [
                    {"code-name": TARGET_RUST, "line": 12, "location": "inner"}
                ],
                "display-name": "rust_only_consumer",
                "rust-qualified-name": "autofv_diamond::rust_only_consumer",
            }
        )
        rust["data"][consumer] = rust_consumer
        merged_consumer = copy.deepcopy(aeneas["data"][TARGET_RUST])
        merged_consumer.update(rust_consumer)
        for key in ("translation-name", "translation-path", "translation-text"):
            merged_consumer.pop(key, None)
        aeneas["data"][consumer] = merged_consumer

        report = json.loads(probes.render_target_report(self.parse(rust=rust, aeneas=aeneas)))

        self.assertEqual(report["graph_tops"], [TOP])

    def test_graph_top_without_a_primary_spec_is_reported_not_prepared(self):
        rust = copy.deepcopy(self.rust)
        aeneas = copy.deepcopy(self.aeneas)
        unspecced_rust = "probe:autofv-diamond/0.1.0/unspecced()"
        unspecced_lean = "probe:Diamond.unspecced"
        rust_atom = copy.deepcopy(rust["data"][TARGET_RUST])
        rust_atom.update(
            {
                "dependencies": [],
                "dependencies-with-locations": [],
                "display-name": "unspecced",
                "rust-qualified-name": "autofv_diamond::unspecced",
            }
        )
        rust["data"][unspecced_rust] = rust_atom
        merged_rust = copy.deepcopy(aeneas["data"][TARGET_RUST])
        merged_rust.update(rust_atom)
        merged_rust["translation-name"] = unspecced_lean
        aeneas["data"][unspecced_rust] = merged_rust
        lean_atom = copy.deepcopy(aeneas["data"][TOP])
        lean_atom.update(
            {
                "dependencies": [],
                "display-name": "unspecced",
                "term-dependencies": [],
                "type-dependencies": [],
            }
        )
        lean_atom.pop("primary-spec", None)
        lean_atom.pop("specs", None)
        aeneas["data"][unspecced_lean] = lean_atom

        report = json.loads(
            probes.render_target_report(self.parse(rust=rust, aeneas=aeneas))
        )

        self.assertEqual(report["graph_tops"], [TOP])
        self.assertEqual(
            report["diagnostics"],
            [
                {
                    "kind": "graph_top_primary_spec_missing",
                    "declaration": unspecced_lean,
                }
            ],
        )

    def lean_def(self, aeneas, name, dependencies, *, rust_source="src/lib.rs",
                 artifact=False, kind="def", spec=None, hidden=False):
        """Add an Aeneas-shaped Lean def, and its primary spec when named."""
        atom = copy.deepcopy(aeneas["data"][LEFT])
        atom.update(
            {
                "display-name": name.rsplit(".", 1)[-1],
                "dependencies": dependencies,
                "term-dependencies": dependencies,
                "rust-source": rust_source,
                "is-extraction-artifact": artifact,
                "is-hidden": hidden,
                "kind": kind,
            }
        )
        if spec is not None:
            atom.update({"primary-spec": spec, "specs": [spec]})
            theorem = copy.deepcopy(aeneas["data"][TOP_SPEC])
            theorem.update(
                {
                    "display-name": spec.rsplit(".", 1)[-1],
                    "dependencies": [name],
                    "term-dependencies": [name],
                    "type-dependencies": [name],
                    "is-hidden": hidden,
                }
            )
            aeneas["data"][spec] = theorem
        aeneas["data"][name] = atom

    def test_lean_def_without_a_rust_link_is_the_top_over_its_callee(self):
        # AffinePoint's `Default::default` calls `identity`, but probe-aeneas
        # links no Rust function to the Lean `default` and hides it.
        aeneas = copy.deepcopy(self.aeneas)
        default = "probe:Diamond.Point.Insts.CoreDefaultDefault.default"
        record = "probe:Diamond.Point.Insts.CoreDefaultDefault"
        self.lean_def(aeneas, default, [TOP], spec=f"{default}_spec", hidden=True)
        self.lean_def(aeneas, record, [default], artifact=True)

        report = json.loads(probes.render_target_report(self.parse(aeneas=aeneas)))

        self.assertEqual(report["graph_tops"], [default])
        self.assertEqual(
            report["declarations"][default],
            {
                "rust_function": None,
                "public_api": None,
                "primary_spec": f"{default}_spec",
                "directed_closure": [default, LEFT, RIGHT, TOP],
                "source": {"path": "Diamond/Left.lean", "lines": [3, 4]},
            },
        )

    def test_operator_forwarder_is_the_top_not_the_method_it_forwards(self):
        aeneas = copy.deepcopy(self.aeneas)
        forwarder = "probe:Diamond.SharedAPoint.Insts.CoreOpsArithAddPoint.add"
        self.lean_def(aeneas, forwarder, [TOP], rust_source="src/macros.rs",
                      spec=f"{forwarder}_spec", hidden=True)
        self.lean_def(aeneas, "probe:Diamond.SharedAPoint.Insts.CoreOpsArithAddPoint",
                      [forwarder], artifact=True)

        report = json.loads(probes.render_target_report(self.parse(aeneas=aeneas)))
        self.assertEqual(report["graph_tops"], [forwarder])

        # The hidden forwarder is a target, but a hidden callee is never a job.
        aeneas["data"][TOP]["is-hidden"] = True
        report = json.loads(probes.render_target_report(self.parse(aeneas=aeneas)))
        self.assertEqual(report["declarations"][forwarder]["directed_closure"], [forwarder])

    def test_trait_records_and_loop_bodies_are_transparent(self):
        aeneas = copy.deepcopy(self.aeneas)
        method = "probe:Diamond.Point.Insts.CoreOpsArithMul.mul"
        record = "probe:Diamond.Point.Insts.CoreOpsArithMul"
        user = "probe:Diamond.sum"
        loop = "probe:Diamond.sum_loop"
        helper = "probe:Diamond.step"
        self.lean_def(aeneas, method, [], spec=f"{method}_spec")
        self.lean_def(aeneas, record, [method], artifact=True)
        self.lean_def(aeneas, helper, [])
        self.lean_def(aeneas, loop, [loop, helper, f"{loop}.mutual"], artifact=True)
        self.lean_def(aeneas, user, [record, loop], spec=f"{user}_spec")

        report = json.loads(probes.render_target_report(self.parse(aeneas=aeneas)))

        # Using the record calls its methods; the loop's calls are its parent's.
        self.assertEqual(report["graph_tops"], [user, TOP])
        self.assertEqual(report["diagnostics"], [])

    def test_foreign_impls_and_theorems_do_not_hide_a_top(self):
        aeneas = copy.deepcopy(self.aeneas)
        self.lean_def(aeneas, "probe:Diamond.Bool.Insts.CoreCloneClone.clone", [TOP],
                      rust_source="/rustc/library/core/src/clone.rs")
        self.lean_def(aeneas, "probe:Diamond.top_lemma", [TOP], kind="theorem")

        report = json.loads(probes.render_target_report(self.parse(aeneas=aeneas)))

        self.assertEqual(report["graph_tops"], [TOP])

    def test_manifest_target_may_name_the_lean_declaration(self):
        manifest = {**self.manifest, "targets": [{"function": TOP, "spec": "Diamond.top_spec"}]}

        graph = probes.parse_probe_bytes(manifest, self.rust_raw, self.aeneas_raw)

        self.assertEqual(graph["frozen_targets"], [TOP])
        self.assertEqual(graph["graph_sha256"], self.parse()["graph_sha256"])

    def test_generated_and_nonscheduled_dependencies_do_not_create_jobs(self):
        aeneas = copy.deepcopy(self.aeneas)
        generated = f"{LEFT}.mutual"
        trusted = "probe:Diamond.trusted"
        aeneas["data"][TOP]["dependencies"] += [generated, trusted]
        aeneas["data"][TOP]["term-dependencies"] += [generated, trusted]
        trusted_atom = copy.deepcopy(aeneas["data"][LEFT])
        trusted_atom.update(
            {
                "display-name": "trusted",
                "verification-status": "trusted",
            }
        )
        aeneas["data"][trusted] = trusted_atom

        graph = self.parse(aeneas=aeneas)

        self.assertEqual(graph["selected_nodes"], [LEFT, RIGHT, TOP])
        self.assertNotIn([TOP, trusted], graph["term_dependencies"])

    def test_unowned_generated_looking_dependency_fails_closed(self):
        aeneas = copy.deepcopy(self.aeneas)
        dependency = "probe:Missing.owner.mutual"
        aeneas["data"][TOP]["dependencies"].append(dependency)
        aeneas["data"][TOP]["term-dependencies"].append(dependency)

        with self.assertRaisesRegex(
            probes.ProbeError, "selected_term_dependency_missing"
        ):
            self.parse(aeneas=aeneas)

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
                mock.patch.object(worker, "force_destroy_worker") as cleanup,
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
            cleanup.assert_called_once()
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
