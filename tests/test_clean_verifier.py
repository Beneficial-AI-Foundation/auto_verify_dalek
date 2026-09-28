import copy
from contextlib import nullcontext
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import (
    axiom_audit,
    experiment,
    generic_role_runtime,
    probes,
    terminal_run,
    verifier,
    verifier_bundle,
    worker,
)


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "fixtures" / "diamond"
RUST_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-rust.json"
AENEAS_PROBE = ROOT / "tests" / "fixtures" / "probes" / "diamond-aeneas.json"
REFERENCE = ROOT / "tests" / "fixtures" / "diamond-reference" / "reference.json"


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _assumptions():
    return [
        {
            "assumption": "Lean.ofReduceBool",
            "evidence": "Pinned Lean compiler source and binary identity",
            "evidence_sha256": "5" * 64,
        },
        {
            "assumption": "Lean.trustCompiler",
            "evidence": "Pinned native compiler toolchain identity",
            "evidence_sha256": "6" * 64,
        },
    ]


def _state():
    manifest = json.loads((TARGET / "autofv.json").read_text())
    rust = RUST_PROBE.read_bytes()
    aeneas = AENEAS_PROBE.read_bytes()
    graph = probes.parse_probe_bytes(manifest, rust, aeneas)
    lock = experiment.load_toolchain_lock()
    return {
        "schema": "autofv-verifier-state/v1",
        "base_commit": "1" * 40,
        "graph": graph,
        "accepted_nodes": graph["selected_nodes"],
        "frozen_contracts": {
            "Diamond.left_spec": {
                "canon": (
                    "theorem Diamond.left_spec (n : Nat) : "
                    "Diamond.left n = Nat.succ n"
                ),
                "model_fingerprint": (
                    "a7ebd0571ce241a681ae7f4c668089af616f4e9cc1db52a62ba4744da4ea0e72"
                ),
                "native_decide_policy_sha256": lock[
                    "native_decide_policy_sha256"
                ],
                "status": "frozen",
            },
            "Diamond.right_spec": {
                "canon": (
                    "theorem Diamond.right_spec (n : Nat) : "
                    "Diamond.right n = n * (Nat.succ 1)"
                ),
                "model_fingerprint": (
                    "7c96c88e75d4d9d308b7b97a286515afc64a8ae0f67e0e09666d94064454a2a5"
                ),
                "native_decide_policy_sha256": lock[
                    "native_decide_policy_sha256"
                ],
                "status": "frozen",
            },
        },
        "native_decide_uses": [],
        "compiler_assumptions": _assumptions(),
    }


def _members(state=None):
    return {
        "accepted/repository.bundle": b"fixture repository bundle",
        "evidence/probe-aeneas.json": AENEAS_PROBE.read_bytes(),
        "evidence/probe-rust.json": RUST_PROBE.read_bytes(),
        "input/autofv.json": _canonical(
            json.loads((TARGET / "autofv.json").read_text())
        ),
        "state/verification.json": _canonical(state or _state()),
    }


def _invocation(bundle, state=None, *, audit_reference=None):
    state = state or _state()
    graph = state["graph"]
    lock = experiment.load_toolchain_lock()
    return {
        "schema": "autofv-verifier-invocation/v1",
        "run_id": "run-001",
        "invocation_id": "verify-001",
        "agent_worker_id": "lima:autofv-agent-run:agent-machine",
        "verifier_worker_id": "lima:autofv-verifier:verifier-machine",
        "snapshot_sha256": "0" * 64,
        "manifest_sha256": _sha256(_members(state)["input/autofv.json"]),
        "probe_rust_sha256": graph["probe_rust_sha256"],
        "probe_aeneas_sha256": graph["probe_aeneas_sha256"],
        "graph_sha256": graph["graph_sha256"],
        "image_digest": lock["image"]["image_digest"],
        "control_bundle_sha256": worker.control_manifest(lock)[0][
            "bundle_sha256"
        ],
        "native_decide_policy_sha256": lock["native_decide_policy_sha256"],
        "axiom_scope_sha256": axiom_audit.inventory_scope_sha256(
            axiom_audit.expected_inventory(
                state, audit_reference if audit_reference is not None else json.loads(REFERENCE.read_text())
            )
        ),
        "toolchain_lock_sha256": _sha256(_canonical(lock)),
        "accepted_commit": "2" * 40,
        "accepted_tree_sha256": "3" * 64,
        "bundle_sha256": _sha256(bundle),
        "reference_sha256": _sha256(REFERENCE.read_bytes()),
    }


def _observed(state=None, *, audit_reference=None):
    state = state or _state()
    graph = state["graph"]
    return {
        "verifier_worker_id": "lima:autofv-verifier:verifier-machine",
        "runtime_identity": True,
        "snapshot_sha256": "0" * 64,
        "accepted_commit": "2" * 40,
        "accepted_tree_sha256": "3" * 64,
        "image_digest": experiment.load_toolchain_lock()["image"]["image_digest"],
        "fresh_cache": True,
        "clean_build": True,
        "accepted_nodes": graph["selected_nodes"],
        "status_by_node": {name: "accepted" for name in graph["selected_nodes"]},
        "statement_fingerprints": {
            name: item["model_fingerprint"]
            for name, item in state["frozen_contracts"].items()
        },
        "changed_paths": sorted(
            {
                graph["source_paths"][name]
                for name in graph["selected_nodes"]
            }
        ),
        "holes": [],
        "trust_passed": True,
        "native_decide_policy_sha256": experiment.load_toolchain_lock()[
            "native_decide_policy_sha256"
        ],
        "native_decide_uses": state["native_decide_uses"],
        "accepted_native_decide_uses": state["native_decide_uses"],
        "hidden_native_decide_uses": [],
        "compiler_assumptions": state["compiler_assumptions"],
        "axiom_inventory": axiom_audit.expected_inventory(
            state, audit_reference if audit_reference is not None else json.loads(REFERENCE.read_text())
        ),
        "meaning": {
            "reference_integrity": True,
            "statement_equivalence": True,
            "non_vacuity": True,
            "broken_implementation_rejected": True,
        },
        "sorry_count_before": 1,
        "sorry_count_after": 0,
    }


def _preparation_manifest(state=None):
    state = state or _state()
    graph = state["graph"]
    files = []
    body = {
        "schema": "preparation-manifest/v1",
        "mode": "small",
        "source": {
            "repository": "https://example.invalid/dalek.git",
            "revision": "7" * 40,
            "tree_sha256": "8" * 64,
        },
        "probes": {
            name: {
                "repository": f"https://example.invalid/{name}.git",
                "revision": revision * 40,
                "tree_sha256": revision * 64,
                "version": version,
            }
            for name, revision, version in (
                ("probe-aeneas", "9", "0.19.0"),
                ("probe-rust", "a", "0.10.0"),
                ("probe-lean", "b", "0.15.0"),
            )
        },
        "target_report_sha256": "b" * 64,
        "probe_identities_sha256": "c" * 64,
        "roots": graph["frozen_targets"],
        "closures": {
            root: graph["selected_nodes"] for root in graph["frozen_targets"]
        },
        "retained_declarations": sorted(
            set(graph["selected_nodes"]) | set(graph["supplied_specs"].values())
        ),
        "files": files,
        "tree_sha256": _sha256(_canonical(files)),
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
    return {**body, "manifest_sha256": _sha256(_canonical(body))}


def _terminal_state(*, incomplete=False):
    state = _state()
    state["target_states"] = {
        node: {
            "status": (
                "blocked"
                if incomplete and node == state["graph"]["frozen_targets"][0]
                else "accepted"
            ),
            "statement_sha256": _sha256(node.encode()),
        }
        for node in state["graph"]["selected_nodes"]
    }
    if incomplete:
        state["accepted_nodes"] = state["accepted_nodes"][:-1]
    return state


def _raw_tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, raw in entries:
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


def _tar_entries(raw):
    entries = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
        for member in archive.getmembers():
            extracted = archive.extractfile(member) if member.isfile() else None
            entries.append((copy.copy(member), extracted.read() if extracted else b""))
    return entries


class PartialDeclarationTests(unittest.TestCase):
    def test_empty_reference_program_is_only_allowed_for_scoped_replay(self):
        with self.assertRaisesRegex(Exception, "verifier_reference_leaves_invalid"):
            axiom_audit.reference_program({"leaves": []})
        source = axiom_audit.reference_program({"leaves": []}, allow_empty=True)
        self.assertIn(b"namespace AutoFVVerifier", source)
        self.assertNotIn(b"hidden_", source)

    def test_partial_audit_imports_candidate_modules_without_hidden_reference(self):
        reference = axiom_audit.reference_program({"leaves": []}, allow_empty=True)
        self.assertNotIn(b"import Diamond.Top", reference)
        source = axiom_audit.audit_program(
            [{"declaration": "Diamond.helper_spec", "dependencies": []}],
            project_modules=["Diamond.Top"],
        )
        self.assertIn(
            b"def autofvAuditCandidateFiles : List (Name \xc3\x97 System.FilePath) := "
            b"[(`Diamond.Top, \".lake/build/lib/lean/Diamond/Top.olean\"), "
            b"(`AutoFVReferenceCheck, \".lake/build/lib/lean/AutoFVReferenceCheck.olean\")]",
            source,
        )

    def _case(self):
        state = _state()
        state["compiler_assumptions"] = verifier.compiler_assumptions(experiment.load_toolchain_lock())
        helper = state["graph"]["selected_nodes"][0]
        self.assertNotEqual(helper, state["graph"]["frozen_targets"][0])
        state["accepted_nodes"] = [helper]
        state["frozen_contracts"] = {
            name: record for name, record in state["frozen_contracts"].items()
            if f"probe:{name.removesuffix('_spec')}" == helper
        }
        state["partial_target"] = helper
        audit_reference = {"leaves": []}
        observed = _observed(state, audit_reference=audit_reference)
        observed["status_by_node"] = {
            node: "unknown" for node in state["graph"]["selected_nodes"]
        }
        observed["changed_paths"] = [state["graph"]["source_paths"][helper]]
        observed["holes"] = ["Diamond/Top.lean:99"]
        observed["sorry_count_before"] = 2
        observed["sorry_count_after"] = 1
        observed["meaning"] = {}
        return state, helper, audit_reference, observed

    def _verify(self, state, helper, audit_reference, observed):
        bundle = verifier_bundle.build_bundle(_members(state))
        invocation = _invocation(bundle, state, audit_reference=audit_reference)
        return verifier_bundle.verify_bundle(
            bundle, invocation, reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda _members, _state, _reference: observed,
            partial_target=helper,
        )

    def test_helper_can_pass_without_claiming_unverified_root(self):
        state, helper, audit_reference, observed = self._case()
        report = self._verify(state, helper, audit_reference, observed)
        self.assertEqual(report["verdict"], "SCOPED_PASS")
        self.assertEqual(report["evidence_level"], "P1")
        self.assertEqual(report["partial_target"], helper)
        self.assertEqual(report["root_status"], "unverified")
        self.assertFalse(report["checks"]["meaning"])
        self.assertNotEqual(report["verdict"], "PASS")

    def test_partial_receipt_validation_binds_worker_commit_statement_and_root(self):
        state, helper, audit_reference, observed = self._case()
        report = self._verify(state, helper, audit_reference, observed)
        bundle = verifier_bundle.build_bundle(_members(state))
        invocation = _invocation(bundle, state, audit_reference=audit_reference)
        run = {"run_id": invocation["run_id"], "agent_worker_id": invocation["agent_worker_id"]}
        self.assertIs(
            verifier.validate_partial_report(report, run, invocation, helper, state), report
        )
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(report, run, invocation)
        for field, value in (
            ("verifier_worker_id", run["agent_worker_id"]),
            ("accepted_commit", "f" * 40),
            ("partial_target", state["graph"]["frozen_targets"][0]),
            ("root_status", "accepted"),
            ("evidence_level", "L4"),
        ):
            with self.subTest(field=field), self.assertRaises(verifier.VerifierError):
                forged = {**report, field: value}
                forged["report_sha256"] = _sha256(_canonical({
                    key: item for key, item in forged.items() if key != "report_sha256"
                }))
                verifier.validate_partial_report(forged, run, invocation, helper, state)

    def test_forged_helper_closure_and_commit_never_pass(self):
        state, helper, audit_reference, observed = self._case()
        cases = []
        drift = copy.deepcopy(observed)
        drift["accepted_commit"] = "f" * 40
        cases.append(("accepted_commit_mismatch", state, helper, drift))
        drift = copy.deepcopy(observed)
        drift["statement_fingerprints"] = {}
        cases.append(("statement_mismatch", state, helper, drift))
        drift = copy.deepcopy(observed)
        drift["axiom_inventory"][0]["axioms"] = ["sorryAx"]
        cases.append(("axiom_inventory_invalid", state, helper, drift))
        drift = copy.deepcopy(observed)
        drift["changed_paths"].append(state["graph"]["source_paths"][state["graph"]["frozen_targets"][0]])
        cases.append(("scope_mismatch", state, helper, drift))
        drift = copy.deepcopy(observed)
        drift["trust_passed"] = False
        cases.append(("trust_failed", state, helper, drift))
        for failure, case_state, target, case_observed in cases:
            with self.subTest(failure=failure):
                report = self._verify(case_state, target, audit_reference, case_observed)
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(failure, report["failures"])

    def test_controller_retains_exact_first_helper_receipt_without_root_upgrade(self):
        verification, helper, audit_reference, observed = self._case()
        bundle = verifier_bundle.build_bundle(_members(verification))
        invocation = _invocation(bundle, verification, audit_reference=audit_reference)
        run = {
            "run_id": invocation["run_id"], "agent_worker_id": invocation["agent_worker_id"],
            "base_commit": verification["base_commit"],
            "snapshot_sha256": invocation["snapshot_sha256"],
            "manifest_sha256": invocation["manifest_sha256"],
            "image_digest": invocation["image_digest"],
            "control_bundle_sha256": invocation["control_bundle_sha256"],
            "native_decide_policy_sha256": invocation["native_decide_policy_sha256"],
            "lock": experiment.load_toolchain_lock(),
            "preparation_manifest": {"schema": "preparation-manifest/v1"},
        }
        accepted = {
            "accepted_commit": invocation["accepted_commit"],
            "accepted_tree_sha256": invocation["accepted_tree_sha256"],
        }
        state = {
            "run": run, "graph": verification["graph"], "accepted": accepted,
            "contracts": {"frozen": verification["frozen_contracts"]},
            "accepted_nodes": verification["accepted_nodes"],
            "target_states": {
                node: {"status": "accepted" if node == helper else "pending"}
                for node in verification["graph"]["selected_nodes"]
            },
            "native_decide_uses": [],
        }
        checkpoints = []
        def clean(_run, expected, *, verification_state):
            self.assertEqual(verification_state["partial_target"], helper)
            self.assertNotIn("target_states", verification_state)
            self.assertEqual(expected["accepted_commit"], accepted["accepted_commit"])
            return verifier_bundle.verify_bundle(
                bundle, {**invocation, "invocation_id": expected["invocation_id"]},
                reference_bytes=REFERENCE.read_bytes(),
                run_checks=lambda *_args: observed, partial_target=helper,
            )
        with (
            mock.patch.object(verifier, "_trusted_reference", return_value=REFERENCE.read_bytes()),
            mock.patch.object(verifier, "verify_run", side_effect=clean) as verified,
        ):
            receipt = terminal_run.clean_verify_partial(
                state, helper, checkpoint=lambda _state, name: checkpoints.append(name),
                charge_wall=lambda _state: None,
            )
            self.assertEqual(receipt["verdict"], "SCOPED_PASS")
            self.assertEqual(state["target_states"][helper]["status"], "accepted")
            self.assertEqual(state["target_states"][verification["graph"]["frozen_targets"][0]]["status"], "pending")
            self.assertIs(
                terminal_run.clean_verify_partial(
                    state, helper, checkpoint=lambda _state, name: checkpoints.append(name),
                    charge_wall=lambda _state: None,
                ), receipt,
            )
            verified.assert_called_once()
        self.assertIn("partial_verifier:before", checkpoints)
        self.assertIn("partial_verifier:after", checkpoints)
        state["accepted"] = {**accepted, "accepted_commit": "f" * 40}
        with (
            mock.patch.object(verifier, "_trusted_reference", return_value=REFERENCE.read_bytes()),
            mock.patch.object(verifier, "verify_run", side_effect=RuntimeError("fresh commit requires recheck")) as fresh,
        ):
            with self.assertRaisesRegex(RuntimeError, "fresh commit requires recheck"):
                terminal_run.clean_verify_partial(
                    state, helper, checkpoint=lambda _state, name: checkpoints.append(name),
                    charge_wall=lambda _state: None,
                )
            fresh.assert_called_once()

    def test_unresolved_partial_invocation_does_not_repeat_verifier(self):
        state, helper, _, _ = self._case()
        run = {
            "preparation_manifest": {}, "base_commit": state["base_commit"],
            "lock": experiment.load_toolchain_lock(),
        }
        controller = {
            "run": run, "graph": state["graph"],
            "accepted": {"accepted_commit": "2" * 40},
            "accepted_nodes": state["accepted_nodes"],
            "partial_verifier_inflight": {
                "node": helper, "accepted_commit": "2" * 40,
                "invocation_id": "partial-locked",
            },
        }
        with mock.patch.object(verifier, "verify_run") as live:
            with self.assertRaisesRegex(verifier.VerifierError, "unresolved"):
                terminal_run.clean_verify_partial(
                    controller, helper, checkpoint=lambda *_: None,
                    charge_wall=lambda *_: None,
                )
            live.assert_not_called()

    def test_partial_report_cannot_mask_locally_accepted_root(self):
        state, helper, audit_reference, observed = self._case()
        state["accepted_nodes"] = sorted([helper, state["graph"]["frozen_targets"][0]])
        bundle = verifier_bundle.build_bundle(_members(state))
        invocation = _invocation(bundle, state, audit_reference=audit_reference)
        called = []
        report = verifier_bundle.verify_bundle(
            bundle, invocation, reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_args: called.append(1) or observed,
            partial_target=helper,
        )
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("accepted_nodes_mismatch", report["failures"])
        self.assertEqual(called, [])

    def test_unbound_partial_target_fails_before_clean_worker(self):
        state, helper, audit_reference, observed = self._case()
        state["partial_target"] = state["graph"]["frozen_targets"][0]
        called = []
        bundle = verifier_bundle.build_bundle(_members(state))
        invocation = _invocation(bundle, state, audit_reference=audit_reference)
        report = verifier_bundle.verify_bundle(
            bundle, invocation, reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_args: called.append(1) or observed,
            partial_target=helper,
        )
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("verifier_state_mismatch", report["failures"])
        self.assertEqual(called, [])


class BundleIntakeTests(unittest.TestCase):
    def setUp(self):
        self.bundle = verifier.build_bundle(_members())

    def _verify(self, bundle, observed=None):
        return verifier.verify_bundle(
            bundle,
            _invocation(bundle),
            reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_: copy.deepcopy(observed or _observed()),
        )

    def test_canonical_bundle_passes_and_reordered_input_is_identical(self):
        reversed_members = dict(reversed(list(_members().items())))
        self.assertEqual(self.bundle, verifier.build_bundle(reversed_members))
        report = self._verify(self.bundle)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["evidence_level"], "L4")

    def test_clean_worker_infrastructure_failure_is_not_reduced_to_a_failed_proof(self):
        with self.assertRaisesRegex(
            verifier.VerifierInfrastructureError, "verifier unavailable"
        ):
            verifier.verify_bundle(
                self.bundle,
                _invocation(self.bundle),
                reference_bytes=REFERENCE.read_bytes(),
                run_checks=mock.Mock(
                    side_effect=verifier.VerifierInfrastructureError(
                        "verifier unavailable"
                    )
                ),
            )

    def test_archive_paths_types_duplicates_members_sizes_and_hashes_fail_closed(self):
        cases = []
        entries = _tar_entries(self.bundle)
        for name in ("/absolute", "../parent", "input/../parent"):
            changed = copy.deepcopy(entries)
            changed[0][0].name = name
            cases.append(("unsafe_path", _raw_tar(changed), None))

        link = tarfile.TarInfo("input/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        cases.append(("unsafe_type", _raw_tar(entries + [(link, b"")]), None))

        device = tarfile.TarInfo("input/device")
        device.type = tarfile.CHRTYPE
        cases.append(("unsafe_type", _raw_tar(entries + [(device, b"")]), None))

        cases.append(("duplicate_member", _raw_tar(entries + [entries[1]]), None))
        extra = tarfile.TarInfo("extra.txt")
        cases.append(("member_set_mismatch", _raw_tar(entries + [(extra, b"x")]), None))

        changed = copy.deepcopy(entries)
        member_index = next(
            index for index, (info, _) in enumerate(changed)
            if info.name == "input/autofv.json"
        )
        changed[member_index] = (changed[member_index][0], b"{}")
        cases.append(("member_hash_mismatch", _raw_tar(changed), None))

        with mock.patch.object(verifier_bundle, "MAX_MEMBER_BYTES", 8):
            report = self._verify(self.bundle)
        self.assertIn("member_too_large", report["failures"])

        for reason, raw, observed in cases:
            with self.subTest(reason=reason):
                report = self._verify(raw, observed)
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(reason, report["failures"])


class CleanStateMutationTests(unittest.TestCase):
    def _verify(self, *, state=None, observed=None, reference=None):
        state = state or _state()
        bundle = verifier.build_bundle(_members(state))
        return verifier.verify_bundle(
            bundle,
            _invocation(bundle, state),
            reference_bytes=REFERENCE.read_bytes() if reference is None else reference,
            run_checks=lambda *_: copy.deepcopy(observed or _observed(state)),
        )

    def test_state_and_clean_worker_mutation_matrix(self):
        state_cases = []
        missing_target = _state()
        missing_target["accepted_nodes"] = missing_target["accepted_nodes"][1:]
        state_cases.append(("accepted_nodes_mismatch", missing_target))

        dependency = _state()
        dependency["graph"]["term_dependencies"] = []
        state_cases.append(("graph_mismatch", dependency))

        status = _state()
        status["frozen_contracts"]["Diamond.left_spec"]["status"] = "unknown"
        state_cases.append(("frozen_contract_invalid", status))

        policy = _state()
        policy["frozen_contracts"]["Diamond.left_spec"][
            "native_decide_policy_sha256"
        ] = "f" * 64
        state_cases.append(("native_decide_policy_mismatch", policy))

        for reason, state in state_cases:
            with self.subTest(reason=reason):
                report = self._verify(state=state)
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(reason, report["failures"])

        observed_cases = {
            "snapshot_mismatch": {"snapshot_sha256": "f" * 64},
            "accepted_commit_mismatch": {"accepted_commit": "f" * 40},
            "accepted_tree_mismatch": {"accepted_tree_sha256": "f" * 64},
            "verifier_worker_mismatch": {"verifier_worker_id": "wrong-worker"},
            "cache_not_fresh": {"fresh_cache": False},
            "clean_build_failed": {"clean_build": False},
            "accepted_status_mismatch": {
                "status_by_node": {name: "unknown" for name in _state()["accepted_nodes"]}
            },
            "statement_mismatch": {
                "statement_fingerprints": {"Diamond.left_spec": "f" * 64}
            },
            "holes_present": {"holes": ["Diamond/Left.lean:4"]},
            "trust_failed": {"trust_passed": False},
            "scope_mismatch": {"changed_paths": ["unrelated.txt"]},
            "native_decide_policy_mismatch": {
                "native_decide_policy_sha256": "f" * 64
            },
            "native_decide_inventory_mismatch": {
                "native_decide_uses": [{"untrusted": True}]
            },
            "compiler_assumptions_mismatch": {"compiler_assumptions": []},
            "meaning_incomplete": {
                "meaning": {
                    "reference_integrity": True,
                    "statement_equivalence": True,
                    "non_vacuity": False,
                    "broken_implementation_rejected": True,
                }
            },
        }
        for reason, mutation in observed_cases.items():
            with self.subTest(reason=reason):
                observed = _observed()
                observed.update(mutation)
                report = self._verify(observed=observed)
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(reason, report["failures"])

    def test_generic_contract_preserves_verifier_statement_fingerprint(self):
        state = _state()
        statement = state["frozen_contracts"]["Diamond.left_spec"]["canon"]
        candidate = {
            "claimed_status": "candidate",
            "evidence": ["statement:" + statement],
            "candidate_identity": "different from statement identity",
        }
        record = generic_role_runtime._contract_record(
            candidate,
            "Diamond.left_spec",
            experiment.load_toolchain_lock()["native_decide_policy_sha256"],
            [],
        )
        state["frozen_contracts"]["Diamond.left_spec"] = {
            **record,
            "status": "frozen",
        }
        bundle = verifier.build_bundle(_members(state))
        report = verifier.verify_bundle(
            bundle,
            _invocation(bundle, state),
            reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_: _observed(state),
        )

        self.assertEqual(record["model_fingerprint"], _sha256(statement.encode()))
        self.assertNotEqual(record["candidate_sha256"], record["model_fingerprint"])
        self.assertEqual(report["verdict"], "PASS", report)

    def test_hidden_reference_is_required_and_bound_after_bundle_integrity(self):
        missing = self._verify(reference=b"")
        self.assertEqual(missing["verdict"], "FAIL")
        self.assertIn("reference_hash_mismatch", missing["failures"])

        changed = self._verify(reference=REFERENCE.read_bytes() + b"\n")
        self.assertEqual(changed["verdict"], "FAIL")
        self.assertIn("reference_hash_mismatch", changed["failures"])


class ReportAuthorityTests(unittest.TestCase):
    def test_hidden_reference_imports_exact_source_modules(self):
        program = verifier._reference_program(REFERENCE.read_bytes()).decode()
        self.assertIn("import Diamond.Left\n", program)
        self.assertIn("import Diamond.Right\n", program)
        self.assertNotIn("import Diamond\n", program)
        self.assertIn("def meaning_0 : Prop :=", program)
        self.assertIn("#check (Diamond.left_spec :", program)
        self.assertNotIn("exact Diamond.left_spec", program)

    def test_only_exact_current_distinct_worker_pass_is_authoritative(self):
        bundle = verifier.build_bundle(_members())
        invocation = _invocation(bundle)
        report = verifier.verify_bundle(
            bundle,
            invocation,
            reference_bytes=REFERENCE.read_bytes(),
            run_checks=lambda *_: _observed(),
        )
        run = {
            "run_id": invocation["run_id"],
            "agent_worker_id": invocation["agent_worker_id"],
        }
        self.assertEqual(verifier.validate_report(report, run, invocation), report)

        for field, value in (
            ("invocation_id", "late-invocation"),
            ("run_id", "cross-run"),
            ("accepted_commit", "f" * 40),
        ):
            with self.subTest(field=field):
                stale = dict(invocation)
                stale[field] = value
                with self.assertRaisesRegex(verifier.VerifierError, field):
                    verifier.validate_report(report, run, stale)

        same_worker = copy.deepcopy(report)
        same_worker["verifier_worker_id"] = same_worker["agent_worker_id"]
        body = {key: value for key, value in same_worker.items() if key != "report_sha256"}
        same_worker["report_sha256"] = _sha256(_canonical(body))
        with self.assertRaisesRegex(verifier.VerifierError, "distinct"):
            verifier.validate_report(same_worker, run, invocation)

class VerifyRunWiringTests(unittest.TestCase):
    def test_prepared_verifier_refuses_oversized_vm_before_checks(self):
        with mock.patch.object(verifier.worker_runtime, "inspect_lima_instance", return_value={
            "status": "Running", "cpus": 8, "memory": 24 * 1024**3
        }):
            with self.assertRaisesRegex(verifier.VerifierInfrastructureError, "resource limit"):
                verifier._check_quiet_verifier_vm()
        with mock.patch.object(verifier.worker_runtime, "inspect_lima_instance", return_value={
            "status": "Running", "cpus": 2, "memory": 8 * 1024**3
        }):
            verifier._check_quiet_verifier_vm()

    def test_prepared_checkout_links_package_subdirectory(self):
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        with (
            mock.patch.object(verifier, "_docker", return_value=completed) as docker,
            mock.patch.object(verifier, "_seed_file"),
        ):
            verifier.axiom_audit.checkout_volume(
                image="sha256:" + "1" * 64,
                volume="audit-volume",
                repository_bundle=b"baseline",
                commit="a" * 40,
                runtime="runsc-hardened",
                docker=verifier._docker,
                runtime_argv=verifier._runtime_argv,
                seed_file=verifier._seed_file,
            )
        self.assertIn(
            "ln -s /project/dependencies/packages repo/.lake/packages",
            str(docker.call_args.args),
        )

    def test_clean_dependency_cache_replays_public_artifacts_from_base_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "dependency-cache.tar.zst"
            source.write_bytes(b"bound archive")
            completed = subprocess.CompletedProcess((), 0, b"", b"")
            with (
                mock.patch.object(verifier, "_prepared_dependency_cache", return_value=source),
                mock.patch.object(verifier.dependency_cache, "validated_archive", return_value=nullcontext(source)) as validate,
                mock.patch.object(verifier, "_docker", return_value=completed) as docker,
                mock.patch.object(verifier.subprocess, "run", return_value=completed) as streamed,
                mock.patch.object(verifier.axiom_audit, "checkout_volume") as checkout,
            ):
                verifier._seed_verifier_dependency_cache(
                    {"lock": experiment.load_toolchain_lock(), "dependency_cache_receipt": {
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "size": source.stat().st_size,
                    }},
                    "sha256:" + "1" * 64,
                    "dependency-volume",
                    b"accepted bundle",
                    "a" * 40,
                )
            validate.assert_called_once_with(source, hashlib.sha256(source.read_bytes()).hexdigest(), source.stat().st_size)
            self.assertIn("docker run --rm -i", streamed.call_args.args[0][-1])
            checkout.assert_called_once()
            self.assertEqual(checkout.call_args.kwargs["commit"], "a" * 40)
            calls = [call.args for call in docker.call_args_list]
            prep = next(args for args in calls if "lake exe cache get" in str(args))
            gate = next(args for args in calls if "--no-build" in args)
            self.assertLess(calls.index(prep), calls.index(gate))
            self.assertIn("runc", prep)
            self.assertIn("runc", gate)
            self.assertIn("lake exe cache unpack!", str(prep))
            self.assertIn("else exit 97", str(prep))
            self.assertIn("--network", prep)
            self.assertIn("none", prep)
            warm = next(args for args in calls if "LEAN_NUM_THREADS=1; lake build" in str(args))
            full_gate = next(args for args in calls if "lake build --no-build" in str(args))
            self.assertLess(calls.index(gate), calls.index(warm))
            self.assertLess(calls.index(warm), calls.index(full_gate))
            self.assertIn("runc", warm)
            self.assertIn("6g", warm)
            self.assertIn("runc", full_gate)
            self.assertIn("dst=/project/dependencies,volume-nocopy", str(warm))
            self.assertNotIn("dst=/project/dependencies,volume-nocopy,readonly", str(warm))
            self.assertIn("volume", calls[-1])
            self.assertIn("rm", calls[-1])

    def test_verifier_runtime_mismatch_fails_before_bundle_intake(self):
        lock = experiment.load_toolchain_lock()
        configured = {
            lock["tools"]["runsc"]["runtime_name"]: {
                "path": "/usr/bin/runsc",
                "runtimeArgs": lock["tools"]["runsc"]["runtime_args"],
            }
        }

        def docker(*argv, **_):
            output = (
                b"29.7.2\n"
                if argv[0] == "version"
                else _canonical(configured)
            )
            return subprocess.CompletedProcess(argv, 0, output, b"")

        runsc = subprocess.CompletedProcess(
            ("runsc", "--version"),
            0,
            b"runsc version release-20260817.0\nspec: 1.2.1\n",
            b"",
        )
        with (
            mock.patch.object(verifier, "_docker", side_effect=docker),
            mock.patch.object(verifier, "_shell", return_value=runsc),
        ):
            verifier._check_verifier_runtime(lock)

        configured[lock["tools"]["runsc"]["runtime_name"]]["runtimeArgs"] = [
            "--network=host"
        ]
        with (
            mock.patch.object(verifier, "_docker", side_effect=docker),
            mock.patch.object(verifier, "_shell", return_value=runsc),
            self.assertRaisesRegex(
                verifier.VerifierInfrastructureError, "runtime identity mismatch"
            ),
        ):
            verifier._check_verifier_runtime(lock)

    def test_prepared_partial_routes_to_distinct_worker_without_root_claim(self):
        state = _state()
        helper = state["graph"]["selected_nodes"][0]
        state["accepted_nodes"] = [helper]
        state["frozen_contracts"] = {
            name: record for name, record in state["frozen_contracts"].items()
            if f"probe:{name.removesuffix('_spec')}" == helper
        }
        state["partial_target"] = helper
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state, audit_reference={"leaves": []})
        run = {
            "run_id": invocation["run_id"],
            "agent_worker_id": invocation["agent_worker_id"],
            "image_digest": invocation["image_digest"],
            "manifest": json.loads((TARGET / "autofv.json").read_text()),
            "lock": experiment.load_toolchain_lock(),
            "accepted": {"accepted_commit": invocation["accepted_commit"]},
            "verification_state": state,
            "preparation_manifest": {"schema": "preparation-manifest/v1"},
        }
        expected = {
            key: invocation[key] for key in verifier_bundle.INVOCATION_FIELDS - {"schema", "run_id", "agent_worker_id", "verifier_worker_id", "bundle_sha256"}
        }
        observed = _observed(state, audit_reference={"leaves": []})
        observed.update(
            status_by_node={node: "unknown" for node in state["graph"]["selected_nodes"]},
            changed_paths=[state["graph"]["source_paths"][helper]],
            holes=["Diamond/Top.lean:99"], sorry_count_before=2,
            sorry_count_after=1, meaning={},
        )
        started = subprocess.CompletedProcess(("limactl", "start", verifier.VERIFIER_VM), 0, b"", b"")
        machine = subprocess.CompletedProcess(("cat", "/etc/machine-id"), 0, b"verifier-machine\n", b"")
        with (
            mock.patch.object(verifier.subprocess, "run", return_value=started),
            mock.patch.object(verifier, "_shell", return_value=machine),
            mock.patch.object(verifier, "_check_quiet_verifier_vm"),
            mock.patch.object(verifier, "_check_verifier_runtime"),
            mock.patch.object(verifier, "_run_bundle", return_value=bundle),
            mock.patch.object(verifier, "_trusted_reference", return_value=REFERENCE.read_bytes()),
            mock.patch.object(verifier, "_clean_worker_checks", return_value=observed) as clean,
            mock.patch.object(verifier.terminal_verifier, "verify_terminal_bundle") as full,
        ):
            report = verifier.verify_run(run, expected)
        self.assertEqual(report["verdict"], "SCOPED_PASS")
        self.assertEqual(report["partial_target"], helper)
        self.assertEqual(report["root_status"], "unverified")
        self.assertEqual(clean.call_args.args[-1], _canonical({"leaves": []}))
        full.assert_not_called()

    def test_verify_run_binds_bundle_reference_worker_and_invocation(self):
        state = _state()
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state)
        run = {
            "run_id": invocation["run_id"],
            "agent_worker_id": invocation["agent_worker_id"],
            "image_digest": invocation["image_digest"],
            "manifest": json.loads((TARGET / "autofv.json").read_text()),
            "lock": experiment.load_toolchain_lock(),
            "accepted": {"accepted_commit": invocation["accepted_commit"]},
            "verification_state": state,
        }
        expected = {
            key: invocation[key]
            for key in (
                "invocation_id",
                "snapshot_sha256",
                "manifest_sha256",
                "probe_rust_sha256",
                "probe_aeneas_sha256",
                "graph_sha256",
                "image_digest",
                "control_bundle_sha256",
                "native_decide_policy_sha256",
                "axiom_scope_sha256",
                "toolchain_lock_sha256",
                "accepted_commit",
                "accepted_tree_sha256",
                "reference_sha256",
            )
        }
        started = subprocess.CompletedProcess(
            args=("limactl", "start", verifier.VERIFIER_VM),
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        machine = subprocess.CompletedProcess(
            args=("cat", "/etc/machine-id"),
            returncode=0,
            stdout=b"verifier-machine\n",
            stderr=b"",
        )
        with (
            mock.patch.object(verifier.subprocess, "run", return_value=started),
            mock.patch.object(verifier, "_shell", return_value=machine),
            mock.patch.object(verifier, "_check_verifier_runtime") as runtime,
            mock.patch.object(verifier, "_run_bundle", return_value=bundle),
            mock.patch.object(
                verifier, "_clean_worker_checks", return_value=_observed(state)
            ) as clean,
        ):
            report = verifier.verify_run(run, expected)

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["invocation_id"], invocation["invocation_id"])
        self.assertEqual(
            report["verifier_worker_id"], invocation["verifier_worker_id"]
        )
        self.assertEqual(report["bundle_sha256"], _sha256(bundle))
        self.assertEqual(report["reference_sha256"], _sha256(REFERENCE.read_bytes()))
        runtime.assert_called_once_with(run["lock"])
        clean.assert_called_once()

if __name__ == "__main__":
    unittest.main()


class BoundedCommandTests(unittest.TestCase):
    """Verifier commands cannot outlive their deadline or flood host memory."""

    def test_output_is_captured_within_bounds(self):
        done = verifier._bounded_run(("sh", "-c", "cat; echo err >&2"), b"in", 10)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"in", b"err\n"))

    def test_timeout_kills_the_whole_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "survived"
            with self.assertRaisesRegex(verifier.VerifierInfrastructureError, "timed out"):
                verifier._bounded_run(
                    ("sh", "-c", f"(sleep 2; touch {marker}) & sleep 30"), None, 0.5
                )
            subprocess.run(("sleep", "2.5"))
            self.assertFalse(marker.exists())

    def test_output_flood_is_cut_off(self):
        with mock.patch.object(verifier, "MAX_COMMAND_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(verifier.VerifierInfrastructureError, "exceeded"):
                verifier._bounded_run(("sh", "-c", "yes"), None, 10)

    def test_failed_container_run_is_removed_by_name(self):
        calls = []

        def shell(*argv, **_kwargs):
            calls.append(argv)
            if "run" in argv:
                raise verifier.VerifierInfrastructureError("clean verifier command timed out")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch.object(verifier, "_shell", side_effect=shell):
            with self.assertRaisesRegex(verifier.VerifierInfrastructureError, "timed out"):
                verifier._docker("run", "--rm", "image", "true")
        name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1], ("sudo", "docker", "rm", "-f", name))
