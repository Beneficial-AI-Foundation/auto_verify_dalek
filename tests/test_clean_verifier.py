import copy
import hashlib
import io
import json
import subprocess
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import (
    axiom_audit,
    experiment,
    generic_role_runtime,
    probes,
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


def _invocation(bundle, state=None):
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
                state, json.loads(REFERENCE.read_text())
            )
        ),
        "toolchain_lock_sha256": _sha256(_canonical(lock)),
        "accepted_commit": "2" * 40,
        "accepted_tree_sha256": "3" * 64,
        "bundle_sha256": _sha256(bundle),
        "reference_sha256": _sha256(REFERENCE.read_bytes()),
    }


def _observed(state=None):
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
            state, json.loads(REFERENCE.read_text())
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
        "retained_declarations": graph["selected_nodes"],
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
