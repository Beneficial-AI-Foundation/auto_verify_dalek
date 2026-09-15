import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import axiom_audit, experiment, verifier
from tests.test_clean_verifier import (
    REFERENCE,
    _invocation,
    _members,
    _observed,
    _state,
)
from tests import test_terminal_verifier as terminal_fixtures


class KernelAxiomAuditTests(unittest.TestCase):
    def test_counterexample_volumes_checkout_only_trusted_baseline(self):
        state, reference, certificate = (
            terminal_fixtures.CounterexampleAuthorityTests._reference_and_certificate()
        )
        obligation = verifier.counterexample.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        invocation = {
            **_invocation(verifier.build_bundle(_members(state)), state),
            "accepted_commit": certificate["accepted_commit"],
        }
        commits = []

        def runtime_argv(_image, volume, *command, **_kwargs):
            if "autofv-checkout" in command:
                commits.append((volume, command[-1]))
            return ("run", volume, *command)

        with mock.patch.object(
            verifier.counterexample, "confirm", return_value=certificate["certificate_sha256"]
        ):
            verifier.terminal_verifier.confirm_counterexample_certificate(
                {"lock": experiment.load_toolchain_lock()},
                invocation,
                certificate,
                obligation,
                _members(state),
                state,
                docker=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                    _args, 0, b"", b""
                ),
                runtime_argv=runtime_argv,
                seed_file=lambda *_args, **_kwargs: None,
            )
        self.assertEqual(len(commits), 2)
        self.assertEqual({commit for _, commit in commits}, {state["base_commit"]})
        self.assertNotIn(invocation["accepted_commit"], {commit for _, commit in commits})

    def test_counterexample_witness_cannot_mutate_pristine_auditor(self):
        module = verifier.counterexample
        state, reference, certificate = (
            terminal_fixtures.CounterexampleAuthorityTests._reference_and_certificate()
        )
        obligation = module.resolve_obligation(
            reference, certificate, state["target_states"]
        )
        events = []

        def runtime_argv(_image, volume, *command, **kwargs):
            events.append(("argv", volume, command, kwargs))
            return ("run", volume, *command)

        def seed_file(_image, volume, path, raw, **_kwargs):
            events.append(("seed", volume, path, raw))

        def docker(*argv, **_kwargs):
            if "cat" in argv and "AutoFVCounterexample.olean" in " ".join(argv):
                return subprocess.CompletedProcess(argv, 0, b"hostile-olean", b"")
            if "AutoFVCounterexampleAudit.lean" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    b"'AutoFV.counterexample' depends on axioms: [sorryAx]\n",
                    b"",
                )
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with self.assertRaises(verifier.VerifierError):
            module.confirm(
                certificate,
                obligation,
                image="fixture-image",
                volume="witness-volume",
                audit_volume="audit-volume",
                runtime="runsc-hardened",
                runtime_argv=runtime_argv,
                docker=docker,
                seed_file=seed_file,
                native_decide_policy_sha256=experiment.load_toolchain_lock()[
                    "native_decide_policy_sha256"
                ],
            )
        audit_invocations = [
            event
            for event in events
            if event[0] == "argv"
            and "AutoFVCounterexampleAudit.lean" in event[2]
        ]
        self.assertEqual(len(audit_invocations), 1)
        self.assertEqual(audit_invocations[0][1], "audit-volume")
        self.assertTrue(audit_invocations[0][3].get("read_only_volume"))
        self.assertIn(
            ("seed", "audit-volume", f"repo/{module.OLEAN_PATH}", b"hostile-olean"),
            events,
        )

    def test_clean_worker_audits_transferred_oleans_in_pristine_read_only_volume(self):
        state = _state()
        reference = json.loads(REFERENCE.read_text())
        expected = axiom_audit.expected_inventory(state, reference)
        audit_output = "\n".join(
            f"'{record['declaration']}' does not depend on any axioms"
            for record in expected
        ).encode()
        definitions = sorted(
            {
                dependency
                for record in expected
                for dependency in record["dependencies"]
            }
        )
        observed_names = sorted(
            {record["declaration"] for record in expected} | set(definitions)
        )
        closures = {
            record["declaration"]: sorted(
                {record["declaration"], *record["semantic_dependencies"]}
            )
            for record in expected
        }

        def identity_output(names, checked_names=()):
            checked_names = set(checked_names)
            return "\n".join(
                [
                    "AUTOFV_REPLAYED:" + ",".join(names),
                    "AUTOFV_KERNEL_CHECKED:"
                    + ",".join(name for name in names if name in checked_names),
                    "AUTOFV_BASELINE_BOUND:"
                    + ",".join(name for name in names if name not in checked_names),
                ]
                + [
                    line
                    for name in names
                    for line in (
                    f"AUTOFV_TYPE_BEGIN:{name}",
                    f"type:{name}",
                    f"AUTOFV_TYPE_END:{name}",
                    f"AUTOFV_VALUE_BEGIN:{name}",
                    f"value:{name}",
                    f"AUTOFV_VALUE_END:{name}",
                    f"AUTOFV_DEPS:{name}:"
                    + ",".join(closures.get(name, [name])),
                    f"AUTOFV_PROJECT_DEPS:{name}:"
                    + ",".join(
                        dependency
                        for dependency in closures.get(name, [name])
                        if dependency.startswith("Diamond.")
                    ),
                )
                ]
            ).encode()
        bundle = verifier.build_bundle(_members(state))
        invocation = _invocation(bundle, state)
        run = {
            "lock": experiment.load_toolchain_lock(),
            "manifest": {"verify": ["lake", "build"]},
        }
        events = []

        def runtime_argv(_image, volume, *command, **kwargs):
            events.append((volume, command, kwargs))
            return ("run", volume, *command)

        def docker(*argv, **_kwargs):
            stdout = b""
            command = argv[2:]
            if "rev-parse" in command:
                stdout = invocation["accepted_commit"].encode() + b"\n"
            elif "archive" in command:
                stdout = b"fixture-archive"
            elif "diff" in command:
                stdout = b"Diamond/Left.lean\n"
            elif "cat" in command:
                stdout = b"fixture-olean"
            elif axiom_audit.BASELINE_SOURCE in command:
                stdout = identity_output(definitions)
            elif axiom_audit.AUDIT_SOURCE in command:
                stdout = audit_output + b"\n" + identity_output(
                    observed_names,
                    {record["declaration"] for record in expected},
                )
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        def seed_file(_image, volume, path, raw, **kwargs):
            events.append(("seed", volume, path, kwargs))

        with (
            mock.patch.object(verifier, "_docker", side_effect=docker),
            mock.patch.object(verifier, "_runtime_argv", side_effect=runtime_argv),
            mock.patch.object(
                verifier, "_seed_file", side_effect=seed_file
            ) as seed,
            mock.patch.object(verifier, "_probe_output", return_value=b"probe"),
            mock.patch.object(verifier.probes, "parse_probe_bytes", return_value=state["graph"]),
            mock.patch.object(verifier, "_source_audit", return_value=([], True, [])),
            mock.patch.object(
                verifier,
                "_final_statuses",
                return_value={name: "accepted" for name in state["graph"]["selected_nodes"]},
            ),
            mock.patch.object(
                verifier, "_snapshot_hash", return_value=invocation["snapshot_sha256"]
            ),
            mock.patch.object(verifier.worker, "probe_bridge", return_value=b"{}"),
        ):
            observed = verifier._clean_worker_checks(
                run,
                invocation,
                _members(state),
                state,
                REFERENCE.read_bytes(),
            )

        self.assertEqual(observed["axiom_inventory"], expected)
        audit_calls = [
            event for event in events if axiom_audit.AUDIT_SOURCE in event[1]
        ]
        self.assertEqual(len(audit_calls), 1)
        self.assertIn("audit", audit_calls[0][0])
        self.assertTrue(audit_calls[0][2]["read_only_volume"])
        transferred = [
            call
            for call in seed.call_args_list
            if call.args[2].endswith(".olean")
        ]
        self.assertTrue(transferred)
        self.assertTrue(all("audit" in call.args[1] for call in transferred))
        audit_seed = next(
            index
            for index, event in enumerate(events)
            if event[0] == "seed" and event[2] == f"repo/{axiom_audit.AUDIT_SOURCE}"
        )
        witness_build = next(
            index
            for index, event in enumerate(events)
            if event[0] != "seed"
            and "audit" not in event[0]
            and event[1] == ("lake", "build")
        )
        self.assertLess(audit_seed, witness_build)


if __name__ == "__main__":
    unittest.main()
