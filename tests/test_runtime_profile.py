"""Synthetic profile/identity checks. No runtime, authentication, or model requests."""
from __future__ import annotations

import copy
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from autofv import agent_lane, contracts, fvs_adapter, fvs_packet, fvs_profile, runtime_profile, worker


def packet() -> dict:
    body = {
        "schema": "autofv-fvs-source-packet/v1",
        "source_identity": {"repository": "https://example.invalid/public", "revision": "a" * 40,
                            "tree_sha256": "b" * 64},
        "sources": [fvs_packet.source(path, surface, content) for path, surface, content in (
            ("Example.lean", "lean", "def f (n : Nat) := n\n"),
            ("rust/example.rs", "rust", "pub fn f(n: u64) -> u64 { n }\n"),
            ("Types.lean", "types", "def Word := Nat\n"),
            ("Meaning.lean", "interpretation", "def interpret (n : Nat) := n\n"),
            ("Intent.md", "intent", "Return the unchanged input.\n"),
        )],
        "style": {"path": "FVS fallback", "content": "100 columns, two namespace dots.",
                  "max_columns": 100, "max_namespace_dots": 2},
        "grounding": {"version": 1, "declarations": [],
                      "cited_apis": [{"path": "Example.lean", "start": 1, "end": 1}],
                      "limitations": "Synthetic fixture only."},
    }
    return {**body, "packet_sha256": fvs_profile.digest(body)}


def config() -> dict:
    return {"schema": "autofv-run/v3", "model": runtime_profile.PI_MODEL,
            "role_profile": runtime_profile.PI_PROFILE_ID, "source_packet": packet(),
            "max_wall_seconds": 600, "max_cost_usd": None, "max_invocations": 12}


def runtime_identity() -> dict:
    return {"schema": "autofv-pi-runtime-identity/v1", "protocol_version": 1,
            "node_sha256": "a" * 64, "bridge_sha256": "b" * 64,
            "package_lock_sha256": "c" * 64, "packages": dict(runtime_profile.PI_PACKAGES)}


def binding() -> dict:
    return {"schema": "autofv-provider-binding/v3", "role_profile": runtime_profile.profile(),
            "role_profile_sha256": fvs_profile.digest(runtime_profile.profile()),
            "runtime_identity": runtime_identity(),
            "runtime_identity_sha256": fvs_profile.digest(runtime_identity()),
            "source_packet_sha256": packet()["packet_sha256"]}


def job() -> dict:
    return {"schema": "autofv-role-job/v1", "run_id": "run-profile-test",
            "declaration": "Example.f_spec", "role": "prover", "assigned_path": "Example.lean",
            "allowed_read_paths": ["Example.lean"], "graph_sha256": "1" * 64,
            "statement_sha256": "2" * 64, "contract_fingerprint": "3" * 64,
            "input_hashes": ["4" * 64], "accepted_commit": "a" * 40,
            "role_context": {"data": "complete frozen context"}}


def pi_job(role: str = "prover", runtime_sha256: str | None = None) -> dict:
    identity = runtime_profile.role_identity(role, runtime_sha256 or binding()["runtime_identity_sha256"])
    return {**job(), "schema": "autofv-role-job/v3", "methodology": "fvs-fc/v1", "role": role,
            "runtime_profile": identity,
            "input_hashes": sorted({"4" * 64} | runtime_profile.identity_hashes(identity))}


class RuntimeProfileTests(unittest.TestCase):
    def validate(self, value, *, canonical=True):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.json"
            path.write_bytes(contracts.canonical_json_bytes(value) + (b"\n" if canonical else b""))
            return contracts.validate_run_config(path)[1]

    def test_api_profile_and_role_message_bytes_are_unchanged(self):
        self.assertEqual(fvs_profile.digest(fvs_profile.profile()),
                         "dbe0c289b298d684bbf0c4b79c03d0088e304cfc3167a29f820ec11bf607f680")
        snapshots = {
            ("v1", "prover"): ("b56953f2ba03b230ba6411e8fcf28d677df7a298e236961facbf31afb2f9cc88", "32a35a8e6d1ff9c7ff5e6b3073b4be28cd7db353f415cb011632db49a2669245"),
            ("v1", "spec_reviewer"): ("3cc775ce9113f7a1f10827e8678b570ce2086888aae29647b89fa7726d08ce3c", "e034e26e52abe13099477b935707cf91c6b8e41a1107ac977ee67307fc74b24f"),
            ("v2", "prover"): ("e247747eacbb83311106a770259852c4c2b7b33d87e7e4bc40047cb9b2296902", "137e51902a90371f164aad100cc30cceb2c0278c60effd1513351a6d4ccb8beb"),
            ("v2", "spec_reviewer"): ("e5cc62337330c8aecfa6f8b54bf3fd388836b64b7344d9057c62bb84ddf60edf", "03dee72f0b09f60aadcabd31c672ac11668ee2d356f13d13a63be4c3a6337e23"),
        }
        for (version, role), (spec_hash, messages_hash) in snapshots.items():
            value = {**job(), "schema": "autofv-role-job/" + version, "role": role}
            if version == "v2":
                value["methodology"] = "fvs-fc/v1"
            spec = agent_lane.role_conversation_spec(value)
            self.assertEqual(fvs_profile.digest(spec), spec_hash)
            self.assertEqual(fvs_profile.digest(agent_lane.initial_role_messages(spec)), messages_hash)

    def test_original_config_semantics_preserved(self):
        legacy = {"schema": "autofv-run/v1", "model": "unchanged/model",
                  "max_wall_seconds": 600, "max_cost_usd": "5.000000"}
        self.assertEqual(self.validate(legacy)["max_cost_usd"], Decimal("5"))
        api = {**config(), "schema": "autofv-run/v2", "model": fvs_profile.AUTHOR,
               "role_profile": fvs_profile.PROFILE_ID, "max_cost_usd": "5.000000"}
        del api["max_invocations"]
        self.assertEqual(self.validate(api)["max_cost_usd"], Decimal("5"))
        self.assertEqual(runtime_profile.resolve(api), fvs_profile.profile())
        self.assertEqual(fvs_profile.model_for(api, "spec_reviewer"), fvs_profile.REVIEWER)

    def test_pi_is_distinct_openai_only_same_methodology(self):
        value = self.validate(config())
        self.assertIsNone(value["max_cost_usd"])
        self.assertTrue(fvs_profile.enabled(value))
        selected = runtime_profile.resolve(value)
        self.assertEqual(selected["methodology"], agent_lane._FVS_METHODOLOGY)
        self.assertEqual(selected["role_runtime"], "deepagents")
        for role in fvs_profile.ROLE_MODELS:
            self.assertEqual(fvs_profile.model_for(value, role), runtime_profile.PI_MODEL)
        self.assertNotEqual(runtime_profile.profile_sha256(value), fvs_profile.digest(fvs_profile.profile()))

    def test_no_output_cap_or_known_monetary_ceiling_claim(self):
        profile = runtime_profile.profile()
        self.assertIsNone(profile["parameters"]["server_output_token_cap"])
        self.assertEqual(profile["accounting_class"], "subscription_cost_unknown")
        self.assertEqual(profile["limits"]["max_concurrent_generations"], 1)
        self.assertEqual(profile["limits"]["remote_cancellation"], "best_effort")
        self.assertNotIn("max_output_tokens", profile["parameters"])
        for role in fvs_profile.ROLE_MODELS:
            spec = agent_lane.role_conversation_spec(pi_job(role))
            self.assertIsNone(spec["max_output_tokens"])
            agent_lane.initial_role_messages(spec)

    def test_api_authority_cannot_be_copied_to_pi(self):
        for change in ({"max_cost_usd": "10.000000"}, {"max_cost_usd": 0},
                       {"role_profile": fvs_profile.PROFILE_ID}, {"model": fvs_profile.AUTHOR},
                       {"model": "gpt-6.1-sol-mini"}, {"approval_id": "copied-api-approval"}):
            with self.subTest(change=change), self.assertRaises(contracts.ContractError):
                self.validate({**config(), **change})
        with self.assertRaises(contracts.ContractError):
            runtime_profile.validate_binding_profile({**binding(), "schema": "autofv-provider-binding/v2"})

    def test_config_requires_bounded_invocations_and_canonical_bytes(self):
        for limit in (0, -1, None, True, "12", 1.5):
            with self.subTest(limit=limit), self.assertRaises(contracts.ContractError):
                self.validate({**config(), "max_invocations": limit})
        value = config()
        del value["max_invocations"]
        with self.assertRaises(contracts.ContractError):
            self.validate(value)
        with self.assertRaises(contracts.ContractError):
            self.validate(config(), canonical=False)

    def test_pi_helper_reserves_still_apply(self):
        value = {**config(), "helper_reserves": {"first_specification": 400,
                 "distinct_verification": 300, "terminal_audit": 200, "finalization": 100}}
        self.validate(value)
        value["helper_reserves"]["terminal_audit"] = 500
        with self.assertRaises(contracts.ContractError):
            self.validate(value)

    def test_profile_rejects_effort_clamp_fallback_and_extra_options(self):
        for key, value in (("requested_effort", "high"), ("tool_choice", "auto"),
                           ("server_output_token_cap", 16384), ("temperature", 0)):
            changed = runtime_profile.profile()
            changed["parameters"][key] = value
            with self.subTest(key=key), self.assertRaises(contracts.ContractError):
                runtime_profile.validate_profile(changed)
        changed = runtime_profile.profile()
        changed["role_models"]["spec_reviewer"] = fvs_profile.REVIEWER
        with self.assertRaises(contracts.ContractError):
            runtime_profile.validate_profile(changed)
        with self.assertRaises(contracts.ContractError):
            runtime_profile.model_for(config(), "arbitrary")

    def test_runtime_hashes_and_exact_package_versions_required(self):
        runtime_profile.validate_binding_profile(binding())
        for malformed in (None, [], {}, {"schema": "autofv-provider-binding/v2"}):
            with self.assertRaises(contracts.ContractError):
                runtime_profile.validate_binding_profile(malformed)
        for field, value in (("node_sha256", "bad"), ("protocol_version", True),
                             ("schema", "unknown"), ("unverified", True)):
            changed = runtime_identity()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(contracts.ContractError):
                runtime_profile.validate_runtime_identity(changed)
        changed = binding()
        changed["runtime_identity"]["packages"]["@earendil-works/pi-ai"] = "latest"
        with self.assertRaises(contracts.ContractError):
            runtime_profile.validate_binding_profile(changed)
        for field in ("role_profile_sha256", "runtime_identity_sha256"):
            with self.assertRaises(contracts.ContractError):
                runtime_profile.validate_binding_profile({**binding(), field: "f" * 64})

    def test_job_binds_role_profile_and_runtime_in_input_and_conversation(self):
        value = pi_job()
        self.assertEqual(agent_lane.validate_role_job(value), value)
        spec = agent_lane.role_conversation_spec(value)
        self.assertEqual(spec["schema"], "autofv-role-conversation/v3")
        self.assertEqual(spec["runtime_profile"], spec["context"]["runtime_profile"])
        newer = agent_lane.role_conversation_spec(pi_job(runtime_sha256="f" * 64))
        self.assertNotEqual(spec["conversation_id"], newer["conversation_id"])
        reviewer = agent_lane.role_conversation_spec(pi_job("spec_reviewer"))
        self.assertNotEqual(spec["conversation_id"], reviewer["conversation_id"])
        for field in ("role_profile_sha256", "runtime_identity_sha256"):
            changed = copy.deepcopy(value)
            changed["input_hashes"].remove(value["runtime_profile"][field])
            with self.assertRaises(worker.WorkerError):
                agent_lane.validate_role_job(changed)

    def test_job_and_conversation_reject_profile_drift_and_implicit_api(self):
        value = pi_job()
        for key, changed in (("requested_effort", "high"), ("role_profile", fvs_profile.PROFILE_ID),
                             ("tool_choice", "auto"), ("model_id", fvs_profile.AUTHOR)):
            bad = copy.deepcopy(value)
            bad["runtime_profile"][key] = changed
            with self.subTest(key=key), self.assertRaises(worker.WorkerError):
                agent_lane.validate_role_job(bad)
        spec = agent_lane.role_conversation_spec(value)
        with self.assertRaises(worker.WorkerError):
            agent_lane.initial_role_messages({**spec, "max_output_tokens": 16384})
        with self.assertRaises(worker.WorkerError):
            agent_lane.validate_role_job({**value, "schema": "autofv-role-job/v2"})

    def test_pi_candidate_cannot_be_relabelled_as_mixed_api_profile(self):
        value = pi_job()
        candidate = agent_lane._candidate(value, {
            "patch": "diff --git a/Example.lean b/Example.lean\n",
            "claimed_status": "candidate", "evidence": []})
        relabelled = {k: v for k, v in value.items() if k != "runtime_profile"}
        relabelled["schema"] = "autofv-role-job/v2"
        with self.assertRaisesRegex(worker.WorkerError, "role context mismatch"):
            agent_lane.validate_candidate(candidate, relabelled)
        changed = pi_job(runtime_sha256="f" * 64)
        replay = {**candidate, "input_hashes": changed["input_hashes"]}
        with self.assertRaisesRegex(worker.WorkerError, "role context mismatch"):
            agent_lane.validate_candidate(replay, changed)

    def test_generic_job_carries_trusted_runtime_identity(self):
        from autofv.generic_role_runtime import _role_job
        state = {"config": config(), "run": {"run_id": "run-profile-test",
                 "runtime_identity_sha256": binding()["runtime_identity_sha256"]}}
        lane = {"node": "Example.f_spec", "assigned_path": "Example.lean", "base_commit": "a" * 40}
        value = _role_job(state, {"graph_sha256": "1" * 64}, lane, "prover",
                          statement_sha256="2" * 64, contract_fingerprint="3" * 64,
                          input_hashes=["4" * 64], role_context={"data": "frozen"})
        agent_lane.validate_role_job(value)
        self.assertEqual(value["runtime_profile"], pi_job()["runtime_profile"])
        del state["run"]["runtime_identity_sha256"]
        with self.assertRaises(contracts.ContractError):
            _role_job(state, {"graph_sha256": "1" * 64}, lane, "prover",
                      statement_sha256="2" * 64, contract_fingerprint="3" * 64,
                      input_hashes=["4" * 64], role_context={"data": "frozen"})

    def test_stage_records_profile_runtime_and_rejects_replay_drift(self):
        state = {"config": config(), "run": {"provider_binding": binding(),
                 "runtime_identity_sha256": binding()["runtime_identity_sha256"]}}
        stage = fvs_adapter.Stages(state, {}, {"node": "Example.f", "assigned_path": "Example.lean"},
                                  lambda *a, **k: None, lambda *a: None)
        value = stage.record("gate", {"status": "synthetic"})
        self.assertEqual(value["role_profile_sha256"], runtime_profile.profile_sha256(config()))
        self.assertEqual(value["runtime_identity_sha256"], binding()["runtime_identity_sha256"])
        fvs_adapter.validate_evidence(state["fvs_evidence"], binding=binding(), exchanges={})
        with self.assertRaises(contracts.ContractError):
            stage.record("gate", {"status": "changed"})
        modified = copy.deepcopy(state["fvs_evidence"])
        entry = next(iter(modified.values()))
        entry["runtime_identity_sha256"] = "f" * 64
        entry["record_sha256"] = fvs_profile.digest({k: v for k, v in entry.items() if k != "record_sha256"})
        with self.assertRaises(contracts.ContractError):
            fvs_adapter.validate_evidence(modified, binding=binding(), exchanges={})

    def test_stage_refuses_copied_mixed_profile_binding(self):
        state = {"config": config(), "run": {"provider_binding": {**binding(),
                 "role_profile": fvs_profile.profile()}, "runtime_identity_sha256": "e" * 64}}
        with self.assertRaises(contracts.ContractError):
            fvs_adapter.Stages(state, {}, {"node": "Example.f", "assigned_path": "Example.lean"},
                               lambda *a, **k: None, lambda *a: None)

    def test_effort_provenance_does_not_invent_independent_observation(self):
        exchange = {"receipt": {"receipt_sha256": "e" * 64,
                    "provider": {"requested_effort": "xhigh", "observed_effort": None,
                                 "parameter_observation": "requested; effort not independently reported"}}}
        observed = fvs_adapter._effort_observations([exchange])[0]
        self.assertEqual(observed["requested_effort"], "xhigh")
        self.assertIsNone(observed["observed_effort"])


if __name__ == "__main__":
    unittest.main()
