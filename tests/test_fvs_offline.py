"""Offline FVS seams. All credentials, provider replies and Lean verdicts are synthetic."""
from __future__ import annotations

import asyncio
import copy
import difflib
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import (agent_lane, contracts, experiment, fvs_adapter, fvs_packet, fvs_profile,
                    generic_role_runtime, model, provider_config, provider_receipts,
                    provider_transport, worker, worker_proxy, worker_runtime)
from tests.test_provider_transport import _provider_env, _provider_run, _provider_reply, _ProviderReply

ROOT = Path(__file__).resolve().parents[1]
PATH = "Arithmetic.lean"
ORIGINAL = "import Types\nnamespace Arithmetic\ndef increment (n : Nat) := n + 1\nend Arithmetic\n"
CANON = "theorem Arithmetic.increment_spec (n : Nat) : ∃ result, increment n = ok result"
SPEC = ORIGINAL.replace("end Arithmetic\n", "@[step]\ntheorem increment_spec (n : Nat) : ∃ result, increment n = ok result := by\n  sorry\nend Arithmetic\n")
PROOF = SPEC.replace("sorry", "rfl")
IDENTITY = {"repository": "https://example.invalid/public", "revision": "a" * 40, "tree_sha256": "b" * 64}
PASS = """# FC Specification Review
## Findings
None.
## Content coverage statement
The supplied implementation, returned value and natural-number interpretation are covered.
## Coverage
Source fidelity: the complete increment implementation was examined.
Preconditions: all natural inputs are reachable without extra assumptions.
Postconditions: the returned value equals increment of the input.
Interpretation: natural-number equality has the intended quantifiers.
Vacuity: no conclusion is assumed and the result is used.
Dependencies: complete Types and interpretation evidence was read.
Helper reuse: the inventory identifies existing increment APIs.
## Evidence
Arithmetic.lean:1-4; Types.lean:1; boundary inputs zero and one yield one and two.
VERDICT: PASS"""
REVISE = PASS.replace("None.", """### F-1 — MAJOR
Class: CONTENT
Claim: The successor bound needs an explicit statement.
Evidence: Arithmetic.lean:3 exposes the successor behavior.
Suggested change: State the precise successor bound in the postcondition.""").replace("VERDICT: PASS", "VERDICT: REVISE")


def patch(text: str, baseline: str = ORIGINAL) -> str:
    return f"diff --git a/{PATH} b/{PATH}\n" + "".join(difflib.unified_diff(
        baseline.splitlines(keepends=True), text.splitlines(keepends=True), fromfile="a/" + PATH, tofile="b/" + PATH))


def packet() -> dict:
    body = {"schema": "autofv-fvs-source-packet/v1", "source_identity": IDENTITY,
        "sources": [fvs_packet.source(PATH, "lean", ORIGINAL),
                    fvs_packet.source("rust/increment.rs", "rust", "pub fn increment(n: u64) -> u64 { n + 1 }\n"),
                    fvs_packet.source("Types.lean", "types", "def Word := Nat\n"),
                    fvs_packet.source("Interpretation.lean", "interpretation", "def interpret (n : Nat) := n\n"),
                    fvs_packet.source("Intent.md", "intent", "Return the successor of the input.\n"),
                    fvs_packet.source("Root.lean", "lean", "theorem Arithmetic.root_spec : True := by sorry\n")],
        "style": {"path": "FVS fallback", "content": "At most 100 columns and two namespace dots.",
                  "max_columns": 100, "max_namespace_dots": 2},
        "grounding": {"version": 1, "declarations": [], "cited_apis": [{"path": PATH, "start": 3, "end": 3}], "limitations": "Synthetic pinned API inventory."}}
    return {**body, "packet_sha256": fvs_profile.digest(body)}


def config() -> dict:
    return {"schema": "autofv-run/v2", "model": fvs_profile.AUTHOR,
            "role_profile": fvs_profile.PROFILE_ID, "source_packet": packet(),
            "max_wall_seconds": 600, "max_cost_usd": "5.000000"}


class FvsBindingDomainTests(unittest.TestCase):
    def job(self, role="specifier", *, canon=CANON, candidate=None):
        view = packet() if candidate is None else fvs_packet.review_snapshot(
            packet(), path=PATH, patch=candidate["patch"])
        context = {"stage": "spec-author:0" if candidate is None else "spec-review:0",
                   "contracts_sha256": fvs_profile.digest(fvs_adapter.contracts()),
                   "task_brief": {"final_goal": {"canon": "theorem Arithmetic.root_spec : True"}},
                   "source_packet": view}
        if candidate is not None:
            context["reviewed_candidate"] = candidate
        fingerprint = fvs_adapter._raw_sha256(context["task_brief"]["final_goal"]["canon"] if role == "specifier" else canon)
        return generic_role_runtime._role_job(
            {"config": config(), "run": {"run_id": "binding-fixture"}},
            {"graph_sha256": "d" * 64},
            {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}, role,
            statement_sha256=fingerprint, contract_fingerprint=fingerprint,
            input_hashes=[packet()["packet_sha256"], fvs_profile.digest(view), fvs_profile.digest(context)],
            role_context=context)

    def candidate(self, job, canon=CANON):
        return agent_lane._candidate(job, {"patch": patch(SPEC), "claimed_status": "candidate",
                                          "evidence": ["statement:" + canon]})

    def annex(self, job):
        messages = agent_lane.initial_role_messages(agent_lane.role_conversation_spec(job))
        self.assertNotIn("binding_domains", messages[0]["content"])
        return json.loads(messages[1]["content"])["context"]["binding_domains"]

    def test_frozen_proof_authors_are_told_the_exact_submission_evidence_contract(self):
        for role in ("prover", "repair"):
            with self.subTest(role=role):
                job = self.job(role)
                job["role_context"]["frozen_statement"] = CANON
                spec = agent_lane.role_conversation_spec(job)
                self.assertIn("exactly one evidence item", spec["system_prompt"])
                self.assertIn("statement:theorem ", spec["system_prompt"])
                self.assertIn("'statement:' + frozen_statement", spec["system_prompt"])
                self.assertIn("No model proof-review or pure PASS-acknowledgement", spec["system_prompt"])
                self.assertEqual(spec["context"]["role_context"]["frozen_statement"], CANON)
                self.assertEqual(fvs_adapter.statement({"evidence": ["statement:" + CANON]}), CANON)
                for evidence in (["Proof compiled successfully"],
                                 ["statement:" + CANON] * 2,
                                 ["statement:" + CANON + " := by sorry"]):
                    with self.assertRaises(fvs_adapter.StatementBindingError):
                        fvs_adapter.statement({"evidence": evidence})

    def test_binding_domains_separate_raw_statements_packets_and_role_contexts(self):
        author = self.job()
        candidate = self.candidate(author)
        before = copy.deepcopy(candidate)
        review = self.job("spec_reviewer", candidate=candidate)
        a, r = self.annex(author), self.annex(review)
        self.assertEqual(a["job_bindings"]["fingerprint_domain"], "supplied_root_goal")
        self.assertEqual(r["job_bindings"]["fingerprint_domain"], "reviewed_statement")
        self.assertNotEqual(a["job_bindings"]["statement_sha256"], r["job_bindings"]["statement_sha256"])
        for summary in (a, r):
            for field in ("statement_sha256_check", "contract_fingerprint_check", "input_hashes_check"):
                self.assertEqual(summary["job_bindings"][field], "verified")
        domains = r["json_sha256"]
        self.assertEqual(domains["original_packet_body"], packet()["packet_sha256"])
        self.assertEqual(domains["full_stage_packet"], fvs_profile.digest(review["role_context"]["source_packet"]))
        self.assertEqual(domains["role_context"], fvs_profile.digest(review["role_context"]))
        self.assertEqual(domains["methodology_role_context"], agent_lane.role_context_sha256(
            review["role_context"], methodology=agent_lane._FVS_METHODOLOGY))
        self.assertEqual(len(set(domains.values())), 4)
        self.assertNotIn("binding_domains", review["role_context"])
        self.assertEqual(candidate, before)
        spaced = CANON.replace(" (n", "  (n")
        spaced_candidate = self.candidate(author, spaced)
        spaced_review = self.job("spec_reviewer", canon=spaced, candidate=spaced_candidate)
        spaced_annex = self.annex(spaced_review)
        self.assertNotEqual(r["reviewed_statement"]["sha256"], spaced_annex["reviewed_statement"]["sha256"])
        self.assertEqual(spaced_annex["reviewed_statement"]["normalized_source_check"], "verified")
        self.assertNotEqual(r["candidate_patch"]["sha256"], r["assigned_source"]["sha256"])

    def test_direct_root_role_job_keeps_non_stage_inputs_without_inventing_the_triplet(self):
        state = {"config": config(), "run": {"run_id": "binding-fixture"}}
        graph = {"graph_sha256": "d" * 64}
        lane = {"node": "probe:Arithmetic.root_spec", "assigned_path": "Root.lean", "base_commit": "c" * 40}
        root = "theorem Arithmetic.root_spec : True"
        for role in ("scout", "prover", "proof_reviewer", "repair"):
            job = generic_role_runtime._role_job(state, graph, lane, role,
                statement_sha256=fvs_adapter._raw_sha256(root), contract_fingerprint=fvs_adapter._raw_sha256(root),
                input_hashes=[graph["graph_sha256"]], role_context={"contract": {"canon": root}})
            before = copy.deepcopy(job)
            annex = self.annex(job)
            self.assertEqual(job, before)
            self.assertEqual(job["role_context"]["source_packet"], packet())
            self.assertEqual(annex["source_packet_check"], "verified")
            self.assertEqual(annex["job_bindings"]["input_hashes_check"], "not_verified")
            self.assertNotIn("input_hashes_construction", annex["job_bindings"])

    def test_binding_domains_do_not_bless_mutated_same_domain_or_missing_context(self):
        job = self.job("spec_reviewer", candidate=self.candidate(self.job()))
        for field in ("statement_sha256", "contract_fingerprint", "input_hashes"):
            bad = copy.deepcopy(job)
            bad[field] = ["0" * 64] if field == "input_hashes" else "0" * 64
            summary = self.annex(bad)["job_bindings"]
            self.assertEqual(summary[field + "_check"], "mismatch")
        minimal = {**self.job(), "role_context": {"source_packet": packet()}}
        summary = self.annex(minimal)
        self.assertEqual(summary["job_bindings"]["fingerprint_domain"], "not_verified")
        self.assertEqual(summary["job_bindings"]["input_hashes_check"], "not_verified")
        self.assertNotIn("supplied_root_goal", summary)


class FvsReviewFormatTests(unittest.TestCase):
    def review_template(self):
        guide = fvs_adapter.contracts()["review_contract"]
        self.assertEqual(guide.count("```markdown\n"), 1, "review contract must disclose one complete Markdown template")
        return guide.split("```markdown\n", 1)[1].split("\n```", 1)[0]

    def synthetic_review(self, verdict="APPROVE-WITH-EDITS"):
        # Format fixtures only: this Nat-only review makes no Rust/proof acceptance claim.
        values = {
            "<positive integer>": "1", "<severity>": "MINOR", "<class>": "CONTENT",
            "<claim>": "The theorem doc omits its Nat-only scope, inviting a machine-word reading.",
            "<finding evidence>": "Arithmetic.lean:3 uses Nat, which has no machine-word wraparound.",
            "<suggested change>": "Optional clarity edit, not a soundness defect: document the Nat-only scope.",
            "<content coverage>": "Synthetic Nat-only review of Arithmetic.lean:3 and the equation increment n = n + 1; no Rust correspondence or proof certification claimed.",
            "<source fidelity analysis>": "Arithmetic.lean:3 adds one over Nat: no finite widths, overflow/wrapping, casts, shifts, mutation or panics.",
            "<preconditions analysis>": "All Nat inputs reach the return at Arithmetic.lean:3; n = 0 is allowed and no extra bound is needed.",
            "<postconditions analysis>": "The result at Arithmetic.lean:3 is n + 1, hence strictly greater than n; no state update or canonical residue is promised.",
            "<interpretation analysis>": "The equation quantifies every n : Nat; equality means natural/integer equality, not a modular relation.",
            "<vacuity analysis>": "The equation constrains the actual result without assumptions; at n = 0 it requires 1, ruling out a constant-zero implementation.",
            "<dependencies analysis>": "Arithmetic.lean:1 imports Types.lean:1 (Word := Nat); this fixture needs no external arithmetic model.",
            "<helper reuse analysis>": "The synthetic grounding inventory cites only Arithmetic.lean:3; it contains no successor theorem or direct callers to reuse.",
            "<review evidence>": "Arithmetic.lean:1-4; Types.lean:1; n = 0 and n = 1 compute 1 and 2. No Lean diagnostic is claimed.",
            "<verdict>": verdict,
        }
        if verdict == "BLOCKED":
            values["<dependencies analysis>"] = "Types.lean:1 is missing, so the import and any hidden assumptions cannot be checked."
            values["<review evidence>"] = "Arithmetic.lean:1 imports Types; missing Types.lean:1 prevents checking that dependency."
        raw = self.review_template()
        for placeholder, value in values.items():
            self.assertIn(placeholder, raw)
            raw = raw.replace(placeholder, value)
        if verdict in {"PASS", "BLOCKED"}:
            raw = "## Findings\nNone.\n## Content coverage statement" + raw.split("## Content coverage statement", 1)[1]
        self.assertNotRegex(raw, r"<[^>]+>")
        self.assertLessEqual(len(raw), 4096)
        return raw

    def test_review_contract_discloses_complete_parser_format(self):
        template = self.review_template()
        self.assertEqual([line for line in template.splitlines() if line.startswith("## ")],
                         ["## Findings", "## Content coverage statement", "## Coverage", "## Evidence"])
        self.assertIn("### F-<positive integer> — <severity>\nClass: <class>\nClaim: <claim>\nEvidence: <finding evidence>\nSuggested change: <suggested change>", template)
        coverage = template.split("## Coverage\n", 1)[1].split("## Evidence", 1)[0]
        self.assertEqual([line.split(":", 1)[0] for line in coverage.splitlines()],
                         ["source fidelity", "preconditions", "postconditions", "interpretation", "vacuity", "dependencies", "helper reuse"])
        self.assertEqual(template.count("VERDICT:"), 1)
        guide = fvs_adapter.contracts()["review_contract"]
        for rule in ("one report of at most 4096 characters", "each on its own line",
                     "Qualifications belong in values, never labels", "Placeholders are not valid review evidence",
                     "Missing analysis requires BLOCKED, never default PASS", "PASS only with no findings",
                     "REVISE and APPROVE-WITH-EDITS need findings", "BLOCKED must name missing evidence"):
            with self.subTest(rule=rule):
                self.assertIn(rule, guide)

    def test_review_contract_template_parses_all_verdicts_without_rewriting(self):
        for verdict in ("PASS", "APPROVE-WITH-EDITS", "REVISE", "BLOCKED"):
            with self.subTest(verdict=verdict):
                raw = self.synthetic_review(verdict)
                review = fvs_adapter.parse_review(raw)
                self.assertEqual(review["verdict"], verdict)
                self.assertEqual(review["raw"], raw)
                self.assertEqual(review["raw_sha256"], hashlib.sha256(raw.encode()).hexdigest())
                self.assertEqual(len(review["findings"]), int(verdict in {"APPROVE-WITH-EDITS", "REVISE"}))
                if review["findings"]:
                    self.assertEqual(review["findings"][0]["Class"], "CONTENT")
                    self.assertTrue(review["findings"][0]["Suggested change"].startswith("Optional clarity edit"))

    def test_parse_review_rejects_observed_coverage_aliases(self):
        raw = self.synthetic_review()
        aliases = {"source fidelity": "Widths and casts", "preconditions": "Callers",
                   "postconditions": "Postcondition", "interpretation": "Quantifiers",
                   "vacuity": "Style", "dependencies": "Trust", "helper reuse": "Helper scope"}
        combined = raw
        for label, alias in aliases.items():
            with self.subTest(label=label), self.assertRaisesRegex(contracts.ContractError, "omits applicable review surfaces"):
                fvs_adapter.parse_review(raw.replace(label + ":", alias + ":"))
            combined = combined.replace(label + ":", alias + ":")
        with self.assertRaisesRegex(contracts.ContractError, "omits applicable review surfaces"):
            fvs_adapter.parse_review(combined)

    def test_parse_review_rejects_observed_combined_header_and_renamed_field(self):
        raw = self.synthetic_review()
        with self.assertRaisesRegex(contracts.ContractError, "malformed finding header"):
            fvs_adapter.parse_review(raw.replace("### F-1 — MINOR\nClass: CONTENT", "### F-1 — MINOR, Class: CONTENT"))
        with self.assertRaisesRegex(contracts.ContractError, "lacks substantive fields"):
            fvs_adapter.parse_review(raw.replace("Suggested change:", "Suggested change (optional, not a soundness defect):"))

    def test_parse_review_template_preserves_sections_verdict_and_findings_rules(self):
        raw = self.synthetic_review()
        invalid = [raw + "\nVERDICT: PASS", raw.replace("VERDICT: APPROVE-WITH-EDITS", "VERDICT: PASS"),
                   self.synthetic_review("PASS").replace("VERDICT: PASS", "VERDICT: REVISE"),
                   self.synthetic_review("PASS").replace("VERDICT: PASS", "VERDICT: APPROVE-WITH-EDITS"),
                   self.synthetic_review("PASS").replace("VERDICT: PASS", "VERDICT: BLOCKED")]
        invalid += [raw.replace(heading, "## Omitted") for heading in
                    ("## Findings", "## Content coverage statement", "## Coverage", "## Evidence")]
        for index, malformed in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises(contracts.ContractError):
                fvs_adapter.parse_review(malformed)

    def test_parse_review_template_keeps_4096_character_bound(self):
        raw = self.synthetic_review()
        bounded = raw.replace("\nVERDICT:", " " * (4096 - len(raw)) + "\nVERDICT:")
        self.assertEqual(len(bounded), 4096)
        self.assertEqual(fvs_adapter.parse_review(bounded)["raw"], bounded)
        with self.assertRaisesRegex(contracts.ContractError, "empty/oversized"):
            fvs_adapter.parse_review(bounded + "\n")


class FvsOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)
        token_env = mock.patch.dict(os.environ, {"AUTOFV_RUN_TOKEN": "synthetic-fvs-run-token"})
        token_env.start()
        self.addCleanup(token_env.stop)
        lock = contracts.load_toolchain_lock()
        self.run = _provider_run(self.root, lock, "c" * 40)
        self.run.update(role_profile=fvs_profile.PROFILE_ID, source_packet_sha256=packet()["packet_sha256"])
        env = _provider_env(self.root, overrides={
            "AUTOFV_PROVIDER_ENDPOINT": "https://openrouter.ai/api/v1/chat/completions",
            "AUTOFV_PROVIDER_MODEL": fvs_profile.AUTHOR,
            "AUTOFV_PROVIDER_INPUT_USD_PER_MILLION": "2",
            "AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION": "0.1",
            "AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION": "10"})
        provider_config.configure_provider(self.run, env_path=env, tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=self.root)
        self.binding = provider_config.provider_binding(self.run)
        self.addCleanup(provider_config.release_provider, self.run)
        self.state = {"run": self.run, "config": config(), "receipts": [], "model_exchanges": {},
                      "pending_model_exchanges": {}, "cost": Decimal(0), "checkpoint_enabled": False,
                      "manifest": {"verify": ["lake", "build"]}, "accepted": {"accepted_commit": "c" * 40}}

    def bound_packet(self):
        """Synthetic local Git provenance; no real preparation or solved Lean reads."""
        p = packet()
        for item in p["sources"]:
            if item["surface"] != "rust":
                (self.root / item["path"]).write_text(item["content"])
        repo = self.root / "public"
        rust_root = repo / "curve25519-dalek" / "src"
        rust_root.mkdir(parents=True)
        (rust_root / "increment.rs").write_text(p["sources"][1]["content"])
        def git(*args):
            return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        git("config", "user.name", "Synthetic Test")
        git("config", "user.email", "synthetic@example.invalid")
        git("remote", "add", "origin", IDENTITY["repository"])
        git("add", "curve25519-dalek/src/increment.rs")
        git("commit", "-qm", "Synthetic public Rust fixture")
        p["source_identity"] = {**IDENTITY, "revision": git("rev-parse", "HEAD")}
        p["packet_sha256"] = fvs_profile.digest({k: v for k, v in p.items() if k != "packet_sha256"})
        preparation = {"source": p["source_identity"], "files": [
            {"path": s["path"], "sha256": s["sha256"]}
            for s in p["sources"] if s["surface"] != "rust"]}
        return p, preparation, rust_root

    def exchange(self, role="specifier", *, input_hashes=None, sequence=None, response_overrides=None):
        request = model._model_envelope(self.state, request_id=f"fixture-{len(self.state['model_exchanges'])+1}",
            role=role, input_hashes=input_hashes or [], sequence=sequence)
        upstream = _provider_reply()
        upstream.update(model=request["model_id"], provider="Anthropic" if role in fvs_profile.REVIEW_ROLES else "OpenAI")
        upstream["usage"] = {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110,
                            "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                            "completion_tokens_details": {"reasoning_tokens": 5}, "cost": Decimal("0.000300")}
        if response_overrides:
            response_overrides(upstream)
        response, accounting = provider_transport._provider_response(self.binding, request, upstream, "c" * 40)
        receipt = provider_receipts.sign_receipt(self.binding, self.run, request, response, accounting)
        exchange = {"request": request, "response": response, "receipt": receipt, "call_kind": "explicit"}
        return exchange

    def remember(self, exchange):
        self.state["model_exchanges"][exchange["request"]["request_id"]] = exchange
        self.state["receipts"].append(exchange["receipt"])
        self.state["cost"] += Decimal(exchange["receipt"]["cost"]["amount"])

    def validate(self, exchange):
        request = exchange["request"]
        return provider_receipts.validate_receipt(exchange["receipt"], binding=self.binding.public,
            run_id=request["run_id"], sequence=request["sequence"], request_id=request["request_id"],
            model_id=request["model_id"], request_sha256=fvs_profile.digest(request),
            response_sha256=fvs_profile.digest(exchange["response"]), seen_receipt_sha256=set())

    def test_role_routing_and_upstream_parameters_are_bound(self):
        for role in fvs_profile.ROLE_MODELS:
            e = self.exchange(role)
            request = e["request"]
            self.assertEqual(request["model_id"], fvs_profile.ROLE_MODELS[role])
            upstream = provider_transport._upstream_request(self.binding, request, [{"role": "user", "content": "synthetic"}])
            self.assertEqual(upstream["reasoning"], {"effort": "xhigh", "exclude": True})
            self.assertNotIn("temperature", upstream)
            self.assertEqual(upstream["max_tokens"], 16384)
            self.assertFalse(upstream["provider"]["allow_fallbacks"])
            self.assertTrue(upstream["provider"]["require_parameters"])
            self.assertEqual(upstream["provider"]["ignore"], [] if role in fvs_profile.REVIEW_ROLES else ["openai/fast", "openai/flex", "openai/ultrafast"])
            self.assertEqual(e["receipt"]["provider"]["requested_routing"], upstream["provider"])
            self.assertEqual(self.validate(e), Decimal("0.000300"))
            wrong = copy.deepcopy(request)
            wrong["model_id"] = fvs_profile.AUTHOR if role in fvs_profile.REVIEW_ROLES else fvs_profile.REVIEWER
            with self.assertRaises(worker.WorkerError):
                provider_transport.validate_dispatch_request(self.binding, wrong)
            with self.assertRaises(worker.WorkerError):
                worker_proxy._validate_proxy_request(self.run, wrong)
        with self.assertRaises(contracts.ContractError):
            model._model_envelope(self.state, request_id="bad-role", role="opus", input_hashes=[])

    def test_full_size_fvs_context_reaches_hash_reserve_stage_and_signed_transport(self):
        from tests.test_provider_service import _install_trusted_authorization_fixture
        from autofv import provider_service
        _install_trusted_authorization_fixture(self.run, self.root)
        self.state["run_round"] = model.agentproc.run_round
        self.state["config"]["max_cost_usd"] = Decimal("5.000000")
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        sent = []
        def upstream(request, **_kwargs):
            body = json.loads(request.data)
            sent.append(body)
            reply = _provider_reply()
            reply.update(model=body["model"], provider="OpenAI" if body["model"] == fvs_profile.AUTHOR else "Anthropic")
            reply["usage"] = {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110,
                "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                "completion_tokens_details": {"reasoning_tokens": 5}, "cost": 0.0003}
            return _ProviderReply(reply)
        for role in ("scout", "spec_reviewer"):
            job = generic_role_runtime._role_job(self.state, graph, lane, role,
                statement_sha256="e" * 64, contract_fingerprint="f" * 64, input_hashes=[packet()["packet_sha256"]],
                role_context={"source_packet": packet(), "public_context_note": "x" * 150_625})
            messages = agent_lane.initial_role_messages(agent_lane.role_conversation_spec(job))
            self.assertGreater(len(messages[-1]["content"].encode()), 150_000)
            self.assertLess(len(contracts.canonical_json_bytes(messages)), 262_144)
            with mock.patch.object(provider_transport, "_open_upstream", side_effect=upstream), \
                 mock.patch.object(worker, "proxy_round", side_effect=lambda run, req:
                     provider_service.dispatch(run, req, run_token="synthetic-fvs-run-token")):
                response, receipt = model._model_request(self.state, request_id="full-context-" + role,
                    role=role, input_hashes=[], messages=messages)
            self.assertEqual(response["role"], role)
            self.assertEqual(Decimal(receipt["cost"]["amount"]), Decimal("0.000300"))
            self.assertEqual(sent[-1]["messages"], messages)
        self.assertEqual(len(sent), 2)
        self.assertEqual(self.state["cost"], Decimal("0.000600"))
        self.assertEqual(self.state["pending_model_exchanges"], {})

    def test_full_size_fvs_discards_reasoning_and_bills_complete_usage(self):
        original = _provider_reply
        def reply():
            value = original()
            value["choices"][0]["message"].update(
                reasoning="synthetic-private-text",
                reasoning_details=[{"type": "reasoning.encrypted", "data": "synthetic-private-opaque"}])
            return value
        with mock.patch(__name__ + "._provider_reply", side_effect=reply):
            self.test_full_size_fvs_context_reaches_hash_reserve_stage_and_signed_transport()
        records = list((Path(self.run["evidence_dir"]) / "provider-journal").glob("*.json"))
        self.assertEqual(len(records), 2)
        for path in records:
            raw = path.read_bytes()
            self.assertNotIn(b"synthetic-private-", raw)
            record = json.loads(raw)
            self.assertEqual(record["status"], "completed")
            provider = record["receipt"]["provider"]
            self.assertEqual(provider["usage"]["reasoning_tokens"], 5)
            self.assertEqual(provider["usage"]["output_tokens"], 10)
            self.assertEqual(Decimal(record["receipt"]["cost"]["amount"]), Decimal("0.000300"))
        self.assertNotIn("synthetic-private-", json.dumps(self.state["model_exchanges"]))
        self.assertNotIn("reasoning_details", json.dumps(self.state["model_exchanges"]))

    def test_fvs_reasoning_discard_keeps_invalid_tools_rejected_and_private(self):
        original = _provider_reply
        def reply():
            value = original()
            message = value["choices"][0]["message"]
            message.update(reasoning="synthetic-private-text",
                reasoning_details=[{"type": "reasoning.encrypted", "data": "synthetic-private-opaque"}])
            message["tool_calls"][0]["function"]["name"] = "unapproved_tool"
            return value
        with mock.patch(__name__ + "._provider_reply", side_effect=reply):
            with self.assertRaisesRegex(provider_transport.ProviderError, "provider tool call is invalid"):
                self.test_full_size_fvs_context_reaches_hash_reserve_stage_and_signed_transport()
        records = list((Path(self.run["evidence_dir"]) / "provider-journal").glob("*.json"))
        self.assertEqual(len(records), 1)
        raw = records[0].read_bytes()
        self.assertNotIn(b"synthetic-private-", raw)
        self.assertNotIn(b"reasoning_details", raw)
        self.assertEqual(json.loads(raw)["status"], "rejected")
        self.assertFalse(self.state["receipts"])

    def test_fvs_reasoning_discard_preserves_secret_scan_and_other_shape_checks(self):
        for field in ("reasoning", "reasoning_details"):
            with self.subTest(unexpected_top_level_field=field):
                with self.assertRaises(provider_transport.ProviderError):
                    self.exchange(response_overrides=lambda value: value.update({field: "unexpected"}))
        original = _provider_reply
        def reply():
            value = original()
            value["choices"][0]["message"]["reasoning"] = bytes(self.binding.api_key).decode()
            return value
        with mock.patch(__name__ + "._provider_reply", side_effect=reply):
            with self.assertRaises(provider_transport.ProviderError):
                self.test_full_size_fvs_context_reaches_hash_reserve_stage_and_signed_transport()
        self.assertFalse(self.state["receipts"])

    def test_message_limits_require_pinned_fvs_binding_and_keep_aggregate_bound(self):
        from autofv import provider_messages
        messages = [{"role": "system", "content": "synthetic context"}, {"role": "user", "content": "x" * 150_625}]
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages)
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages, run={"role_profile": fvs_profile.PROFILE_ID})
        public_only = {**self.run, "provider_binding": copy.deepcopy(self.run["provider_binding"])}
        public_only["provider_binding"]["binding_sha256"] = "0" * 64
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages, run=public_only)
        digest = provider_transport.messages_sha256(messages, run=self.run)
        self.assertEqual(digest, fvs_profile.digest(messages))
        messages[-1]["content"] = "é" * 35_000
        self.assertGreater(len(messages[-1]["content"].encode()), 65_536)
        provider_transport.messages_sha256(messages, run=self.run)
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages)
        messages[-1]["content"] = ""
        overhead = len(contracts.canonical_json_bytes(messages))
        messages[-1]["content"] = "x" * (262_144 - overhead)
        self.assertEqual(len(contracts.canonical_json_bytes(messages)), 262_144)
        provider_transport.messages_sha256(messages, run=self.run)
        messages[-1]["content"] += "x"
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages, run=self.run)
        messages[-1]["content"] = "x" * 262_145
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.messages_sha256(messages, run=self.run)
        self.assertEqual(provider_messages.MAX_MESSAGE_BYTES, 262_144)
        self.assertEqual(provider_messages.MAX_WIRE_BYTES, 1_000_000)

    def test_registered_legacy_binding_keeps_65536_byte_message_limit(self):
        root = self.root / "legacy"
        root.mkdir()
        legacy = _provider_run(root, contracts.load_toolchain_lock(), "c" * 40)
        provider_config.configure_provider(legacy, env_path=_provider_env(root),
            tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=root)
        try:
            messages = [{"role": "system", "content": "synthetic"}, {"role": "user", "content": "x" * 65_536}]
            self.assertEqual(provider_transport.messages_sha256(messages, run=legacy),
                             provider_transport.messages_sha256(messages))
            messages[-1]["content"] += "x"
            with self.assertRaises(provider_config.ProviderConfigError):
                provider_transport.messages_sha256(messages, run=legacy)
            request = {"schema": "autofv-model-request/v1", "run_id": legacy["run_id"], "sequence": 1,
                "request_id": "synthetic-legacy-large", "batch_id": None, "role": "scout",
                "model_id": legacy["proxy_model_id"], "input_hashes": [fvs_profile.digest(messages)],
                "prompt_sha256": "a" * 64}
            with self.assertRaises(provider_config.ProviderConfigError):
                provider_transport.reservation_usd(legacy, request, messages)
            with self.assertRaises(provider_config.ProviderConfigError):
                provider_transport.stage_messages(legacy, request, messages)
        finally:
            provider_config.abort_configuration(legacy)

    def test_profile_parameter_and_pricing_drift_rejected_even_when_rehashed(self):
        public = self.binding.public
        for field, value in (("reasoning", {"effort": "high", "exclude": True}), ("work_max_output_tokens", 8192)):
            bad = copy.deepcopy(public)
            bad["parameters"][field] = value
            bad["binding_sha256"] = fvs_profile.digest({k: v for k, v in bad.items() if k != "binding_sha256"})
            with self.assertRaises(worker.WorkerError):
                provider_config.validate_public_binding(bad)
        bad_profile = fvs_profile.profile()
        bad_profile["models"][fvs_profile.REVIEWER]["tiers"][0]["write_upper"] = "2.50"
        with self.assertRaises(contracts.ContractError):
            fvs_profile.validate_profile(bad_profile)

    def test_sonnet_cache_writes_have_labeled_bounds_and_known_reported_amount(self):
        def writes(reply):
            reply["usage"]["prompt_tokens_details"] = {"cached_tokens": 20, "cache_write_tokens": 40}
            reply["usage"]["cost"] = Decimal("0.000324")
            reply["usage"]["cost_details"] = {"upstream_inference_cost": Decimal("0.000324")}
        e = self.exchange("spec_reviewer", response_overrides=writes)
        p = e["receipt"]["provider"]
        self.assertEqual(p["cache_write_ttl"], "unknown")
        self.assertEqual(p["billing"]["bounds_usd"], {"lower": "0.000282", "upper": "0.000342"})
        self.assertEqual(p["billing"]["pricing_verification"], "bounded")
        self.assertEqual(e["receipt"]["cost"]["amount"], "0.000324")
        self.assertEqual(self.validate(e), Decimal("0.000324"))
        for amount in ("0.000281", "0.000343"):
            with self.assertRaises(worker.WorkerError):
                self.exchange("spec_reviewer", response_overrides=lambda r: (writes(r), r["usage"].update(cost=Decimal(amount))))

    def test_known_zero_completion_modality_counters_preserve_text_billing(self):
        def observed_usage_shape(reply):
            usage = reply["usage"]
            usage.update(prompt_tokens=200, completion_tokens=32, total_tokens=232, cost=Decimal("0.000720"))
            usage["completion_tokens_details"].update(audio_tokens=0, image_tokens=0)
        for role in ("specifier", "spec_reviewer"):
            exchange = self.exchange(role, response_overrides=observed_usage_shape)
            self.assertEqual(self.validate(exchange), Decimal("0.000720"))
            usage = exchange["receipt"]["provider"]["usage"]
            self.assertEqual(usage["input_tokens"], 200)
            self.assertEqual(usage["output_tokens"], 32)
            self.assertEqual(usage["reasoning_tokens"], 5)
            self.assertNotIn("audio_tokens", usage)
            self.assertNotIn("image_tokens", usage)

    def test_nonzero_untyped_or_unknown_completion_categories_still_fail_closed(self):
        for field, value in [("audio_tokens", 1), ("image_tokens", 1),
                             ("audio_tokens", False), ("image_tokens", False),
                             ("audio_tokens", 0.0), ("image_tokens", Decimal(0)),
                             ("unknown_zero_category", 0), ("accepted_prediction_tokens", 1),
                             ("rejected_prediction_tokens", 1)]:
            with self.subTest(field=field, value=value):
                def unsupported(reply):
                    reply["usage"]["completion_tokens_details"][field] = value
                with self.assertRaises(provider_config.ProviderConfigError):
                    self.exchange("specifier", response_overrides=unsupported)

    def test_sonnet_cached_read_pin_matches_catalog_and_keeps_drift_errors(self):
        from tests.test_fvs_preflight import endpoint
        document = endpoint(fvs_profile.REVIEWER)
        prices = document["data"]["endpoints"][0]["pricing"]
        prices["input_cache_read"] = "0.0000001"
        inventory = fvs_profile.public_endpoint_inventory(fvs_profile.REVIEWER, document)
        self.assertEqual(inventory["pricing_tiers"][0]["cached"], "0.10")
        for changed in ("0.0000002", "0.00000011"):
            prices["input_cache_read"] = changed
            with self.subTest(price=changed), self.assertRaisesRegex(contracts.ContractError, "price tier drift"):
                fvs_profile.public_endpoint_inventory(fvs_profile.REVIEWER, document)
        prices["input_cache_read"] = "0.0000001"
        prices["unknown_fee"] = 0
        with self.assertRaisesRegex(contracts.ContractError, "unknown price categories"):
            fvs_profile.public_endpoint_inventory(fvs_profile.REVIEWER, document)
        with self.assertRaisesRegex(contracts.ContractError, "metadata is malformed"):
            fvs_profile.public_endpoint_inventory(fvs_profile.REVIEWER, {})

    def test_sonnet_cached_usage_binds_new_reported_cost_without_changing_other_rates(self):
        def cached(reply):
            reply["usage"]["prompt_tokens_details"]["cached_tokens"] = 100
            reply["usage"]["cost"] = Decimal("0.000110")
        exchange = self.exchange("spec_reviewer", response_overrides=cached)
        self.assertEqual(self.validate(exchange), Decimal("0.000110"))
        usage = {"input_tokens": 100, "cached_input_tokens": 100, "cache_write_tokens": 0,
                 "output_tokens": 10, "reasoning_tokens": 5}
        self.assertEqual(fvs_profile.pricing_bounds(fvs_profile.REVIEWER, usage),
                         (Decimal("0.000110"), Decimal("0.000110")))
        self.assertEqual(fvs_profile.profile()["models"][fvs_profile.REVIEWER]["tiers"], [{
            "min_input_tokens": 0, "input": "2", "cached": "0.10", "write_lower": "2.50",
            "write_upper": "4", "output": "10"}])
        self.assertEqual(fvs_profile.profile()["models"][fvs_profile.AUTHOR]["tiers"][1]["cached"], "0.20")

    def test_tiered_reservations_cover_cache_writes_and_billed_reasoning(self):
        for model_id in (fvs_profile.AUTHOR, fvs_profile.REVIEWER):
            for count in (100, 272000, 280000):
                usage = {"input_tokens": count, "cached_input_tokens": 0, "cache_write_tokens": count,
                         "output_tokens": fvs_profile.profile()["models"][model_id]["max_output_tokens"],
                         "reasoning_tokens": 1}
                upper = fvs_profile.pricing_bounds(model_id, usage)[1]
                self.assertGreaterEqual(fvs_profile.reservation(model_id, count), upper)
        low = {"input_tokens": 271999, "cached_input_tokens": 0, "cache_write_tokens": 0, "output_tokens": 1, "reasoning_tokens": 1}
        high = {**low, "input_tokens": 272000}
        self.assertGreater(fvs_profile.pricing_bounds(fvs_profile.AUTHOR, high)[1], fvs_profile.pricing_bounds(fvs_profile.AUTHOR, low)[1])

    def test_unknown_charges_missing_cost_variants_and_output_exhaustion_fail_closed(self):
        mutations = [lambda r: r["usage"].pop("cost"),
                     lambda r: r["usage"].update(cost_details={"unknown_fee": 0}),
                     lambda r: r.update(provider="OpenAI/fast"),
                     lambda r: r.update(service_tier="flex"),
                     lambda r: r["usage"]["completion_tokens_details"].update(audio_tokens=1),
                     lambda r: r["usage"]["prompt_tokens_details"].update(cache_write_tokens=101)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises((contracts.ContractError, worker.WorkerError)):
                self.exchange(response_overrides=mutate)
        with self.assertRaises(provider_config.ProviderConfigError) as error:
            self.exchange("proof_reviewer", response_overrides=lambda r: r["choices"][0].update(finish_reason="length"))
        self.assertEqual(error.exception.classification, "output_exhausted")

    def test_receipt_replay_wrong_role_and_reordered_sequence_are_rejected(self):
        first = self.exchange("specifier")
        self.remember(first)
        second = self.exchange("spec_reviewer")
        self.remember(second)
        reduced = provider_receipts._reduce_exchange_accounting(self.run, self.state, binding=self.binding.public)
        self.assertEqual(reduced["requests"], 2)
        self.assertEqual(reduced["pricing_verification"], "bounded")
        self.assertFalse(reduced["price_reconstruction_exact"])
        self.state["receipts"].reverse()
        with self.assertRaises(worker.WorkerError):
            provider_receipts._reduce_exchange_accounting(self.run, self.state, binding=self.binding.public)
        self.state["receipts"].reverse()
        request = first["request"]
        with self.assertRaises(worker.WorkerError):
            provider_receipts.validate_receipt(first["receipt"], binding=self.binding.public,
                run_id=request["run_id"], sequence=request["sequence"], request_id=request["request_id"],
                model_id=request["model_id"], request_sha256=fvs_profile.digest(request),
                response_sha256=fvs_profile.digest(first["response"]), seen_receipt_sha256={first["receipt"]["receipt_sha256"]})
        second["request"]["role"] = "prover"
        with self.assertRaises(worker.WorkerError):
            provider_receipts._reduce_exchange_accounting(self.run, self.state, binding=self.binding.public)

    def test_signed_failed_request_keeps_upper_liability(self):
        from autofv import provider_service
        e = self.exchange("proof_reviewer")
        request = e["request"]
        messages = [{"role": "system", "content": "synthetic offline protocol"}, {"role": "user", "content": "synthetic offline request"}]
        request["input_hashes"] = sorted(set(request["input_hashes"] + [provider_transport.messages_sha256(messages)]))
        provider_transport.stage_messages(self.run, request, messages)
        amount = provider_transport.reservation_usd(self.run, request, messages)
        self.state["pending_model_exchanges"][request["request_id"]] = {"request": request, "reservation_usd": f"{amount:.6f}", "dispatch_state": "dispatched"}
        with mock.patch("autofv.provider_service.preflight.authorize_provider_action", return_value={}), \
             mock.patch("autofv.provider_transport.provider_round", side_effect=provider_config.ProviderConfigError("synthetic timeout", classification="timeout")):
            with self.assertRaises(provider_config.ProviderConfigError):
                provider_service.dispatch(self.run, request, run_token="synthetic-fvs-run-token")
        reduced = provider_receipts.reduce_incomplete_accounting(self.run, self.state, binding=self.binding)
        self.assertTrue(reduced["unknown_provider_spend"])
        self.assertEqual(reduced["cost"], amount)
        self.assertEqual(reduced["unresolved_requests"][0]["reservation_usd"], f"{amount:.6f}")

    def test_packet_byte_hash_paths_missing_surfaces_drift_and_exact_overlay(self):
        p = packet()
        self.assertEqual(fvs_packet.validate_packet(p), p)
        snapshot = fvs_packet.review_snapshot(p, path=PATH, patch=patch(SPEC))
        self.assertEqual(snapshot["overlay"]["content"], SPEC)
        self.assertEqual(snapshot["original_packet"], p)
        for bad in ("../private", ".hidden/Lean.lean", "a/../Types.lean", "proof-engineering/a.md"):
            with self.assertRaises(ValueError):
                fvs_packet.safe_path(bad)
        altered = copy.deepcopy(p)
        altered["sources"][0]["content"] += "-- drift\n"
        altered["packet_sha256"] = fvs_profile.digest({k: v for k, v in altered.items() if k != "packet_sha256"})
        with self.assertRaises(ValueError):
            fvs_packet.validate_packet(altered)
        p, preparation, rust_root = self.bound_packet()
        fvs_packet.bind_original(p, prepared_root=self.root, preparation=preparation, source_paths=[PATH], rust_root=rust_root)
        (self.root / PATH).write_text(ORIGINAL + "-- drift\n")
        with self.assertRaises(ValueError):
            fvs_packet.bind_original(p, prepared_root=self.root, preparation=preparation, source_paths=[PATH], rust_root=rust_root)
        (self.root / PATH).unlink()
        (self.root / PATH).symlink_to(self.root / "Types.lean")
        with self.assertRaises(ValueError):
            fvs_packet.bind_original(p, prepared_root=self.root, preparation=preparation, source_paths=[PATH], rust_root=rust_root)
        with self.assertRaises(ValueError):
            fvs_packet.apply_patch(ORIGINAL + "-- drift first\n", PATH, patch(SPEC).replace("def increment", "def wrong"))

    def test_fvs_request_uses_only_advertised_provider_parameters(self):
        # Default-provider metadata advertises these controls, not parallel_tool_calls.
        supported = {"reasoning", "include_reasoning", "seed", "max_tokens", "response_format",
                     "structured_outputs", "tools", "tool_choice", "verbosity", "reasoning_effort"}
        for model_id in (fvs_profile.AUTHOR, fvs_profile.REVIEWER):
            upstream = provider_transport._upstream_request(self.binding, {"model_id": model_id},
                [{"role": "user", "content": "synthetic request"}])
            controls = set(upstream) - {"model", "messages", "stream", "provider"}
            self.assertLessEqual(controls, supported)
            self.assertNotIn("parallel_tool_calls", upstream)
            self.assertEqual(upstream["reasoning"], {"effort": "xhigh", "exclude": True})
            self.assertTrue(upstream["provider"]["require_parameters"])
            self.assertFalse(upstream["provider"]["allow_fallbacks"])
            self.assertEqual(upstream["tool_choice"], "required" if model_id == fvs_profile.AUTHOR else "auto")
            self.assertEqual(upstream["max_tokens"], 16384)

    def test_parallel_provider_reply_retains_only_the_first_validated_tool_call(self):
        def add_discarded_call(reply):
            second = copy.deepcopy(reply["choices"][0]["message"]["tool_calls"][0])
            second["id"] = "discarded-second-call"
            second["function"]["name"] = "unapproved-second-tool"
            reply["choices"][0]["message"]["tool_calls"].append(second)
        exchange = self.exchange("specifier", response_overrides=add_discarded_call)
        self.assertEqual(exchange["response"]["kind"], "tool_call")
        self.assertEqual(exchange["response"]["payload"]["name"], "read_allowed")
        self.assertNotIn("unapproved-second-tool", json.dumps(exchange["response"]))
        self.assertNotIn("discarded-second-call", json.dumps(exchange["response"]))
        self.assertEqual(self.validate(exchange), Decimal("0.000300"))

    def test_sonnet_auto_tool_choice_is_bound_without_relaxing_submission(self):
        for role, choice in (("specifier", "required"), ("spec_reviewer", "auto"), ("proof_reviewer", "auto")):
            exchange = self.exchange(role)
            upstream = provider_transport._upstream_request(self.binding, exchange["request"],
                [{"role": "user", "content": "synthetic"}])
            self.assertEqual(upstream["tool_choice"], choice)
            self.assertEqual(exchange["receipt"]["provider"]["requested_tool_choice"], choice)
            self.assertEqual(self.validate(exchange), Decimal("0.000300"))
            forged = copy.deepcopy(exchange)
            forged["receipt"]["provider"]["requested_tool_choice"] = "required" if choice == "auto" else "auto"
            with self.assertRaises(worker.WorkerError):
                self.validate(forged)
        def prose_only(reply):
            reply["choices"][0]["message"].pop("tool_calls")
            reply["choices"][0]["message"]["content"] = PASS
        with self.assertRaises(provider_config.ProviderConfigError):
            self.exchange("spec_reviewer", response_overrides=prose_only)

    def test_direct_routing_excludes_openai_price_variants(self):
        # OpenRouter base slugs match all endpoints of that provider, not only the bare tag.
        routing = fvs_profile.requested_routing(fvs_profile.AUTHOR)
        advertised = ["openai", "openai/flex", "openai/fast", "openai/ultrafast", "azure"]
        eligible = [tag for tag in advertised
            if any(tag == allowed or tag.startswith(allowed + "/") for allowed in routing["only"])
            and tag not in routing.get("ignore", [])]
        self.assertEqual(eligible, ["openai"])
        self.assertFalse(routing["allow_fallbacks"])
        self.assertTrue(routing["require_parameters"])

    def test_sol_catalog_excludes_forbidden_variants_and_rejects_unknown_routes(self):
        from tests.test_fvs_preflight import endpoint
        document = endpoint(fvs_profile.AUTHOR)
        default = document["data"]["endpoints"][0]
        forbidden = ["openai/fast", "openai/flex", "openai/ultrafast"]
        for tag in forbidden:
            variant = copy.deepcopy(default)
            variant.update(tag=tag, pricing={"unapproved_fee": "99"})
            document["data"]["endpoints"].append(variant)
        inventory = fvs_profile.public_endpoint_inventory(fvs_profile.AUTHOR, document)
        self.assertEqual(inventory["matching_endpoint_slugs"], ["openai"])
        self.assertEqual(inventory["ignored_endpoint_slugs"], forbidden)
        old_profile = fvs_profile.profile()
        old_profile["models"][fvs_profile.AUTHOR]["ignored_endpoints"] = forbidden[:-1]
        with self.assertRaisesRegex(contracts.ContractError, "profile drift"):
            fvs_profile.validate_profile(old_profile)
        unknown = copy.deepcopy(default)
        unknown["tag"] = "openai/unapproved-new-variant"
        document["data"]["endpoints"].append(unknown)
        with self.assertRaisesRegex(contracts.ContractError, "ambiguous eligible variants"):
            fvs_profile.public_endpoint_inventory(fvs_profile.AUTHOR, document)
        document["data"]["endpoints"] = document["data"]["endpoints"][1:-1]
        with self.assertRaisesRegex(contracts.ContractError, "ambiguous eligible variants"):
            fvs_profile.public_endpoint_inventory(fvs_profile.AUTHOR, document)

    def test_runtime_binder_rejects_rehashed_rust_without_trusted_bytes(self):
        p = packet()
        for item in p["sources"]:
            if item["surface"] != "rust":
                (self.root / item["path"]).write_text(item["content"])
        preparation = {"source": IDENTITY, "files": [
            {"path": s["path"], "sha256": s["sha256"]}
            for s in p["sources"] if s["surface"] != "rust"]}
        p["sources"][1] = fvs_packet.source("rust/increment.rs", "rust",
            "pub fn increment(n: u64) -> u64 { n + 99 }\n")
        p["packet_sha256"] = fvs_profile.digest({k: v for k, v in p.items() if k != "packet_sha256"})
        self.assertEqual(fvs_packet.validate_packet(p), p)
        with self.assertRaises(contracts.ContractError):
            fvs_packet.bind_original(p, prepared_root=self.root,
                preparation=preparation, source_paths=[PATH])

    def test_runtime_binds_rust_to_real_git_and_rejects_rehashed_substitution(self):
        p, preparation, rust_root = self.bound_packet()
        def bind(value):
            return fvs_packet.bind_original(value, prepared_root=self.root,
                preparation=preparation, source_paths=[PATH], rust_root=rust_root)
        self.assertEqual(bind(p), p)
        forged = copy.deepcopy(p)
        forged["sources"][1] = fvs_packet.source("rust/increment.rs", "rust",
            "pub fn increment(n: u64) -> u64 { n + 99 }\n")
        forged["packet_sha256"] = fvs_profile.digest({k: v for k, v in forged.items() if k != "packet_sha256"})
        self.assertEqual(fvs_packet.validate_packet(forged), forged)
        with self.assertRaisesRegex(contracts.ContractError, "pinned public Rust bytes"):
            bind(forged)
        # Matching forged packet and dirty checkout still cannot override the pinned commit.
        (rust_root / "increment.rs").write_text(forged["sources"][1]["content"])
        with self.assertRaisesRegex(contracts.ContractError, "pinned revision"):
            bind(forged)
        (rust_root / "increment.rs").unlink()
        (rust_root / "increment.rs").symlink_to(self.root / "Intent.md")
        with self.assertRaisesRegex(contracts.ContractError, "symlink"):
            bind(p)

    def test_runtime_rejects_rust_provenance_drift_and_git_replacement(self):
        p, preparation, rust_root = self.bound_packet()
        def bind():
            return fvs_packet.bind_original(p, prepared_root=self.root,
                preparation=preparation, source_paths=[PATH], rust_root=rust_root)
        def git(*args, **kwargs):
            return subprocess.run(["git", "-C", str(rust_root), *args],
                check=True, capture_output=True, text=True, **kwargs).stdout.strip()
        git("remote", "set-url", "origin", "https://example.invalid/wrong")
        with self.assertRaisesRegex(contracts.ContractError, "provenance mismatch"):
            bind()
        git("remote", "set-url", "origin", IDENTITY["repository"])
        identity = {**p["source_identity"], "revision": "0" * 40}
        bad = {**p, "source_identity": identity}
        bad["packet_sha256"] = fvs_profile.digest({k: v for k, v in bad.items() if k != "packet_sha256"})
        with self.assertRaisesRegex(contracts.ContractError, "provenance mismatch"):
            fvs_packet.bind_original(bad, prepared_root=self.root,
                preparation={**preparation, "source": identity}, source_paths=[PATH], rust_root=rust_root)
        forged_text = "pub fn increment(n: u64) -> u64 { n + 99 }\n"
        original_blob = git("rev-parse", p["source_identity"]["revision"] + ":curve25519-dalek/src/increment.rs")
        replacement = git("hash-object", "-w", "--stdin", input=forged_text)
        git("replace", original_blob, replacement)
        # A replace ref must not change authenticated source, even at the same commit ID.
        self.assertEqual(bind(), p)
        (rust_root / "increment.rs").write_text(forged_text)
        with self.assertRaisesRegex(contracts.ContractError, "pinned revision"):
            bind()

    def test_forged_rust_is_rejected_before_worker_or_provider_setup(self):
        p, preparation, rust_root = self.bound_packet()
        cfg = config()
        cfg["source_packet"] = copy.deepcopy(p)
        cfg["source_packet"]["sources"][1] = fvs_packet.source("rust/increment.rs", "rust", "pub fn wrong() {}\n")
        cfg["source_packet"]["packet_sha256"] = fvs_profile.digest({k: v for k, v in cfg["source_packet"].items() if k != "packet_sha256"})
        cfg_path = self.root / "run.json"
        cfg_path.write_bytes(contracts.canonical_json_bytes(cfg) + b"\n")
        # Synthetic preparation plumbing; exercise the real configuration/binder boundary.
        with (mock.patch.object(experiment, "validate_target", return_value=(self.root, {})),
              mock.patch.object(experiment, "_load_prepared_inputs", return_value=(preparation, {"source_paths": {"n": PATH}}, {}, {})),
              mock.patch.object(experiment, "_persist_unallocated_attempt", side_effect=lambda *a, **kw: kw) as persisted,
              mock.patch.object(worker, "prepare_run") as worker_setup,
              mock.patch.object(experiment.provider_service, "start") as provider_setup):
            result = experiment.run_experiment(self.root, cfg_path,
                preparation_manifest=cfg_path, probe_rust_evidence=cfg_path,
                probe_aeneas_evidence=cfg_path, dependency_cache=cfg_path,
                execution_mode="full", verifier_reference=cfg_path, public_rust_root=rust_root)
        self.assertEqual(result["reason"], "prepared_inputs_invalid")
        self.assertIn("pinned public Rust bytes", str(result["detail"]))
        persisted.assert_called_once()
        worker_setup.assert_not_called()
        provider_setup.assert_not_called()

    def test_valid_fvs_preflight_authenticates_public_rust_before_sealed_checks(self):
        from autofv import preflight_runner
        from tests.test_preflight_cli import _runner_raw
        p, preparation, rust_root = self.bound_packet()
        cfg = {**config(), "source_packet": p}
        cfg_path = self.root / "run.json"
        cfg_path.write_bytes(contracts.canonical_json_bytes(cfg) + b"\n")
        provider_config.abort_configuration(self.run)
        self.run.update(preparation_manifest=preparation, source_packet_sha256=p["packet_sha256"],
            snapshot_sha256=worker.hash_tree(self.root),
            manifest_sha256=hashlib.sha256(contracts.canonical_json_bytes({})).hexdigest())
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        collected = subprocess.CompletedProcess((), 0, _runner_raw(), b"")
        with (tempfile.TemporaryDirectory() as output,
              mock.patch("autofv.contracts.validate_target", return_value=(self.root, {})),
              mock.patch("autofv.prepare_dalek._scan_prepared"),
              mock.patch.object(preflight_runner, "_probe_distinct_verifier", return_value="lima:synthetic-verifier"),
              mock.patch.object(worker_runtime, "_docker", side_effect=[completed, completed, collected, completed]) as docker,
              mock.patch.object(worker, "force_destroy_worker") as destroy,
              mock.patch.object(provider_transport, "_open_upstream", side_effect=AssertionError("no live provider")) as upstream,
              mock.patch.object(fvs_packet, "bind_original", wraps=fvs_packet.bind_original) as bind):
            result = preflight_runner.authorize_prepared_run(self.run, self.root, cfg_path,
                Path(output) / "bundle", env_file=self.root / "providers.env",
                max_age_seconds=300, public_rust_root=rust_root)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(bind.call_args.kwargs["rust_root"], rust_root)
        self.assertEqual(docker.call_count, 4)
        upstream.assert_not_called()
        destroy.assert_not_called()

    def test_fvs_preflight_rejects_public_rust_drift_before_guest_checks(self):
        from autofv import preflight_runner
        p, preparation, rust_root = self.bound_packet()
        cfg_path = self.root / "run.json"
        cfg_path.write_bytes(contracts.canonical_json_bytes({**config(), "source_packet": p}) + b"\n")
        self.run["preparation_manifest"] = preparation
        (rust_root / "increment.rs").write_text("pub fn wrong() {}\n")
        with (tempfile.TemporaryDirectory() as output,
              mock.patch("autofv.contracts.validate_target", return_value=(self.root, {})),
              mock.patch("autofv.prepare_dalek._scan_prepared"),
              mock.patch.object(worker_runtime, "_docker") as docker,
              mock.patch.object(preflight_runner, "configure_prepared_provider") as provider,
              self.assertRaisesRegex(contracts.ContractError, "pinned revision")):
            preflight_runner.authorize_prepared_run(self.run, self.root, cfg_path,
                Path(output) / "bundle", env_file=self.root / "providers.env",
                max_age_seconds=300, public_rust_root=rust_root)
        docker.assert_not_called()
        provider.assert_not_called()

    def test_provider_run_forwards_rust_root_through_real_preflight(self):
        from autofv import preflight_runner
        from tests.test_preflight_cli import _runner_raw
        p, preparation, rust_root = self.bound_packet()
        target = self.root / "prepared"
        target.mkdir()
        for item in p["sources"]:
            if item["surface"] != "rust":
                (target / item["path"]).write_text(item["content"])
        cfg_path = self.root / "run.json"
        cfg_path.write_bytes(contracts.canonical_json_bytes({**config(), "source_packet": p}) + b"\n")
        provider_config.abort_configuration(self.run)
        self.run.update(execution_tier="simulation", snapshot_sha256=worker.hash_tree(target),
            manifest_sha256=hashlib.sha256(contracts.canonical_json_bytes({})).hexdigest())
        graph = {"source_paths": {"n": PATH}, "probe_rust_sha256": "a" * 64,
            "probe_aeneas_sha256": "b" * 64, "graph_sha256": "c" * 64}
        identity = {"run_id": self.run["run_id"], "attempt_id": "synthetic-fvs-preflight",
            "attempt_ledger": str(self.root / "attempts.jsonl")}
        completed = subprocess.CompletedProcess((), 0, b"", b"")
        collected = subprocess.CompletedProcess((), 0, _runner_raw(), b"")
        def prepare(*args, before_worker=None, **kwargs):
            if before_worker:
                before_worker(self.run)
            return self.run
        with (mock.patch.object(experiment.results, "new_attempt_identity", return_value=identity),
              mock.patch.object(experiment, "validate_target", return_value=(target, {})),
              mock.patch("autofv.contracts.validate_target", return_value=(target, {})),
              mock.patch("autofv.prepare_dalek._scan_prepared"),
              mock.patch.object(experiment, "_load_prepared_inputs", return_value=(preparation, graph, {}, {})),
              mock.patch.object(worker, "prepare_run", side_effect=prepare),
              mock.patch.object(experiment.verifier, "bind_prepared_reference", return_value={}),
              mock.patch.object(experiment.verifier.counterexample, "external_reference_identity", return_value={}),
              mock.patch.object(experiment, "_bind_provider_selection"),
              mock.patch.object(experiment.provider_service, "start"),
              mock.patch.object(experiment._EXPERIMENT_GRAPH, "stream", return_value=[]),
              mock.patch.object(experiment, "_checkpoint_if_enabled"),
              mock.patch.object(experiment, "_finish_attempt", return_value={"outcome": "success"}) as finish,
              mock.patch.object(preflight_runner, "_probe_distinct_verifier", return_value="lima:synthetic-verifier"),
              mock.patch.object(worker_runtime, "_docker", side_effect=[completed, completed, collected, completed]) as docker,
              mock.patch.object(provider_transport, "_open_upstream", side_effect=AssertionError("no live provider")) as upstream,
              mock.patch.object(fvs_packet, "bind_original", wraps=fvs_packet.bind_original) as bind):
            experiment.run_experiment(target, cfg_path, preparation_manifest=cfg_path,
                probe_rust_evidence=cfg_path, probe_aeneas_evidence=cfg_path,
                dependency_cache=cfg_path, execution_mode="full", verifier_reference=cfg_path,
                env_file=self.root / "providers.env", provider_selection=cfg_path,
                public_rust_root=rust_root)
        self.assertEqual(bind.call_count, 2)
        self.assertTrue(all(call.kwargs["rust_root"] == rust_root for call in bind.call_args_list))
        self.assertEqual(docker.call_count, 4)
        self.assertNotEqual(finish.call_args.kwargs["outcome"], "infrastructure_failed")
        upstream.assert_not_called()

    def test_public_rust_cli_argument_reaches_controller(self):
        with (mock.patch("sys.argv", ["autofv", "run", "target", "--config", "config", "--public-rust-root", "/public/curve25519-dalek/src"]),
              mock.patch.object(experiment, "run_experiment", return_value={"outcome": "success"}) as run,
              mock.patch("builtins.print")):
            experiment.main()
        self.assertEqual(run.call_args.kwargs["public_rust_root"], "/public/curve25519-dalek/src")

    def test_fvs_cap_complete_packet_and_legacy_cap_remain_distinct(self):
        value = {"source": "x" * 100000}
        with self.assertRaises(worker.WorkerError):
            agent_lane.role_context_sha256(value)
        self.assertEqual(len(agent_lane.role_context_sha256(value, methodology=agent_lane._FVS_METHODOLOGY)), 64)
        with self.assertRaises(worker.WorkerError):
            agent_lane.role_context_sha256({"source": "x" * 262144}, methodology=agent_lane._FVS_METHODOLOGY)
        path = self.root / "run.json"
        path.write_bytes(contracts.canonical_json_bytes(config()) + b"\n")
        self.assertEqual(contracts.validate_run_config(path)[1]["role_profile"], fvs_profile.PROFILE_ID)
        path.write_text(json.dumps(config(), indent=2))
        with self.assertRaises(ValueError):
            contracts.validate_run_config(path)

    def test_fvs_outside_packet_read_returns_no_data_refusal(self):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        job = generic_role_runtime._role_job(self.state, graph, lane, "spec_reviewer", statement_sha256="e" * 64,
            contract_fingerprint="f" * 64, input_hashes=["e" * 64], role_context={"source_packet": packet()})
        callbacks = {k: mock.Mock(side_effect=AssertionError("No ambient operation permitted"))
                     for k in ("read_file", "search_files", "edit_assigned", "check_lean")}
        tools = agent_lane.build_lane_tools(job, **callbacks)
        denied = agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": "NotInPacket.lean"})
        self.assertEqual(denied, "read_denied: path outside the frozen packet allowlist; use exact source_packet source paths. "
                                 "If relevant source is missing, report BLOCKED. No extra read was performed.")
        self.assertNotIn("NotInPacket", denied)
        self.assertEqual(agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": PATH}), ORIGINAL)
        self.assertIn("read_only_role", agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": "synthetic"}))
        self.assertIn("read_only_role", agent_lane.invoke_lane_tool(tools, "check_lean", {}))
        for callback in callbacks.values():
            callback.assert_not_called()
        for unsafe in ("/absolute/No.lean", "../No.lean", "No/../Other.lean"):
            with self.subTest(unsafe=unsafe), self.assertRaises(worker.WorkerError):
                agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": unsafe})
        for malformed in ({}, {"path": None}, {"path": PATH, "extra": True}):
            with self.subTest(malformed=malformed), self.assertRaises(worker.WorkerError):
                agent_lane.invoke_lane_tool(tools, "read_allowed", malformed)
        with mock.patch.object(fvs_packet, "validate_view", return_value={}):
            with self.assertRaisesRegex(worker.WorkerError, "FVS read lacks immutable packet source"):
                agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": PATH})
        with mock.patch.object(fvs_packet, "validate_view", side_effect=contracts.ContractError("synthetic packet integrity failure")):
            with self.assertRaisesRegex(contracts.ContractError, "packet integrity"):
                agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": PATH})
        for callback in callbacks.values():
            callback.assert_not_called()

    def test_legacy_outside_allowlist_read_remains_fatal(self):
        from tests.test_agent_lane import _job
        callbacks = {k: mock.Mock(side_effect=AssertionError("No ambient operation permitted"))
                     for k in ("read_file", "search_files", "edit_assigned", "check_lean")}
        tools = agent_lane.build_lane_tools(_job(), **callbacks)
        with self.assertRaisesRegex(worker.WorkerError, "read path is not allowlisted"):
            agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": "NotInPacket.lean"})
        for callback in callbacks.values():
            callback.assert_not_called()

    def test_fresh_read_only_review_blocks_patch_substitution_and_diagnostics(self):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        author = {"patch": patch(SPEC)}
        snapshot = fvs_packet.review_snapshot(packet(), path=PATH, patch=author["patch"])
        job = generic_role_runtime._role_job(self.state, graph, lane, "spec_reviewer", statement_sha256="e" * 64,
            contract_fingerprint="f" * 64, input_hashes=["e" * 64], role_context={"source_packet": snapshot, "reviewed_candidate": author})
        callbacks = {k: mock.Mock() for k in ("read_file", "search_files", "edit_assigned", "check_lean")}
        tools = agent_lane.build_lane_tools(job, **callbacks)
        self.assertEqual(tools["read_allowed"]["invoke"]({"path": PATH}), SPEC)
        self.assertIn("read_only_role", tools["edit_assigned"]["invoke"]({"patch": patch(PROOF)}))
        self.assertIn("read_only_role", tools["check_lean"]["invoke"]({}))
        with self.assertRaises(worker.WorkerError):
            tools["submit_candidate"]["invoke"]({"patch": patch(PROOF), "claimed_status": "candidate", "evidence": [PASS]})
        reviewed = tools["submit_candidate"]["invoke"]({"patch": patch(SPEC), "claimed_status": "candidate", "evidence": [PASS]})
        self.assertEqual(reviewed["patch"], author["patch"])
        for callback in callbacks.values():
            callback.assert_not_called()
        fresh = copy.deepcopy(job)
        fresh["role_context"]["stage"] = "next-fresh-round"
        self.assertNotEqual(agent_lane.role_conversation_spec(job)["conversation_id"], agent_lane.role_conversation_spec(fresh)["conversation_id"])

    def test_malformed_empty_forged_pass_and_proof_statement_edits_fail(self):
        for raw in ("", "VERDICT: PASS", PASS + "\nVERDICT: PASS", PASS.replace("## Evidence", "## Missing evidence"),
                    PASS.replace("Vacuity:", "Ignored:"), REVISE.replace("VERDICT: REVISE", "VERDICT: PASS")):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                fvs_adapter.parse_review(raw)
        self.assertEqual(fvs_adapter.parse_review(PASS)["verdict"], "PASS")
        fvs_adapter.proof_scope(SPEC, PROOF, canon=CANON)
        with self.assertRaises(ValueError):
            fvs_adapter.proof_scope(SPEC, PROOF.replace("increment n", "n"), canon=CANON)
        with self.assertRaises(ValueError):
            fvs_adapter.proof_scope(SPEC, SPEC, canon=CANON)
        longer = SPEC.replace("sorry", "first\n  second\n  third\n  fourth")
        fvs_adapter.proof_scope(SPEC, longer, canon=CANON)

    def test_selection_requires_both_models_and_rejects_old_single_model_record(self):
        fields = {"model_id", "endpoint", "endpoint_sha256", "parameters", "pricing", "pricing_sha256",
                  "tool_schema_sha256", "capability_sha256", "fixed_proxy_sha256", "proxy_id", "route_id",
                  "role_profile", "role_profile_sha256", "source_packet_sha256"}
        accessibility = {}
        for role in ("specifier", "spec_reviewer"):
            e = self.exchange(role)
            self.remember(e)
            body = {"schema": provider_receipts.PROVIDER_PREFLIGHT_SCHEMA, "provider_binding": self.binding.public, **{k: e[k] for k in ("request", "response", "receipt")}}
            record = {**body, "preflight_sha256": fvs_profile.digest(body)}
            accessibility[e["request"]["model_id"]] = {"provider_preflight": record,
                "supported_parameters": ["reasoning", "tools", "tool_choice"], "supported_efforts": ["xhigh"], "catalog_sha256": "1" * 64,
                "endpoint_inventory": {"routing_slug": fvs_profile.profile()["models"][e["request"]["model_id"]]["provider"],
                    "matching_endpoint_slugs": [fvs_profile.profile()["models"][e["request"]["model_id"]]["provider"]],
                    "ignored_endpoint_slugs": fvs_profile.profile()["models"][e["request"]["model_id"]]["ignored_endpoints"],
                    "supported_tool_choices": ["auto", "none"] if role == "spec_reviewer" else ["auto", "function", "none", "required"],
                    "pricing_tiers": fvs_profile.profile()["models"][e["request"]["model_id"]]["tiers"]}}
        selection = {"schema": "autofv-retained-model-selection/v2", "status": "selected", "selected_at": "synthetic", "selected_by": "fixture",
            "decision": "select-model", "scope": {"proof_smoke": True, "full_retained_run": True,
                "provider_request_authorized": False, "spend_authorized": False, "push_authorized": False,
                "dynamic_routing_allowed": False, "model_substitution_allowed": False},
            "model": {k: self.binding.public[k] for k in fields}, "accessibility_evidence": accessibility,
            "constraints": {}, "verification": {}}
        path = self.root / "selection.json"
        path.write_bytes(contracts.canonical_json_bytes(selection) + b"\n")
        experiment._bind_provider_selection(self.run, path)
        for mutation in (lambda s: s["accessibility_evidence"].pop(fvs_profile.REVIEWER),
                         lambda s: s["accessibility_evidence"][fvs_profile.REVIEWER].update(supported_efforts=["high"]),
                         lambda s: s["model"].update(source_packet_sha256="0" * 64),
                         lambda s: s["accessibility_evidence"][fvs_profile.AUTHOR]["endpoint_inventory"].update(matching_endpoint_slugs=["openai", "openai/flex"]),
                         lambda s: s["accessibility_evidence"][fvs_profile.AUTHOR]["endpoint_inventory"].update(matching_endpoint_slugs=["openai", "openai/future-variant"]),
                         lambda s: s["accessibility_evidence"][fvs_profile.AUTHOR]["endpoint_inventory"].update(ignored_endpoint_slugs=[]),
                         lambda s: s["accessibility_evidence"][fvs_profile.REVIEWER]["endpoint_inventory"].update(supported_tool_choices=["none"]),
                         lambda s: s["accessibility_evidence"][fvs_profile.AUTHOR]["endpoint_inventory"].update(supported_tool_choices=["auto", "none"])):
            bad = copy.deepcopy(selection)
            mutation(bad)
            path.write_bytes(contracts.canonical_json_bytes(bad) + b"\n")
            with self.assertRaises(ValueError):
                experiment._bind_provider_selection(self.run, path)
        old = copy.deepcopy(selection)
        old["schema"] = "autofv-retained-model-selection/v1"
        for k in ("role_profile", "role_profile_sha256", "source_packet_sha256"):
            old["model"].pop(k)
        path.write_bytes(contracts.canonical_json_bytes(old) + b"\n")
        with self.assertRaises(ValueError):
            experiment._bind_provider_selection(self.run, path)

    def test_readonly_research_missing_git_header_still_refused_after_eight_reads(self):
        # Replay cb21bda9's syntax failure with synthetic, genuinely unchanged source.
        original = "-- synthetic padding\n" * 80 + "-- synthetic context\n" * 6
        missing_header = (f"--- a/{PATH}\n+++ b/{PATH}\n@@ -81,6 +81,6 @@\n"
                          + " -- synthetic context\n" * 6)
        complete = f"diff --git a/{PATH} b/{PATH}\n" + missing_header
        self.assertEqual(fvs_packet.apply_patch(original, PATH, complete), original)
        source_packet = packet()
        source_packet["sources"][0] = fvs_packet.source(PATH, "lean", original)
        source_packet["packet_sha256"] = fvs_profile.digest({
            k: v for k, v in source_packet.items() if k != "packet_sha256"})
        job = generic_role_runtime._role_job(self.state,
            {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64},
            {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}, "scout",
            statement_sha256="e" * 64, contract_fingerprint="f" * 64, input_hashes=[source_packet["packet_sha256"]],
            role_context={"source_packet": source_packet})
        forbidden = mock.Mock(side_effect=AssertionError("research must not access mutable source"))
        tools = agent_lane.build_lane_tools(job, read_file=forbidden, search_files=forbidden,
                                           edit_assigned=forbidden, check_lean=forbidden)
        for _ in range(4):
            self.assertEqual(agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": PATH}), original)
            self.assertIn("synthetic context", agent_lane.invoke_lane_tool(
                tools, "search_allowed", {"query": "synthetic context"}))
        with self.assertRaisesRegex(worker.PatchRejected, "candidate must modify exactly its assigned file"):
            agent_lane.invoke_lane_tool(tools, "submit_candidate", {
                "patch": missing_header, "claimed_status": "candidate", "evidence": ["Synthetic research only."]})
        forbidden.assert_not_called()

    def test_readonly_research_patch_replays_frozen_views_and_is_role_scoped(self):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        original = packet()
        overlay = fvs_packet.source(PATH, "lean", ORIGINAL + "-- accepted synthetic dependency ∃\n")
        binding = {"schema": "autofv-fvs-lane-generation/v1", "run_id": self.run["run_id"],
            "node": "helper", "graph_sha256": graph["graph_sha256"], "original_base_commit": "c" * 40,
            "original_packet_sha256": original["packet_sha256"], "dependencies": ["dependency"],
            "accepted_nodes": ["dependency"], "accepted_commit": "a" * 40, "accepted_tree_sha256": "b" * 64,
            "frozen_contracts_sha256": "e" * 64, "dependency_report_hashes": {"dependency": "f" * 64},
            "source_hashes": {s["path"]: (overlay if s["path"] == PATH else s)["sha256"]
                              for s in original["sources"] if s["surface"] != "rust"}}
        binding["generation_sha256"] = fvs_profile.digest(binding)
        dependency = fvs_packet.dependency_snapshot(original, binding, [overlay])
        research_roles = {"scout", "dependency_planner", "verification_adviser"}
        for baseline in (original, dependency):
            active_lane = dict(lane)
            if baseline is dependency:
                active_lane.update(generation_sha256=binding["generation_sha256"], base_commit=binding["accepted_commit"])
                self.state["fvs_lane_generations"] = {"helper": {
                    "phase": "ready", "binding": binding, "packet": dependency}}
            source = fvs_packet.validate_view(baseline)[PATH]["content"]
            for reviewed in (None, {"patch": patch(source + "-- reviewed synthetic candidate\n", source)}):
                for role in fvs_profile.ROLE_MODELS:
                    with self.subTest(view=baseline["schema"], review=reviewed is not None, role=role):
                        jobs = []
                        def capture(state, graph, lane, role, **kwargs):
                            jobs.append(agent_lane.validate_role_job(
                                generic_role_runtime._role_job(state, graph, lane, role, **kwargs)))
                            raise RuntimeError("captured before dispatch")
                        stages = fvs_adapter.Stages(self.state, graph, active_lane, capture, lambda *a: None)
                        before = copy.deepcopy(baseline)
                        # Reserved DATA is assigned after caller context, never copied from it.
                        context = {"readonly_research_patch": patch(SPEC)} if role in research_roles else {}
                        with self.assertRaisesRegex(RuntimeError, "captured before dispatch"):
                            stages.invoke(role, "synthetic-context", candidate=reviewed,
                                          context=context, fingerprint="e" * 64)
                        job = jobs[0]
                        role_context = job["role_context"]
                        self.assertEqual(baseline, before)
                        if role not in research_roles:
                            self.assertNotIn("readonly_research_patch", role_context)
                            if role in fvs_profile.REVIEW_ROLES:
                                self.assertEqual(role_context["reviewed_candidate"], reviewed)
                            continue
                        offered = role_context["readonly_research_patch"]
                        self.assertEqual(offered, f"diff --git a/{PATH} b/{PATH}\n--- a/{PATH}\n+++ b/{PATH}\n@@ -0,0 +0,0 @@\n")
                        frozen = fvs_packet.validate_view(role_context["source_packet"])[PATH]["content"]
                        self.assertEqual(fvs_packet.apply_patch(frozen, PATH, offered).encode(), frozen.encode())
                        forbidden = mock.Mock(side_effect=AssertionError("research has no mutable tools"))
                        tools = agent_lane.build_lane_tools(job, read_file=forbidden, search_files=forbidden,
                                                           edit_assigned=forbidden, check_lean=forbidden)
                        self.assertEqual(len(agent_lane.capture_tool_schemas(tools)), 5)
                        self.assertEqual(agent_lane.invoke_lane_tool(tools, "read_allowed", {"path": PATH}), frozen)
                        for tool, args in (("edit_assigned", {"patch": patch(SPEC)}), ("check_lean", {})):
                            self.assertTrue(agent_lane.invoke_lane_tool(tools, tool, args).startswith("read_only_role:"))
                        submitted = agent_lane.invoke_lane_tool(tools, "submit_candidate", {
                            "patch": offered, "claimed_status": "candidate", "evidence": ["Synthetic inventory."]})
                        self.assertEqual(agent_lane.validate_candidate(submitted, job), submitted)
                        rerouted = copy.deepcopy(submitted)
                        rerouted["patch"] = offered.replace(PATH, "Other.lean")
                        with self.assertRaises(worker.PatchRejected):
                            agent_lane.validate_candidate(rerouted, job)
                        for invalid in ("", offered.split("@@")[0]):
                            with self.assertRaises((contracts.ContractError, worker.WorkerError)):
                                fvs_packet.apply_patch(frozen, PATH, invalid)
                        changed_job = copy.deepcopy(job)
                        changed_job["role_context"]["readonly_research_patch"] += "\n"
                        with self.assertRaisesRegex(worker.WorkerError, "role context mismatch"):
                            agent_lane.validate_candidate(submitted, changed_job)
                        messages = agent_lane.initial_role_messages(agent_lane.role_conversation_spec(job))
                        self.assertNotIn(offered, messages[0]["content"])
                        self.assertIn("copy readonly_research_patch unchanged", messages[0]["content"])
                        self.assertEqual(json.loads(messages[1]["content"])["context"]["role_context"]["readonly_research_patch"], offered)
                        forbidden.assert_not_called()
        generic = copy.deepcopy(self.state)
        generic["config"] = {}
        job = generic_role_runtime._role_job(generic, graph, lane, "scout",
            statement_sha256="e" * 64, contract_fingerprint="f" * 64, input_hashes=["a" * 64],
            role_context={"stage": "synthetic-generic"})
        self.assertNotIn("readonly_research_patch", job["role_context"])
        self.assertNotIn("readonly_research_patch", agent_lane.role_conversation_spec(job)["system_prompt"])

    def test_readonly_research_patch_survives_authenticated_stages_and_explicit_submission(self):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        jobs = []
        def run_role(state, graph, lane, role, **kwargs):
            jobs.append(generic_role_runtime._role_job(state, graph, lane, role, **kwargs))
            return generic_role_runtime._run_role_lane(state, graph, lane, role, **kwargs)
        stages = fvs_adapter.Stages(self.state, graph, lane, run_role, lambda *a: None)
        original = copy.deepcopy(self.state["config"]["source_packet"])
        turns = {}
        def synthetic_round(state, **kwargs):
            role = kwargs["role"]
            turn = turns[role] = turns.get(role, 0) + 1
            visible = json.loads(kwargs["messages"][1]["content"])["context"]["role_context"]
            offered = visible["readonly_research_patch"]
            self.assertEqual(visible, jobs[-1]["role_context"])
            self.assertIn(fvs_profile.digest(visible), kwargs["input_hashes"])
            if role == "scout" and turn <= 8:
                name, arguments = ("read_allowed", {"path": PATH}) if turn % 2 else ("search_allowed", {"query": "increment"})
                self.assertNotIn("helper:synthetic-" + role, self.state["fvs_evidence"])
            else:
                name, arguments = "submit_candidate", {"patch": offered, "claimed_status": "candidate",
                                                       "evidence": ["Synthetic research inventory; no acceptance."]}
            def respond(reply):
                reply["choices"][0]["message"]["tool_calls"][0]["function"] = {
                    "name": name, "arguments": json.dumps(arguments)}
            e = self.exchange(role, input_hashes=kwargs["input_hashes"], response_overrides=respond)
            self.remember(e)
            return e["response"], e["receipt"]
        forbidden = mock.Mock(side_effect=AssertionError("research cannot read/write/check/accept mutable sources"))
        with (mock.patch("autofv.model._model_request", side_effect=synthetic_round),
              mock.patch.multiple(worker, read_lane_file=forbidden, search_lane_files=forbidden,
                                  edit_lane_file=forbidden, check_lane=forbidden,
                                  save_lane_snapshot=forbidden, accept_candidate=forbidden)):
            for role in ("scout", "dependency_planner", "verification_adviser"):
                result = stages.invoke(role, "synthetic-" + role, fingerprint="e" * 64)
                job = jobs[-1]
                self.assertEqual(agent_lane.validate_candidate(result, job), result)
                self.assertEqual(result["patch"], job["role_context"]["readonly_research_patch"])
                self.assertEqual(fvs_packet.apply_patch(ORIGINAL, PATH, result["patch"]), ORIGINAL)
                entry = stages.entries["helper:synthetic-" + role]
                self.assertEqual(entry["stage_context"]["readonly_research_patch"], result["patch"])
                self.assertEqual(entry["fresh_conversation"], fvs_profile.digest(job["role_context"]))
                self.assertEqual(len(entry["invocation_receipts"]), 9 if role == "scout" else 1)
            # Merely providing DATA is not a submission and cannot finish a stage.
            with mock.patch("autofv.model._model_request", side_effect=worker.TransientProviderError("synthetic no submission")):
                with self.assertRaisesRegex(worker.TransientProviderError, "synthetic no submission"):
                    stages.invoke("scout", "synthetic-not-submitted", fingerprint="e" * 64)
            self.assertNotIn("helper:synthetic-not-submitted", stages.entries)
        forbidden.assert_not_called()
        self.assertEqual(self.state["config"]["source_packet"], original)
        self.assertEqual(self.state["accepted"], {"accepted_commit": "c" * 40})
        self.assertEqual(turns, {"scout": 9, "dependency_planner": 1, "verification_adviser": 1})
        fvs_adapter.validate_evidence(stages.entries, binding=self.run["provider_binding"],
                                      exchanges=self.state["model_exchanges"])

    def stage_fixture(self, verdict=PASS, *, statement_overrides=None, review_overrides=None, patch_overrides=None):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64,
                 "supplied_specs": {"helper": "probe:Arithmetic.increment_spec"}}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40,
                "lane_id": "fixture-helper", "request_id": "fixture-helper", "worktree_path": "/synthetic/work",
                "cache_path": "/synthetic/cache", "result_path": "/synthetic/result"}
        actual = {"text": ORIGINAL}
        calls = []
        async def conversation(state, job, tools, *, submission_check=None):
            # This synthetic role returns once; Stages still checks submissions
            # if a runner does not execute its continuation callback.
            stage = job["role_context"]["stage"]
            calls.append(stage)
            evidence = ["statement:" + (statement_overrides or {}).get(stage, CANON)]
            proposed = (patch_overrides or {}).get(stage, patch(PROOF) if stage.startswith("proof-") else patch(SPEC))
            if job["role"] in fvs_profile.REVIEW_ROLES:
                proposed = job["role_context"]["reviewed_candidate"]["patch"]
                evidence = [(review_overrides or {}).get(stage, verdict)]
            elif "triage" in stage or stage not in {"implementation-research", "spec-author:0", "proof-author:0"}:
                parsed = job["role_context"].get("review")
                findings = [] if not parsed else [{"id": f["id"], "disposition": "FIX", "evidence": "Synthetic source-based correction at Arithmetic.lean:3."} for f in parsed["findings"]]
                evidence.append("triage:" + json.dumps({"findings": findings, "summary": "Author checked all source-bound findings."}))
            candidate = tools["submit_candidate"]["invoke"]({"patch": proposed, "claimed_status": "candidate", "evidence": evidence})
            e = self.exchange(job["role"], input_hashes=job["input_hashes"])
            e["response"]["payload"] = {"schema": "autofv-lane-tool-call/v1", "name": "submit_candidate",
                "arguments": {"patch": proposed, "claimed_status": "candidate", "evidence": evidence}}
            e["response"]["payload_sha256"] = fvs_profile.digest(e["response"]["payload"])
            e["receipt"] = provider_receipts.sign_receipt(self.binding, self.run, e["request"], e["response"], e["receipt"]["provider"])
            self.remember(e)
            return candidate
        def edit(run, lane, p):
            actual["text"] = fvs_packet.apply_patch(actual["text"], PATH, p)
            return "synthetic-applied"
        patches = [mock.patch("autofv.agent_lane.run_role_conversation", side_effect=conversation),
                   mock.patch("autofv.worker.read_lane_file", side_effect=lambda *a: actual["text"]),
                   mock.patch("autofv.worker.edit_lane_file", side_effect=edit),
                   mock.patch("autofv.worker.check_lane", return_value="sealed_runtime:exit=0:diagnostic_sha256=" + "0" * 64 + ":synthetic host-only verdict"),
                   mock.patch("autofv.worker.save_lane_snapshot", return_value={"sequence": 1, "synthetic": True})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return graph, lane, actual, calls

    def test_navigation_preserves_complete_packet_and_rejects_missing_or_drifted_source(self):
        original = packet()
        before = copy.deepcopy(original)
        nav = fvs_packet.navigation(original, {"probe:Arithmetic.increment": PATH})
        self.assertEqual(original, before)
        self.assertEqual(nav["baseline_declarations"], [{"declaration": "probe:Arithmetic.increment",
            "path": PATH, "source_sha256": original["sources"][0]["sha256"], "declaration_lines": [3]}])
        self.assertEqual({s["surface"] for s in nav["supporting_sources"]}, {"types", "interpretation", "intent"})
        missing = fvs_packet.navigation(original, {"probe:Arithmetic.absent": PATH})
        self.assertEqual(missing["baseline_declarations"][0]["declaration_lines"], [])
        with self.assertRaisesRegex(contracts.ContractError, "navigation source missing"):
            fvs_packet.navigation(original, {"probe:Arithmetic.increment": "NotInPacket.lean"})
        original["sources"][0]["content"] += "-- drift\n"
        with self.assertRaises(contracts.ContractError):
            fvs_packet.navigation(original, {"probe:Arithmetic.increment": PATH})

    def test_binding_annex_tracks_producer_revision_reviewer_and_prover_without_rewriting_history(self):
        graph, lane, actual, calls = self.stage_fixture(review_overrides={"spec-review:0": REVISE})
        jobs, visible = {}, {}
        def runner(state, graph, lane, role, **kwargs):
            job = generic_role_runtime._role_job(state, graph, lane, role,
                **{k: v for k, v in kwargs.items() if k != "submission_check"})
            key = job["role_context"]["stage"]
            jobs[key] = copy.deepcopy(job)
            messages = agent_lane.initial_role_messages(agent_lane.role_conversation_spec(job))
            visible[key] = json.loads(messages[1]["content"])["context"]
            self.assertEqual(visible[key]["role_context"], job["role_context"])
            self.assertLess(len(contracts.canonical_json_bytes(messages)), agent_lane._MAX_FVS_CONTEXT_BYTES)
            return generic_role_runtime._run_role_lane(state, graph, lane, role, **kwargs)
        stages = fvs_adapter.Stages(self.state, graph, lane, runner, lambda *a: None)
        root = "theorem Arithmetic.root_spec : True"
        capture = "Built Arithmetic (1 job)\n"
        diagnostic = "sealed_runtime:exit=0:diagnostic_sha256=" + fvs_adapter._raw_sha256(capture) + ":" + capture
        with mock.patch.object(worker, "check_lane", return_value=diagnostic):
            candidate = stages.specification(fvs_adapter._raw_sha256(root), {"task_brief": {"final_goal": {"canon": root}}})
            retained = copy.deepcopy(stages.entries)
            stages.proof(candidate, fvs_adapter._raw_sha256(CANON), {})
        for key, entry in retained.items():
            self.assertEqual(stages.entries[key], entry)
        self.assertEqual(stages.entries["helper:spec-review:0:verdict"]["raw"], REVISE)
        self.assertEqual(stages.entries["helper:spec-review:1:verdict"]["raw"], PASS)
        for current, producer in (("spec-review:0", "spec-author:0"), ("spec-author:1", "spec-author:0"),
                                  ("spec-review:1", "spec-author:1")):
            with self.subTest(stage=current):
                inner = jobs[current]["role_context"]
                summary = inner["controller_binding_data"]["producer"]
                self.assertEqual(summary["record_check"], "verified")
                self.assertEqual(summary["json_sha256"]["role_context"], fvs_profile.digest(jobs[producer]["role_context"]))
                self.assertEqual(summary["job_bindings"]["input_hashes"], jobs[producer]["input_hashes"])
                current_summary = visible[current]["binding_domains"]
                self.assertEqual(current_summary["job_bindings"]["input_hashes_check"], "verified")
                self.assertNotEqual(summary["json_sha256"]["role_context"], current_summary["json_sha256"]["role_context"])
                self.assertEqual(current_summary["json_sha256"]["role_context"], fvs_profile.digest(inner))
                self.assertEqual(current_summary["packet_patch_text"]["sha256"], fvs_adapter._raw_sha256(inner["source_packet"]["patch"]))
                self.assertNotIn(current_summary["json_sha256"]["role_context"], json.dumps(inner))
                gate = inner["controller_binding_data"]["gate_capture"]
                self.assertEqual(gate["capture_bytes_check"], "verified")
                self.assertEqual(gate["candidate_identity_check"], "not_verified")
                self.assertEqual(gate["snapshot_inventory_check"], "not_verified")
        author = stages.entries["helper:spec-author:0"]["candidate"]
        reviewer_job = jobs["spec-review:0"]
        self.assertEqual(reviewer_job["role_context"]["reviewed_candidate"], author)
        self.assertNotEqual(author["statement_sha256"], reviewer_job["statement_sha256"])
        for key in ("proof-author:0",):
            self.assertEqual(visible[key]["binding_domains"]["job_bindings"]["fingerprint_domain"], "frozen_statement")
            self.assertEqual(visible[key]["binding_domains"]["job_bindings"]["statement_sha256_check"], "verified")
        fvs_adapter.validate_evidence(stages.entries, binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_gate_capture_annex_checks_scoped_records_not_claimed_hashes_or_snapshot_equivalence(self):
        graph, lane, actual, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.invoke("specifier", "spec-author:0", fingerprint="e" * 64)
        view = fvs_packet.review_snapshot(packet(), path=PATH, patch=candidate["patch"])
        inventory = [{k: source[k] for k in ("path", "sha256")} for source in fvs_packet.validate_view(view).values()]
        captures = ["Built Arithmetic (1 job)\n", "Replayed Arithmetic (0 jobs)\n"]
        diagnostics = ["sealed_runtime:exit=0:diagnostic_sha256=" + fvs_adapter._raw_sha256(text) + ":" + text for text in captures]
        with mock.patch.object(worker, "check_lane", side_effect=diagnostics), \
             mock.patch.object(worker, "save_lane_snapshot", side_effect=[{"sequence": i, "files": inventory} for i in (1, 2)]):
            for i in range(2):
                stages.gate_author(candidate, f"spec-gates:{i}", specification=True)
        before = copy.deepcopy(stages.entries)
        summaries = [stages._controller_binding_data(candidate, view, d)["gate_capture"] for d in diagnostics]
        self.assertNotEqual(summaries[0]["diagnostic_sha256"], summaries[1]["diagnostic_sha256"])
        self.assertNotEqual(summaries[0]["record"], summaries[1]["record"])
        self.assertEqual(summaries[0]["assigned_source_sha256"], summaries[1]["assigned_source_sha256"])
        for summary in summaries:
            self.assertEqual(summary["diagnostic_sha256"], summary["captured_text_sha256"])
            self.assertEqual(summary["capture_bytes_check"], "verified")
            self.assertEqual(summary["snapshot_inventory_check"], "not_verified")
        unknown = "sealed_runtime:exit=0:diagnostic_sha256=" + "1" * 64 + ":model claim only"
        self.assertEqual(stages._controller_binding_data(candidate, view, unknown)["gate_capture"]["status"], "not_verified")
        self.assertEqual(stages.entries, before)
        for field, value in (("source_sha256", "0" * 64), ("original_packet_sha256", "0" * 64),
                             ("diagnostic", diagnostics[0] + "altered suffix")):
            with self.subTest(field=field):
                stages.entries = copy.deepcopy(before)
                gate = stages.entries["helper:spec-gates:0"]
                gate[field] = value
                gate["record_sha256"] = fvs_profile.digest({k: v for k, v in gate.items() if k != "record_sha256"})
                checked = stages._controller_binding_data(candidate, view, gate["diagnostic"])["gate_capture"]
                self.assertEqual(checked["capture_bytes_check"], "mismatch")
        stages.entries = {"other-helper:spec-gates:0": before["helper:spec-gates:0"]}
        self.assertEqual(stages._controller_binding_data(candidate, view, diagnostics[0])["gate_capture"]["status"], "not_verified")

    def test_producer_annex_does_not_bless_changed_input_binding(self):
        graph, lane, actual, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.invoke("specifier", "spec-author:0", fingerprint="e" * 64)
        view = fvs_packet.review_snapshot(packet(), path=PATH, patch=candidate["patch"])
        before = copy.deepcopy(stages.entries)
        changed = {**candidate, "input_hashes": ["0" * 64]}
        self.assertEqual(stages._controller_binding_data(changed, view, None)["producer"]["status"], "not_verified")
        self.assertEqual(stages.entries, before)
        # Even a self-consistent local record hash cannot make the wrong input domain match.
        entry = stages.entries["helper:spec-author:0"]
        entry["candidate"] = changed
        entry["record_sha256"] = fvs_profile.digest({k: v for k, v in entry.items() if k != "record_sha256"})
        checked = stages._controller_binding_data(changed, view, None)["producer"]
        self.assertEqual(checked["job_bindings"]["input_hashes_check"], "mismatch")

    def test_integrated_fc_stages_preserve_raw_review_triage_and_frozen_statement(self):
        graph, lane, actual, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {"intent": "successor"})
        proved = stages.proof(candidate, "e" * 64, {})
        self.assertEqual(actual["text"], PROOF)
        self.assertEqual(proved["patch"], patch(PROOF))
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-review:0", "proof-author:0"])
        evidence = self.state["fvs_evidence"]
        self.assertEqual(evidence["helper:spec-review:0:verdict"]["raw"], PASS)
        self.assertNotIn("helper:spec-triage:0", evidence)
        self.assertEqual(evidence["helper:proof-checked"]["model_proof_review"], "not_requested")
        self.assertEqual(evidence["helper:frozen-statement"]["statement"], CANON)
        self.assertTrue(evidence["helper:spec-review:0"]["invocation_receipts"])
        with self.assertRaises(ValueError):
            stages.record("frozen-statement", {"candidate": proved, "statement": "changed"})

    def test_specification_can_correct_beyond_three_rounds_with_budget_remaining(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={f"spec-author:{i}": bad for i in range(4)})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {})
        self.assertEqual(fvs_adapter.statement(candidate), CANON)
        self.assertEqual(calls, ["implementation-research", *[f"spec-author:{i}" for i in range(5)], "spec-review:4"])
        self.assertEqual(stages.entries["helper:frozen-statement"]["disposition"], "fresh semantic PASS")

    def test_approve_with_edits_requires_fresh_semantic_review_of_changed_statement(self):
        revised = CANON + " ∧ True"
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:1": revised},
            patch_overrides={"spec-author:1": patch(SPEC.replace("increment n = ok result", "increment n = ok result ∧ True"))},
            review_overrides={"spec-review:0": REVISE.replace("VERDICT: REVISE", "VERDICT: APPROVE-WITH-EDITS")})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        result = stages.specification("e" * 64, {})
        self.assertEqual(fvs_adapter.statement(result), revised)
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-review:0", "spec-author:1", "spec-review:1"])
        self.assertEqual(stages.entries["helper:frozen-statement"]["review_sha256"], fvs_adapter.parse_review(PASS)["raw_sha256"])
        self.assertEqual(stages.entries["helper:spec-review:1"]["candidate"]["patch"], result["patch"])

    def test_statement_binding_feedback_corrects_before_any_review(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, actual, calls = self.stage_fixture(statement_overrides={"spec-author:0": bad})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {"intent": "successor"})
        self.assertEqual(fvs_adapter.statement(candidate), CANON)
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-review:1"])
        entries = self.state["fvs_evidence"]
        rejection = entries["helper:spec-binding-error:0"]
        self.assertEqual(rejection["candidate_sha256"], fvs_profile.digest(entries["helper:spec-author:0"]["candidate"]))
        self.assertEqual(rejection["error"], "FVS claimed statement does not match the reviewed source")
        feedback = entries["helper:spec-author:1"]["stage_context"]["statement_binding_feedback"]
        self.assertEqual(feedback["error"], rejection["error"])
        self.assertEqual(feedback["submitted_evidence"], entries["helper:spec-author:0"]["candidate"]["evidence"])
        self.assertNotIn("helper:spec-review:0", entries)
        self.assertEqual(actual["text"], SPEC)
        fvs_adapter.validate_evidence(entries, binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_statement_shape_feedback_corrects_before_any_review(self):
        relation = "∃ result, increment n = ok result"
        bad_relation = "increment n = ok n"
        graph, lane, actual, calls = self.stage_fixture(
            statement_overrides={"spec-author:0": CANON.replace(relation, bad_relation)},
            patch_overrides={"spec-author:0": patch(SPEC.replace(relation, bad_relation))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {"intent": "successor"})
        self.assertEqual(fvs_adapter.statement(candidate), CANON)
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-review:1"])
        entries = self.state["fvs_evidence"]
        rejection = entries["helper:spec-shape-error:0"]
        self.assertEqual(rejection["candidate_sha256"], fvs_profile.digest(entries["helper:spec-author:0"]["candidate"]))
        self.assertEqual(rejection["error"], "FVS target statement lacks existential functional relation")
        feedback = entries["helper:spec-author:1"]["stage_context"]["statement_shape_feedback"]
        self.assertEqual(feedback["submitted_evidence"], entries["helper:spec-author:0"]["candidate"]["evidence"])
        self.assertNotIn("helper:spec-review:0", entries)
        self.assertEqual(actual["text"], SPEC)
        fvs_adapter.validate_evidence(entries, binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_statement_shape_feedback_corrects_missing_result_marker(self):
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:0": CANON.replace("ok result", "result")},
            patch_overrides={"spec-author:0": patch(SPEC.replace("ok result", "result"))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        self.assertEqual(fvs_adapter.statement(stages.specification("e" * 64, {})), CANON)
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-review:1"])
        self.assertNotIn("helper:spec-review:0", self.state["fvs_evidence"])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_statement_shape_feedback_stops_at_the_cost_budget(self):
        self.state["config"]["max_cost_usd"] = Decimal("0.0012")
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={f"spec-author:{i}": CANON.replace("∃", "∀") for i in range(3)},
            patch_overrides={f"spec-author:{i}": patch(SPEC.replace("∃", "∀")) for i in range(3)})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with self.assertRaises(contracts.BudgetExhausted):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-author:2"])
        entries = self.state["fvs_evidence"]
        self.assertEqual(sum(":spec-shape-error:" in key for key in entries), 2)
        self.assertNotIn("helper:frozen-statement", entries)
        self.assertFalse(any(":spec-review:" in key for key in entries))
        fvs_adapter.validate_evidence(entries, binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_shape_and_binding_corrections_share_one_round_counter(self):
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:0": CANON.replace("∃", "∀"),
                                 "spec-author:1": CANON.replace("increment n", "Arithmetic.increment n")},
            patch_overrides={"spec-author:0": patch(SPEC.replace("∃", "∀"))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-author:2", "spec-review:2"])
        self.assertIn("helper:spec-shape-error:0", self.state["fvs_evidence"])
        self.assertIn("helper:spec-binding-error:1", self.state["fvs_evidence"])
        self.assertNotIn("helper:spec-author:3", self.state["fvs_evidence"])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_shape_correction_and_review_share_one_round_counter(self):
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:1": CANON.replace("∃", "∀")},
            patch_overrides={"spec-author:1": patch(SPEC.replace("∃", "∀"))},
            review_overrides={"spec-review:0": REVISE})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-review:0", "spec-author:1", "spec-author:2", "spec-review:2"])
        self.assertNotIn("helper:spec-review:1", self.state["fvs_evidence"])
        self.assertNotIn("helper:spec-author:3", self.state["fvs_evidence"])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_shape_feedback_does_not_hide_source_tampering(self):
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:0": CANON.replace("∃", "∀")},
            patch_overrides={"spec-author:0": patch(SPEC.replace("∃", "∀").replace("n + 1", "n + 2"))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with self.assertRaisesRegex(contracts.ContractError, "changed original prepared source"):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0"])
        self.assertFalse(any(":spec-shape-error:" in key for key in self.state["fvs_evidence"]))

    def test_shape_feedback_does_not_hide_gate_evidence_drift(self):
        graph, lane, _, calls = self.stage_fixture(
            statement_overrides={"spec-author:0": CANON.replace("∃", "∀")},
            patch_overrides={"spec-author:0": patch(SPEC.replace("∃", "∀"))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        stages.entries["helper:spec-gates:0"] = {"record_sha256": "0" * 64}
        with self.assertRaisesRegex(contracts.ContractError, "captured gate evidence drift"):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0"])
        self.assertFalse(any(":spec-shape-error:" in key for key in self.state["fvs_evidence"]))

    def test_fvs_author_receives_explicit_signature_shape_and_shared_round_guidance(self):
        graph, lane, _, _ = self.stage_fixture()
        conversation = agent_lane.run_role_conversation.side_effect
        prompts = []
        async def capture(state, job, tools):
            if job["role"] == "specifier":
                prompts.append(agent_lane.role_conversation_spec(job)["system_prompt"])
            return await conversation(state, job, tools)
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with mock.patch("autofv.agent_lane.run_role_conversation", side_effect=capture):
            stages.specification("e" * 64, {})
        self.assertIn("canonical specification theorem signature itself", prompts[0])
        self.assertIn("explicit ∃", prompts[0])
        self.assertIn("ok", prompts[0])
        self.assertIn("same original wall/cost allowance", prompts[0])

    def test_statement_binding_feedback_stops_at_the_cost_budget(self):
        self.state["config"]["max_cost_usd"] = Decimal("0.0012")
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(statement_overrides={f"spec-author:{i}": bad for i in range(3)})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with self.assertRaises(contracts.BudgetExhausted):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-author:1", "spec-author:2"])
        self.assertEqual(sum(":spec-binding-error:" in k for k in self.state["fvs_evidence"]), 2)
        self.assertNotIn("helper:frozen-statement", self.state["fvs_evidence"])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_statement_correction_and_review_share_one_round_counter(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(statement_overrides={"spec-author:1": bad},
            review_overrides={"spec-review:0": REVISE})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-review:0", "spec-author:1",
            "spec-author:2", "spec-review:2"])
        self.assertNotIn("helper:spec-review:1", self.state["fvs_evidence"])
        self.assertNotIn("helper:spec-author:3", self.state["fvs_evidence"])
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_statement_feedback_does_not_swallow_other_gate_failures(self):
        graph, lane, _, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with mock.patch.object(stages, "gate_author", side_effect=contracts.ContractError("synthetic source integrity failure")):
            with self.assertRaisesRegex(contracts.ContractError, "source integrity"):
                stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0"])
        self.assertFalse(any(":spec-binding-error:" in k for k in self.state["fvs_evidence"]))

    def test_binding_feedback_does_not_hide_source_tampering(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(statement_overrides={"spec-author:0": bad},
            patch_overrides={"spec-author:0": patch(SPEC.replace("n + 1", "n + 2"))})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with self.assertRaisesRegex(contracts.ContractError, "changed original prepared source"):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0"])
        self.assertNotIn("helper:spec-binding-error:0", self.state["fvs_evidence"])

    def test_binding_feedback_does_not_hide_gate_evidence_drift(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(statement_overrides={"spec-author:0": bad})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        stages.entries["helper:spec-gates:0"] = {"record_sha256": "0" * 64}
        with self.assertRaisesRegex(contracts.ContractError, "captured gate evidence drift"):
            stages.specification("e" * 64, {})
        self.assertEqual(calls, ["implementation-research", "spec-author:0"])
        self.assertNotIn("helper:spec-binding-error:0", self.state["fvs_evidence"])

    def test_missing_statement_name_is_a_binding_error_not_an_index_error(self):
        with self.assertRaises(fvs_adapter.StatementBindingError):
            fvs_adapter.statement({"evidence": ["statement:theorem "]})

    def test_proof_statement_change_is_not_repaired_by_spec_feedback(self):
        bad = CANON.replace("increment n", "Arithmetic.increment n")
        graph, lane, _, calls = self.stage_fixture(statement_overrides={"proof-author:0": bad})
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {})
        with self.assertRaisesRegex(contracts.ContractError, "frozen statement"):
            stages.proof(candidate, "e" * 64, {})
        self.assertNotIn("proof-author:1", calls)
        self.assertNotIn("helper:proof-checked", self.state["fvs_evidence"])

    def test_review_revision_budget_blocks_without_forged_approval(self):
        self.state["config"]["max_cost_usd"] = Decimal("0.0024")
        graph, lane, actual, calls = self.stage_fixture(REVISE)
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        with self.assertRaises(contracts.BudgetExhausted):
            stages.specification("e" * 64, {})
        self.assertEqual(sum(s.startswith("spec-review:") for s in calls), 3)
        self.assertNotIn("helper:frozen-statement", self.state["fvs_evidence"])
        self.assertNotIn("helper:proof-checked", self.state["fvs_evidence"])

    def test_progressive_helper_acceptance_requires_distinct_verifier_keeps_root_unverified(self):
        graph, lane, actual, calls = self.stage_fixture()
        node = "probe:Arithmetic.increment"
        root = "probe:Arithmetic.root"
        graph.update(selected_nodes=[node, root], frozen_targets=[root], supplied_specs={root: "probe:Arithmetic.root_spec"},
                     term_dependencies=[[root, node]], source_paths={node: PATH, root: "Root.lean"})
        self.state.update(graph=graph, target_states={node: {"status": "pending"}, root: {"status": "pending"}},
                          lanes=[lane], accepted_nodes=[], accepted_sequence=[])
        lane["node"] = node
        root_lane = {**lane, "node": root, "assigned_path": "Root.lean"}
        def accept(state, candidate, manifest):
            state["accepted_nodes"].append(node)
            state["proof_patch_sha256"][node] = "a" * 64
            return {"status": "accepted_dependency", "synthetic": True}
        report = {"verdict": "SCOPED_PASS", "agent_worker_id": "agent", "verifier_worker_id": "distinct-verifier"}
        with mock.patch("autofv.generic_role_runtime._checkpoint_candidate", side_effect=accept), \
             mock.patch("autofv.worker.persist_lane_result", return_value={}), \
             mock.patch("autofv.terminal_run.clean_verify_partial", return_value=report) as verifier:
            result = generic_role_runtime._run_prepared_progressive(self.state, {node: lane, root: root_lane}, root,
                {"canon": "theorem Arithmetic.root_spec : True", "model_fingerprint": "e" * 64}, {}, proof_only=True)
        verifier.assert_called_once()
        self.assertEqual(result["accepted_nodes"], [node])
        self.assertEqual(self.state["target_states"][root]["status"], "pending")
        self.assertEqual(self.state["fvs_evidence"][node + ":distinct-helper-verifier"]["report"], report)

    def test_prepared_fvs_helper_smoke_starts_at_bundle_and_keeps_acceptance_gates(
        self, *, clean_verdict="SCOPED_PASS", review_verdict=PASS, reject_acceptance=False,
    ):
        graph, lane, actual, calls = self.stage_fixture(review_verdict)
        node, root = "probe:Arithmetic.increment", "probe:Arithmetic.root"
        graph.update(selected_nodes=[node, root], frozen_targets=[root],
            supplied_specs={root: "probe:Arithmetic.root_spec"}, term_dependencies=[[root, node]],
            source_paths={node: PATH, root: "Root.lean"})
        lane.update(node=node, schema="autofv-proof-lane/v1")
        root_lane = {**lane, "node": root, "assigned_path": "Root.lean"}
        self.run.update(execution_mode="proof_only", preparation_manifest={})
        self.state["config"]["max_wall_seconds"] = 3600
        self.state.update(graph=graph, target_states={node: {"status": "pending"}, root: {"status": "pending"}},
                          accepted_nodes=[], accepted_sequence=[])
        role = generic_role_runtime._run_role_lane
        observed_plans = []
        briefs = []
        def guarded_role(state, graph, lane, role_name, **kwargs):
            context = kwargs["role_context"]
            self.assertIn("stage", context, "Root-wide advisory planning was dispatched before the helper")
            expected_limit = 2400 if context["stage"].startswith("proof-") else 1500
            self.assertEqual(worker_runtime._WORK_DEADLINE.get()[2], expected_limit)
            briefs.append(copy.deepcopy(context["task_brief"]))
            source_packet = context["source_packet"]
            self.assertEqual(source_packet.get("original_packet", source_packet), packet())
            self.assertIn(fvs_profile.digest(context), kwargs["input_hashes"])
            plan = context.get("consumer_intent", {}).get("dependency_plan")
            if plan is not None:
                observed_plans.append(copy.deepcopy(plan))
            return role(state, graph, lane, role_name, **kwargs)
        def accept(state, candidate, manifest):
            self.assertEqual(worker_runtime._WORK_DEADLINE.get()[2], 2400)
            if reject_acceptance:
                return {"status": "rejected", "reason": "synthetic rejection"}
            state["accepted_nodes"].append(node)
            state["proof_patch_sha256"][node] = "a" * 64
            return {"status": "accepted_dependency", "synthetic": True}
        report = {"verdict": clean_verdict, "agent_worker_id": "agent", "verifier_worker_id": "distinct-verifier"}
        def verify(*args, **kwargs):
            self.assertEqual(worker_runtime._WORK_DEADLINE.get()[2], 3300)
            self.assertEqual(self.state["target_states"][node]["status"], "unverified")
            return report
        with mock.patch.object(generic_role_runtime, "_supplied_statement", return_value={
                "canon": "theorem Arithmetic.root_spec : True", "model_fingerprint": "e" * 64}), \
             mock.patch.object(generic_role_runtime, "_lane_descriptors", return_value=[lane, root_lane]), \
             mock.patch.object(generic_role_runtime, "_run_role_lane", side_effect=guarded_role), \
             mock.patch.object(worker, "prepare_lanes"), \
             mock.patch.object(generic_role_runtime, "_checkpoint_candidate", side_effect=accept), \
             mock.patch.object(worker, "persist_lane_result", return_value={}), \
             mock.patch("autofv.terminal_run.clean_verify_partial", side_effect=verify) as verifier:
            result = generic_role_runtime.run_generic_role_path(self.state)
        self.assertEqual(calls, ["implementation-research", "spec-author:0", "spec-review:0", "proof-author:0"])
        self.assertTrue(observed_plans)
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())
        self.assertEqual(len(briefs), 4)  # Fresh semantic review; no proof-review/PASS handshakes.
        self.assertTrue(all(brief == briefs[0] for brief in briefs))
        self.assertEqual(briefs[0]["selected_helper"], node)
        self.assertEqual(briefs[0]["final_goal"], {"declaration": "probe:Arithmetic.root_spec",
                                               "canon": "theorem Arithmetic.root_spec : True"})
        self.assertEqual(briefs[0]["direct_callers"][0]["consumer"], root)
        self.assertEqual(briefs[0]["navigation"]["baseline_declarations"][0]["declaration_lines"], [3])
        self.assertEqual(briefs[0]["required_remaining_wall_seconds"]["distinct_verification_start"], 1200)
        for plan in observed_plans:
            self.assertEqual(plan, {"schema": "autofv-frozen-helper-plan/v1", "source": "frozen_graph",
                "graph_sha256": graph["graph_sha256"], "root": root,
                "selected_nodes": graph["selected_nodes"], "term_dependencies": graph["term_dependencies"]})
        verifier.assert_called_once()
        self.assertEqual(result["accepted_nodes"], [node])
        self.assertEqual(self.state["target_states"][root]["status"], "pending")
        self.assertIn("helper_smoke:planning_from_frozen_graph", self.run["events"])
        self.assertEqual(actual["text"], PROOF)

    def test_direct_helper_smoke_stops_on_rejected_acceptance_without_sibling_retry(self):
        with mock.patch.object(generic_role_runtime, "_block_dependents"), \
             self.assertRaisesRegex(contracts.ContractInconclusive, "no sibling retry"):
            self.test_prepared_fvs_helper_smoke_starts_at_bundle_and_keeps_acceptance_gates(reject_acceptance=True)
        self.assertFalse(self.state["accepted_nodes"])
        self.assertNotIn("probe:Arithmetic.increment:distinct-helper-verifier", self.state["fvs_evidence"])

    def test_direct_helper_smoke_rejects_failed_distinct_verification(self):
        with self.assertRaisesRegex(contracts.ContractError, "independent scoped verification"):
            self.test_prepared_fvs_helper_smoke_starts_at_bundle_and_keeps_acceptance_gates(clean_verdict="FAIL")
        self.assertEqual(self.state["target_states"]["probe:Arithmetic.increment"]["status"], "unverified")
        self.assertEqual(self.state["target_states"]["probe:Arithmetic.root"]["status"], "pending")
        self.assertNotIn("probe:Arithmetic.increment:distinct-helper-verifier", self.state["fvs_evidence"])

    def test_direct_helper_smoke_rejects_unapproved_specification(self):
        self.state["config"]["max_cost_usd"] = Decimal("0.0024")
        with self.assertRaises(contracts.BudgetExhausted):
            self.test_prepared_fvs_helper_smoke_starts_at_bundle_and_keeps_acceptance_gates(review_verdict=REVISE)
        self.assertFalse(self.state["accepted_nodes"])
        self.assertNotIn("probe:Arithmetic.increment:frozen-statement", self.state["fvs_evidence"])
        self.assertNotIn("probe:Arithmetic.increment:proof-checked", self.state["fvs_evidence"])

    def test_root_advisory_roles_remain_for_full_fvs_and_legacy_prepared_smoke(self):
        for schema, mode in (("autofv-run/v2", "full"), ("autofv-run/v1", "proof_only")):
            with self.subTest(schema=schema, mode=mode):
                state = {**self.state, "config": {**self.state["config"], "schema": schema},
                    "run": {**self.run, "execution_mode": mode, "preparation_manifest": {}},
                    "graph": {"frozen_targets": ["root"], "selected_nodes": ["helper", "root"],
                        "supplied_specs": {"root": "root_spec"}, "term_dependencies": [["root", "helper"]],
                        "graph_sha256": "d" * 64, "source_paths": {"helper": PATH, "root": "Root.lean"}}}
                lanes = [{"schema": "autofv-proof-lane/v1", "node": node, "lane_id": node,
                    "request_id": node, "base_commit": "c" * 40,
                    "assigned_path": state["graph"]["source_paths"][node],
                    "worktree_path": "/synthetic/work", "cache_path": "/synthetic/cache", "result_path": "/synthetic/result"}
                    for node in ("helper", "root")]
                with mock.patch.object(generic_role_runtime, "_supplied_statement", return_value={
                        "canon": "theorem root_spec : True", "model_fingerprint": "e" * 64}), \
                     mock.patch.object(generic_role_runtime, "_lane_descriptors", return_value=lanes), \
                     mock.patch.object(worker, "prepare_lanes"), \
                     mock.patch.object(worker, "save_lane_snapshot", return_value={"sequence": 1, "synthetic": True}), \
                     mock.patch.object(generic_role_runtime, "_run_role_lane", side_effect=[{"scout": "data"}, {"planner": "data"}]) as role, \
                     mock.patch.object(generic_role_runtime, "_run_prepared_progressive", return_value={"synthetic": True}) as progressive:
                    generic_role_runtime.run_generic_role_path(state)
                self.assertEqual([call.args[3] for call in role.call_args_list], ["scout", "dependency_planner"])
                self.assertEqual(progressive.call_args.args[4], {"planner": "data"})

    def test_full_fvs_direct_root_research_has_conditional_patch_fallback(self):
        state = {**self.state, "run": {**self.run, "execution_mode": "full", "preparation_manifest": {}},
            "graph": {"frozen_targets": ["root"], "selected_nodes": ["helper", "root"],
                "supplied_specs": {"root": "root_spec"}, "term_dependencies": [["root", "helper"]],
                "graph_sha256": "d" * 64, "source_paths": {"helper": PATH, "root": "Root.lean"}}}
        lanes = [{"schema": "autofv-proof-lane/v1", "node": node, "lane_id": node,
            "request_id": node, "base_commit": "c" * 40,
            "assigned_path": state["graph"]["source_paths"][node],
            "worktree_path": "/synthetic/work", "cache_path": "/synthetic/cache", "result_path": "/synthetic/result"}
            for node in ("helper", "root")]
        submissions = []
        async def conversation(state, job, tools):
            self.assertEqual(job["declaration"], "root")
            self.assertEqual(job["methodology"], "fvs-fc/v1")
            self.assertNotIn("readonly_research_patch", job["role_context"])
            self.assertEqual(job["role_context"]["source_packet"], state["config"]["source_packet"])
            messages = agent_lane.initial_role_messages(agent_lane.role_conversation_spec(job))
            guidance = messages[0]["content"]
            self.assertIn("when readonly_research_patch is supplied in role_context DATA, "
                          "copy readonly_research_patch unchanged into an explicit submit_candidate call", guidance)
            self.assertIn("otherwise explicitly submit an unchanged-source one-file Git diff with a context-only hunk", guidance)
            for header in ("diff --git a/<assigned_path> b/<assigned_path>", "--- a/<assigned_path>", "+++ b/<assigned_path>"):
                self.assertIn(header, guidance)
            self.assertIn("never edit source", guidance)
            self.assertIn("that no-change diff is never accepted or applied", guidance)
            path = job["assigned_path"]
            frozen = fvs_packet.validate_view(job["role_context"]["source_packet"])[path]["content"]
            lines = frozen.splitlines(keepends=True)
            fallback = (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
                        f"@@ -1,{len(lines)} +1,{len(lines)} @@\n" + "".join(" " + line for line in lines))
            self.assertEqual(fvs_packet.apply_patch(frozen, path, fallback).encode(), frozen.encode())
            self.assertTrue(agent_lane.invoke_lane_tool(tools, "edit_assigned", {"patch": fallback}).startswith("read_only_role:"))
            result = agent_lane.invoke_lane_tool(tools, "submit_candidate", {
                "patch": fallback, "claimed_status": "candidate", "evidence": ["Synthetic root research only."]})
            self.assertEqual(agent_lane.validate_candidate(result, job), result)
            submissions.append(result)
            return result
        forbidden = mock.Mock(side_effect=AssertionError("direct research must not mutate or use Stages"))
        with (mock.patch.object(generic_role_runtime, "_supplied_statement", return_value={
                  "canon": "theorem root_spec : True", "model_fingerprint": "e" * 64}),
              mock.patch.object(generic_role_runtime, "_lane_descriptors", return_value=lanes),
              mock.patch.object(worker, "prepare_lanes"),
              mock.patch.object(worker, "save_lane_snapshot", return_value={"sequence": 1, "synthetic": True}),
              mock.patch.object(agent_lane, "run_role_conversation", side_effect=conversation),
              mock.patch.object(fvs_adapter.Stages, "invoke", forbidden),
              mock.patch.multiple(worker, read_lane_file=forbidden, search_lane_files=forbidden,
                                  edit_lane_file=forbidden, check_lane=forbidden, accept_candidate=forbidden),
              mock.patch.object(generic_role_runtime, "_run_prepared_progressive", return_value={"synthetic": True}) as progressive):
            generic_role_runtime.run_generic_role_path(state)
        self.assertEqual([result["role"] for result in submissions], ["scout", "dependency_planner"])
        self.assertEqual(progressive.call_args.args[4], submissions[-1])
        forbidden.assert_not_called()

    def test_retained_raw_review_audit_rejects_forgery_and_gate_replay_does_not_build(self):
        graph, lane, actual, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {})
        stages.proof(candidate, "e" * 64, {})
        fvs_adapter.validate_evidence(self.state["fvs_evidence"], binding=self.binding.public,
                                      exchanges=self.state["model_exchanges"])
        with mock.patch("autofv.worker.check_lane") as check:
            text, diagnostic = stages.gate_author(candidate, "spec-gates:0", specification=True)
        check.assert_not_called()
        self.assertEqual(text, SPEC)
        forged = copy.deepcopy(self.state["fvs_evidence"])
        entry = forged["helper:spec-review:0"]
        entry["candidate"]["evidence"] = [PASS.replace("natural inputs", "forged inputs")]
        entry["record_sha256"] = fvs_profile.digest({k: v for k, v in entry.items() if k != "record_sha256"})
        with self.assertRaises(contracts.ContractError):
            fvs_adapter.validate_evidence(forged, binding=self.binding.public, exchanges=self.state["model_exchanges"])

    def test_runner_cannot_skip_green_local_gates(self):
        graph, lane, actual, calls = self.stage_fixture()
        stages = fvs_adapter.Stages(self.state, graph, lane, generic_role_runtime._run_role_lane, lambda *a: None)
        candidate = stages.specification("e" * 64, {})
        with mock.patch("autofv.worker.check_lane", return_value="sealed_runtime:exit=1:synthetic red build") as check:
            with self.assertRaisesRegex(contracts.ContractInconclusive, "without green local gates"):
                stages.proof(candidate, "e" * 64, {})
        self.assertEqual(check.call_count, 1)
        self.assertNotIn("helper:proof-checked", self.state["fvs_evidence"])

    def test_private_reasoning_is_not_retained_even_in_rejected_provider_evidence(self):
        request = model._model_envelope(self.state, request_id="synthetic-reasoning-rejection", role="specifier", input_hashes=[])
        messages = [{"role": "system", "content": "synthetic protocol"}, {"role": "user", "content": "synthetic input"}]
        request["input_hashes"] = sorted(set(request["input_hashes"] + [provider_transport.messages_sha256(messages)]))
        provider_transport.stage_messages(self.run, request, messages)
        reply = _provider_reply()
        reply.update(model=fvs_profile.AUTHOR, provider="OpenAI")
        reply["choices"][0]["message"]["reasoning"] = "synthetic-private-reasoning-never-retain"
        with mock.patch("autofv.provider_transport._open_upstream", return_value=_ProviderReply(reply)):
            with self.assertRaises(provider_config.ProviderConfigError) as error:
                provider_transport.provider_round(self.run, request)
        self.assertNotIn("synthetic-private-reasoning-never-retain", str(error.exception.provider_response))
        self.assertNotIn("reasoning", error.exception.provider_response["choices"][0]["message"])

    def test_builder_uses_only_explicit_prepared_inventory_and_pinned_public_rust_bytes(self):
        p = packet()
        for s in p["sources"]:
            if s["surface"] != "rust":
                (self.root / s["path"]).write_bytes(s["content"].encode())
        rust_root = self.root / "public" / "curve25519-dalek" / "src"
        rust_root.mkdir(parents=True)
        rust_text = p["sources"][1]["content"]
        (rust_root / "increment.rs").write_bytes(rust_text.encode())
        preparation = {"source": IDENTITY, "files": [{"path": s["path"], "sha256": s["sha256"]} for s in p["sources"] if s["surface"] != "rust"]}
        def git_metadata(argv, **kwargs):
            output = (IDENTITY["revision"] if argv[-1] == "HEAD" else IDENTITY["repository"] if argv[-1] == "remote.origin.url"
                      else "curve25519-dalek/src/" if argv[-1] == "--show-prefix" else rust_text)
            return type("SyntheticGitMetadata", (), {"stdout": output if kwargs.get("text") else output.encode()})()
        with mock.patch("autofv.fvs_packet.subprocess.run", side_effect=git_metadata):
            built = fvs_packet.build_packet(prepared_root=self.root, rust_root=rust_root, source_identity=IDENTITY,
                preparation=preparation, paths=[{"path": s["path"], "surface": s["surface"]} for s in p["sources"]],
                style=p["style"], grounding=p["grounding"])
            self.assertEqual(built, p)
            (rust_root / "increment.rs").write_text(rust_text + "// changed bytes\n")
            with self.assertRaises(contracts.ContractError):
                fvs_packet.build_packet(prepared_root=self.root, rust_root=rust_root, source_identity=IDENTITY,
                    preparation=preparation, paths=[{"path": s["path"], "surface": s["surface"]} for s in p["sources"]],
                    style=p["style"], grounding=p["grounding"])

    def test_pinned_deepagents_runs_a_fresh_fvs_review_through_authenticated_model_seam(self):
        graph = {"source_paths": {"helper": PATH}, "graph_sha256": "d" * 64}
        lane = {"node": "helper", "assigned_path": PATH, "base_commit": "c" * 40}
        reviewed = {"patch": patch(SPEC)}
        job = generic_role_runtime._role_job(self.state, graph, lane, "spec_reviewer",
            statement_sha256="e" * 64, contract_fingerprint="f" * 64, input_hashes=["e" * 64],
            role_context={"source_packet": fvs_packet.review_snapshot(packet(), path=PATH, patch=reviewed["patch"]),
                          "reviewed_candidate": reviewed, "stage": "synthetic-fresh-review"})
        tools = agent_lane.build_lane_tools(job, read_file=mock.Mock(), search_files=mock.Mock(),
                                           edit_assigned=mock.Mock(), check_lean=mock.Mock())
        def synthetic_round(state, **kwargs):
            self.assertEqual(kwargs["role"], "spec_reviewer")
            self.assertEqual(kwargs["call_kind"], "explicit")
            def submit(reply):
                reply["choices"][0]["message"]["tool_calls"][0]["function"] = {
                    "name": "submit_candidate", "arguments": json.dumps({"patch": reviewed["patch"],
                    "claimed_status": "candidate", "evidence": [PASS]})}
            e = self.exchange("spec_reviewer", input_hashes=kwargs["input_hashes"], response_overrides=submit)
            self.remember(e)
            return e["response"], e["receipt"]
        with mock.patch("autofv.model._model_request", side_effect=synthetic_round) as dispatch:
            result = asyncio.run(agent_lane.run_role_conversation(self.state, job, tools))
        dispatch.assert_called_once()
        self.assertEqual(result["evidence"], [PASS])
        self.assertEqual(result["patch"], reviewed["patch"])
        fresh = copy.deepcopy(job)
        fresh["role_context"]["stage"] = "synthetic-timeout-review"
        with mock.patch("autofv.model._model_request", side_effect=worker.TransientProviderError("synthetic timeout")) as failed:
            with self.assertRaises(worker.TransientProviderError):
                asyncio.run(agent_lane.run_role_conversation(self.state, fresh, tools))
        failed.assert_called_once()

    def test_new_delivery_members_exist_and_bundle_identity_is_computable(self):
        manifest, files = worker_runtime._control_manifest(contracts.load_toolchain_lock())
        names = {name for name, _, _ in files}
        self.assertTrue({"autofv/fvs_profile.py", "autofv/fvs_packet.py", "autofv/fvs_adapter.py", "autofv/fvs_contracts.json"} <= names)
        self.assertEqual(len(manifest["bundle_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
