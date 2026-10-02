"""Bounded FC methodology over the existing sealed candidate-only lane tools.

No native FVS CLI/tool parity, external-model adoption, or model calls occur here
unless the controller's separately authorized role runner dispatches them.
"""
from __future__ import annotations

import copy
import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .contracts import ContractError, ContractInconclusive, canonical_json_bytes
from . import fvs_packet, fvs_profile


def contracts() -> dict[str, Any]:
    return json.loads(Path(__file__).with_name("fvs_contracts.json").read_text(encoding="utf-8"))


def _raw_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_review(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096:
        raise ContractError("FVS review is empty/oversized")
    verdicts = re.findall(r"^VERDICT: (PASS|APPROVE-WITH-EDITS|REVISE|BLOCKED)$", raw, re.M)
    if len(verdicts) != 1 or len(re.findall(r"VERDICT:", raw)) != 1:
        raise ContractError("FVS review must have exactly one supported verdict")
    sections = {}
    headings = list(re.finditer(r"^## ([^\n]+)$", raw, re.M))
    for index, match in enumerate(headings):
        name = match[1]
        if name in sections:
            raise ContractError("FVS duplicate review section")
        sections[name] = raw[match.end(): headings[index + 1].start() if index + 1 < len(headings) else len(raw)].strip()
    required = {"Findings", "Content coverage statement", "Coverage", "Evidence"}
    if not required <= sections.keys() or any(len(sections[k].split("VERDICT:")[0].strip()) < 24 for k in required - {"Findings"}):
        raise ContractError("FVS review lacks substantive coverage/evidence")
    surfaces = ("source fidelity", "preconditions", "postconditions", "interpretation", "vacuity", "dependencies", "helper reuse")
    if any(surface not in sections["Coverage"].lower() for surface in surfaces):
        raise ContractError("FVS review omits applicable review surfaces")
    findings = []
    matches = list(re.finditer(r"^### (F-[1-9][0-9]*) [—-] (BLOCKER|MAJOR|MINOR)\s*$", sections["Findings"], re.M))
    if len(re.findall(r"^### ", sections["Findings"], re.M)) != len(matches):
        raise ContractError("FVS malformed finding header")
    for index, match in enumerate(matches):
        body = sections["Findings"][match.end(): matches[index+1].start() if index+1 < len(matches) else len(sections["Findings"])]
        fields = {}
        for label in ("Class", "Claim", "Evidence", "Suggested change"):
            values = re.findall(r"^" + label + r": (.+)$", body, re.M)
            if len(values) != 1 or (label != "Class" and len(values[0].strip()) < 12):
                raise ContractError("FVS finding lacks substantive fields")
            fields[label] = values[0]
        if fields["Class"] not in {"CONTENT", "PROCESS"} or len(fields["Suggested change"]) > 4000:
            raise ContractError("FVS finding class/edit bound invalid")
        findings.append({"id": match[1], "severity": match[2], **fields})
    if len({f["id"] for f in findings}) != len(findings):
        raise ContractError("FVS duplicate finding ID")
    verdict = verdicts[0]
    if verdict in {"APPROVE-WITH-EDITS", "REVISE"} and not findings:
        raise ContractError("FVS revision verdict has no findings")
    if verdict == "PASS" and findings:
        raise ContractError("FVS PASS with unresolved findings")
    if verdict == "BLOCKED" and "missing" not in sections["Evidence"].lower():
        raise ContractError("FVS BLOCKED lacks missing-evidence identification")
    return {"verdict": verdict, "findings": findings, "raw": raw,
            "raw_sha256": _raw_sha256(raw)}


def statement(candidate: dict[str, Any]) -> str:
    statements = [s.removeprefix("statement:") for s in candidate.get("evidence", []) if s.startswith("statement:theorem ")]
    if len(statements) != 1 or ":=" in statements[0]:
        raise ContractError("FVS author lacks one proof-free frozen statement")
    return statements[0]


def validate_statement_source(canon: str, text: str) -> None:
    name = canon.split()[1]
    matches = [m for m in re.finditer(r"^\s*theorem\s+([A-Za-z_0-9.]+)\b", text, re.M)
               if m[1].rsplit(".", 1)[-1] == name.rsplit(".", 1)[-1]]
    if len(matches) != 1:
        raise ContractError("FVS statement source declaration is ambiguous/missing")
    start = matches[0].start()
    end = text.find(":=", matches[0].end())
    actual = text[start:end].strip() if end >= 0 else ""
    actual = re.sub(r"^theorem\s+\S+", "theorem " + name, actual)
    if " ".join(actual.split()) != " ".join(canon.split()):
        raise ContractError("FVS claimed statement does not match the reviewed source")


def triage(candidate: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    values = [s.removeprefix("triage:") for s in candidate.get("evidence", []) if s.startswith("triage:")]
    if len(values) != 1:
        raise ContractError("FVS author lacks separate immutable triage")
    from . import provider_messages, provider_config
    try:
        result = provider_messages.strict_json(values[0].encode("utf-8"), "FVS author triage")
    except (ValueError, TypeError, provider_config.ProviderConfigError) as exc:
        raise ContractError("FVS malformed author triage") from exc
    if not isinstance(result, dict) or set(result) != {"findings", "summary"} or not isinstance(result["summary"], str) or len(result["summary"].strip()) < 12:
        raise ContractError("FVS triage lacks summary")
    findings = result["findings"]
    if not isinstance(findings, list) or {f.get("id") for f in findings if isinstance(f, dict)} != {f["id"] for f in review["findings"]} or len(findings) != len(review["findings"]):
        raise ContractError("FVS triage does not cover every finding")
    for item in findings:
        if (not isinstance(item, dict) or set(item) != {"id", "disposition", "evidence"}
            or item["disposition"] not in {"FIX", "DESCOPE", "REJECT-FINDING", "ASK-HUMAN"}
            or not isinstance(item["evidence"], str) or len(item["evidence"].strip()) < 24):
            raise ContractError("FVS triage disposition/evidence invalid")
        if item["disposition"] == "ASK-HUMAN":
            raise ContractInconclusive("FVS unresolved human authority")
    return {"raw": values[0], "raw_sha256": _raw_sha256(values[0]), **result}


def style_structure(text: str, packet: dict[str, Any], *, specification: bool, baseline: str = "") -> None:
    style = packet["style"]
    added = "\n".join(line[2:] for line in difflib.ndiff(baseline.splitlines(), text.splitlines()) if line.startswith("+ "))
    if any(len(line) > style["max_columns"] for line in added.splitlines()):
        raise ContractError("FVS style gate: long line")
    # Comments/strings are not ordinary identifiers. Trust checks remain the
    # existing Lean-aware gates; this is only the mechanical presentation gate.
    stripped = re.sub(r"/\-.*?\-/|--[^\n]*|\"(?:[^\"\\]|\\.)*\"", "", added, flags=re.S)
    stripped = re.sub(r"^\s*(?:import|namespace|open|end)\b[^\n]*", "", stripped, flags=re.M)
    for word in re.findall(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)+", stripped):
        if word.count(".") > style["max_namespace_dots"]:
            raise ContractError("FVS style gate: deep ordinary identifier")
    if specification and ("@[step]" not in text or "import " not in text or "sorry" not in text
                          or not re.search(r"∃|\bexists\b", text) or "ok" not in text):
        raise ContractError("FVS specification structure gate failed")


def proof_scope(frozen: str, current: str, previous: str, *, canon: str) -> None:
    name = canon.split()[1].rsplit(".", 1)[-1]
    matches = [m for m in re.finditer(r"^\s*theorem\s+([A-Za-z_0-9.]+)\b", frozen, re.M)
               if m[1].rsplit(".", 1)[-1] == name]
    if len(matches) != 1:
        raise ContractInconclusive("FVS proof target declaration ambiguous/missing")
    body = re.search(r":=\s*by\s+(sorry)\b", frozen[matches[0].end():])
    if body is None:
        raise ContractInconclusive("FVS proof target is not a single sorry body")
    start = matches[0].end() + body.start(1)
    prefix, suffix = frozen[:start], frozen[start + len("sorry"): ]
    if not current.startswith(prefix) or not current.endswith(suffix):
        raise ContractError("FVS proof changed the frozen statement/source outside its sorry")
    replacement = current[len(prefix):len(current) - len(suffix) if suffix else len(current)]
    if re.search(r"\bsorry\b|\badmit\b", replacement):
        raise ContractInconclusive("FVS proof still contains the targeted placeholder")
    changed = [line for line in difflib.ndiff(previous.splitlines(), current.splitlines()) if line.startswith("+ ")]
    if len(changed) > 3:
        raise ContractError("FVS proof attempt exceeds three added tactic lines")


def validate_evidence(entries: Any, *, binding: dict[str, Any], exchanges: dict[str, Any]) -> None:
    """Recheck retained raw stages against the authenticated model exchange set."""
    from . import agent_lane
    if not isinstance(entries, dict):
        raise ContractError("FVS stage inventory invalid")
    receipts = {e["receipt"]["receipt_sha256"]: e for e in exchanges.values()}
    contract_hash = fvs_profile.digest(contracts())
    for key, entry in entries.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            raise ContractError("FVS stage record invalid")
        body = {k: v for k, v in entry.items() if k != "record_sha256"}
        if (entry.get("record_sha256") != fvs_profile.digest(body)
            or entry.get("adapter") != "autofv-bounded-fc/v1"
            or entry.get("contracts_sha256") != contract_hash
            or entry.get("role_profile_sha256") != binding["role_profile_sha256"]
            or entry.get("original_packet_sha256") != binding["source_packet_sha256"]):
            raise ContractError("FVS retained stage hash/profile/source drift")
        if "invocation_receipts" not in entry:
            continue
        packet = entry["packet"]
        original = packet.get("original_packet", packet)
        fvs_packet.validate_packet(original)
        if original["packet_sha256"] != binding["source_packet_sha256"]:
            raise ContractError("FVS invocation original source drift")
        fvs_packet.validate_view(packet)
        generation = packet.get("dependency_generation")
        if generation is not None and entry.get("generation_sha256") != generation["generation_sha256"]:
            raise ContractError("FVS retained dependency generation drift")
        context = {**entry["stage_context"], "source_packet": packet}
        context_hash = fvs_profile.digest(context)
        candidate = entry["candidate"]
        job = {"schema": "autofv-role-job/v2", "methodology": agent_lane._FVS_METHODOLOGY,
               "role_context": context,
               "allowed_read_paths": sorted(s["path"] for s in original["sources"]),
               **{k: candidate[k] for k in ("run_id", "declaration", "role", "assigned_path", "graph_sha256",
                  "statement_sha256", "contract_fingerprint", "input_hashes", "accepted_commit")}}
        agent_lane.validate_candidate(candidate, job)
        if entry["fresh_conversation"] != context_hash or entry["role"] != candidate["role"]:
            raise ContractError("FVS retained conversation identity drift")
        ids = entry["invocation_receipts"]
        if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids) or any(i not in receipts for i in ids):
            raise ContractError("FVS retained invocation receipt missing/replayed")
        selected = [receipts[i] for i in ids]
        if any(e["request"]["role"] != candidate["role"] or context_hash not in e["request"]["input_hashes"] for e in selected):
            raise ContractError("FVS retained role/context not authenticated")
        submitted = {k: candidate[k] for k in ("patch", "claimed_status", "evidence")}
        if not any(e["response"].get("payload", {}).get("name") == "submit_candidate"
                   and e["response"]["payload"].get("arguments") == submitted for e in selected):
            raise ContractError("FVS retained raw candidate/review not authenticated")
        if entry["role"] in fvs_profile.REVIEW_ROLES:
            if entry["read_only_tools"] is not True:
                raise ContractError("FVS retained reviewer tool boundary mismatch")
            verdict_key = key + ":verdict"
            if verdict_key in entries:
                parsed = parse_review(candidate["evidence"][0])
                if any(entries[verdict_key].get(k) != v for k, v in parsed.items()):
                    raise ContractError("FVS retained verdict/raw response drift")


class Stages:
    def __init__(self, state: dict[str, Any], graph: dict[str, Any], lane: dict[str, Any],
                 role_runner: Callable[..., dict[str, Any]], checkpoint: Callable[..., Any]):
        self.state, self.graph, self.lane = state, graph, lane
        self.runner, self.checkpoint = role_runner, checkpoint
        self.original = fvs_packet.validate_packet(state["config"]["source_packet"])
        self.path, self.node = lane["assigned_path"], lane["node"]
        generation = state.get("fvs_lane_generations", {}).get(self.node)
        self.baseline = generation["packet"] if "generation_sha256" in lane else self.original
        if "generation_sha256" in lane and (generation.get("phase") != "ready"
                or generation["binding"]["generation_sha256"] != lane["generation_sha256"]):
            raise ContractError("FVS stage dependency lane identity drift")
        supplied = graph.get("supplied_specs", {}).get(self.node)
        self.theorem = supplied.removeprefix("probe:") if supplied else self.node.removeprefix("probe:") + "_spec"
        self.contracts = contracts()
        self.entries = state.setdefault("fvs_evidence", {})
        self.source = fvs_packet.validate_view(self.baseline)[self.path]["content"]

    def record(self, key: str, value: dict[str, Any]) -> dict[str, Any]:
        identity = self.node + ":" + key
        body = {"adapter": "autofv-bounded-fc/v1", "contracts_sha256": fvs_profile.digest(self.contracts),
                "role_profile_sha256": fvs_profile.digest(fvs_profile.profile()),
                "original_packet_sha256": self.original["packet_sha256"],
                **({"generation_sha256": self.lane["generation_sha256"]} if "generation_sha256" in self.lane else {}),
                **copy.deepcopy(value)}
        entry = {**body, "record_sha256": fvs_profile.digest(body)}
        from .run_state import _state_lock
        with _state_lock(self.state):
            prior = self.entries.setdefault(identity, entry)
        if prior != entry:
            raise ContractError("FVS stage evidence/replay drift")
        self.checkpoint(self.state, "fvs:" + identity)
        return copy.deepcopy(entry)

    def invoke(self, role: str, key: str, *, candidate: dict[str, Any] | None = None,
               context: dict[str, Any] | None = None, fingerprint: str) -> dict[str, Any]:
        packet = (fvs_packet.review_snapshot(self.baseline, path=self.path, patch=candidate["patch"])
                  if candidate is not None else self.baseline)
        role_context = {"stage": key, "target_theorem": self.theorem, "source_packet": packet, "contracts_sha256": fvs_profile.digest(self.contracts),
                        **(context or {})}
        if role in fvs_profile.REVIEW_ROLES:
            role_context["reviewed_candidate"] = candidate
        from . import worker
        try:
            result = self.runner(self.state, self.graph, self.lane, role,
                statement_sha256=fingerprint,
                contract_fingerprint=fingerprint,
                input_hashes=[self.original["packet_sha256"], fvs_profile.digest(packet), fvs_profile.digest(role_context)],
                role_context=role_context)
        except (ContractError, worker.WorkerError) as exc:
            self.record(key + ":failed", {"role": role, "packet": packet, "error": str(exc),
                "completed_exchanges": [copy.deepcopy(e) for e in self.state.get("model_exchanges", {}).values()
                    if fvs_profile.digest(role_context) in e.get("request", {}).get("input_hashes", [])]})
            raise
        binding = self.state["run"].get("provider_binding")
        if not isinstance(binding, dict) or binding.get("schema") != "autofv-provider-binding/v2":
            raise ContractError("FVS stage requires authenticated frozen pair binding")
        from . import provider_receipts
        exchanges = sorted([e for e in self.state.get("model_exchanges", {}).values()
                     if e.get("request", {}).get("role") == role
                     and fvs_profile.digest(role_context) in e.get("request", {}).get("input_hashes", [])],
                     key=lambda e: e["request"]["sequence"])
        if not exchanges:
            raise ContractError("FVS stage lacks completed authenticated invocation evidence")
        receipts = []
        for exchange in exchanges:
            request, response, receipt = (exchange[k] for k in ("request", "response", "receipt"))
            if (request["model_id"] != fvs_profile.ROLE_MODELS[role]
                or receipt.get("provider", {}).get("role") != role
                or binding["role_profile_sha256"] not in request["input_hashes"]
                or binding["source_packet_sha256"] not in request["input_hashes"]):
                raise ContractError("FVS stage receipt role/profile/source mismatch")
            provider_receipts.validate_receipt(receipt, binding=binding, run_id=request["run_id"],
                sequence=request["sequence"], request_id=request["request_id"], model_id=request["model_id"],
                request_sha256=fvs_profile.digest(request), response_sha256=fvs_profile.digest(response),
                seen_receipt_sha256=set())
            receipts.append(receipt["receipt_sha256"])
        submitted = {"patch": result["patch"], "claimed_status": result["claimed_status"], "evidence": result["evidence"]}
        if not any(e["response"].get("payload", {}).get("name") == "submit_candidate"
                   and e["response"]["payload"].get("arguments") == submitted for e in exchanges):
            raise ContractError("FVS candidate/raw review is not bound to an authenticated submit response")
        self.record(key, {"role": role, "packet": packet, "candidate": result,
                          "stage_context": {k: v for k, v in role_context.items() if k != "source_packet"},
                          "invocation_receipts": receipts, "fresh_conversation": fvs_profile.digest(role_context),
                          "read_only_tools": role in fvs_profile.REVIEW_ROLES,
                          "effort_provenance": "signed requested xhigh; required routing support; not independently reported"})
        if result["claimed_status"] != "candidate":
            raise ContractInconclusive("FVS role blocked: " + role)
        return result

    def gate_author(self, candidate: dict[str, Any], key: str, *, specification: bool) -> tuple[str, str]:
        from . import worker
        packet = fvs_packet.review_snapshot(self.baseline, path=self.path, patch=candidate["patch"])
        target = packet["overlay"]["content"]
        canon = statement(candidate)
        validate_statement_source(canon, target)
        if specification:
            if not re.search(r"∃|\bexists\b", canon) or "ok" not in canon:
                raise ContractError("FVS target statement lacks existential functional relation")
            # Existing prepared implementations/definitions are immutable. The
            # author may insert a specification, not rewrite source to make it true.
            changes = difflib.SequenceMatcher(None, self.source.splitlines(keepends=True), target.splitlines(keepends=True), autojunk=False)
            if any(tag in {"replace", "delete"} for tag, *_ in changes.get_opcodes()):
                raise ContractError("FVS specification author changed original prepared source")
        prior = self.entries.get(self.node + ":" + key)
        if prior is not None:
            body = {k: v for k, v in prior.items() if k != "record_sha256"}
            if (prior["record_sha256"] != fvs_profile.digest(body)
                or prior["source_sha256"] != packet["overlay"]["sha256"]
                or prior["original_packet_sha256"] != self.original["packet_sha256"]
                or prior["contracts_sha256"] != fvs_profile.digest(self.contracts)):
                raise ContractError("FVS captured gate evidence drift")
            return target, prior["diagnostic"]
        style_structure(target, self.original, specification=specification, baseline=self.source)
        from . import role_journal
        from .run_state import _external_call
        def run_gates():
            actual = worker.read_lane_file(self.state["run"], self.lane, self.path, [self.path])
            # Candidate-only submit may omit an edit callback; apply that exact
            # author-owned overlay, never a reviewer patch. Unexpected drift blocks.
            known = self.state.setdefault("fvs_lane_sources", {}).get(self.node, self.source)
            if actual not in (known, target):
                raise ContractError("FVS author lane does not match captured source/candidate")
            if actual != target:
                patch = "".join(difflib.unified_diff(actual.splitlines(keepends=True), target.splitlines(keepends=True),
                            fromfile="a/" + self.path, tofile="b/" + self.path))
                patch = f"diff --git a/{self.path} b/{self.path}\n" + patch
                worker.edit_lane_file(self.state["run"], self.lane, patch)
            diagnostic = worker.check_lane(self.state["run"], self.lane, self.state["manifest"])
            snapshot = worker.save_lane_snapshot(self.state["run"], self.lane)
            self.state.setdefault("lane_snapshots", {})[self.node] = snapshot
            self.state["fvs_lane_sources"][self.node] = target
            return {"source_sha256": packet["overlay"]["sha256"], "diagnostic": diagnostic,
                    "style": "passed", "snapshot": snapshot}
        identity = fvs_profile.digest({"node": self.node, "stage": key, "packet": packet})
        captured = _external_call(self.state, "fvs-gates:" + identity,
            lambda: role_journal.tool_outcome(self.state, identity, "fvs-gates:" + identity,
                {"name": "fixed-author-gates", "arguments": {"candidate_sha256": fvs_profile.digest(candidate)}},
                run_gates, lane_node=self.node))
        self.record(key, captured)
        return target, captured["diagnostic"]

    def review(self, candidate: dict[str, Any], role: str, key: str, fingerprint: str,
               *, history: list[dict[str, Any]], diagnostic: str) -> dict[str, Any]:
        reviewed = self.invoke(role, key, candidate=candidate, fingerprint=fingerprint,
                               context={"untrusted_history": history, "captured_diagnostic": diagnostic})
        if reviewed["patch"] != candidate["patch"] or len(reviewed["evidence"]) != 1:
            raise ContractError("FVS reviewer changed candidate or omitted exact raw review")
        result = parse_review(reviewed["evidence"][0])
        self.record(key + ":verdict", result)
        return result

    def specification(self, fingerprint: str, author_context: dict[str, Any]) -> dict[str, Any]:
        research = self.invoke("scout", "implementation-research", fingerprint=fingerprint,
                               context={"consumer_intent": author_context})
        candidate = self.invoke("specifier", "spec-author:0", fingerprint=fingerprint,
                                context={"untrusted_research": research["evidence"], "consumer_intent": author_context})
        history = []
        for round_index in range(3):
            text, diagnostic = self.gate_author(candidate, f"spec-gates:{round_index}", specification=True)
            canon = statement(candidate)
            review = self.review(candidate, "spec_reviewer", f"spec-review:{round_index}",
                                 _raw_sha256(canon), history=history, diagnostic=diagnostic)
            if review["verdict"] == "PASS":
                if not diagnostic.startswith("sealed_runtime:exit=0:"):
                    raise ContractInconclusive("FVS statement local gates are not green")
                author = self.invoke("specifier", f"spec-pass-triage:{round_index}", candidate=candidate,
                    fingerprint=fingerprint, context={"review": review,
                        "task": "author-owned triage only; preserve statement and patch exactly"})
                if author["patch"] != candidate["patch"] or statement(author) != canon:
                    raise ContractError("FVS PASS triage changed reviewed sources/statement")
                from . import worker
                if worker.read_lane_file(self.state["run"], self.lane, self.path, [self.path]) != self.state["fvs_lane_sources"][self.node]:
                    raise ContractError("FVS PASS triage mutated the reviewed source")
                disposition = triage(author, review)
                self.record(f"spec-triage:{round_index}", {"triage": disposition,
                    "old_sha256": _raw_sha256(text), "new_sha256": _raw_sha256(text),
                    "review_sha256": review["raw_sha256"]})
                self.record("frozen-statement", {"candidate": author, "statement": canon, "source": text})
                return author
            if round_index == 2 and review["verdict"] != "APPROVE-WITH-EDITS":
                raise ContractInconclusive("FVS specification reviewer/revision cap exhausted")
            revision = self.invoke("specifier", f"spec-author:{round_index+1}", candidate=candidate,
                fingerprint=fingerprint, context={"review": review, "untrusted_history": history,
                                                 "task": "author triage and revision; preserve exact raw history"})
            disposition = triage(revision, review)
            new_text = fvs_packet.review_snapshot(self.baseline, path=self.path, patch=revision["patch"])["overlay"]["content"]
            self.record(f"spec-triage:{round_index}", {"triage": disposition,
                "old_sha256": _raw_sha256(text), "new_sha256": _raw_sha256(new_text),
                "old_candidate_sha256": fvs_profile.digest(candidate), "new_candidate_sha256": fvs_profile.digest(revision)})
            if review["verdict"] == "APPROVE-WITH-EDITS":
                if new_text == text and any(f["disposition"] in {"FIX", "DESCOPE"} for f in disposition["findings"]):
                    raise ContractInconclusive("FVS required bounded edits were not applied")
                if any(f["disposition"] == "REJECT-FINDING" for f in disposition["findings"]):
                    # This adapter has no independent source-counterexample
                    # checker for author rejection; re-review rather than assert approval.
                    history.append({"review": review["raw"], "triage": disposition["raw"]})
                    candidate = revision
                    continue
                edits = [line for line in difflib.ndiff(text.splitlines(), new_text.splitlines()) if line[:2] in {"+ ", "- "}]
                if len(edits) > 80 or sum(len(line) for line in edits) > 4000:
                    raise ContractInconclusive("FVS approve-with-edits exceeds bounded edit contract")
                _, gates = self.gate_author(revision, f"spec-edits-gates:{round_index}", specification=True)
                if not gates.startswith("sealed_runtime:exit=0:"):
                    raise ContractInconclusive("FVS approve-with-edits local gates failed")
                self.record("frozen-statement", {"candidate": revision, "statement": statement(revision),
                                                 "source": new_text, "disposition": "approved after edits"})
                return revision
            history.append({"review": review["raw"], "triage": disposition["raw"]})
            candidate = revision
        raise ContractInconclusive("FVS specification cap exhausted")

    def proof(self, contract_candidate: dict[str, Any], fingerprint: str,
              context: dict[str, Any]) -> dict[str, Any]:
        frozen = fvs_packet.review_snapshot(self.baseline, path=self.path, patch=contract_candidate["patch"])["overlay"]["content"]
        canon = statement(contract_candidate)
        previous, candidate = frozen, contract_candidate
        history = []
        for attempt in range(3):
            proposed = self.invoke("prover" if attempt == 0 else "repair", f"proof-author:{attempt}",
                                  candidate=candidate, fingerprint=fingerprint,
                                  context={**context, "frozen_statement": canon, "untrusted_history": history,
                                           "review": history[-1]["parsed_review"] if history else None})
            if history:
                disposition = triage(proposed, history[-1]["parsed_review"])
                self.record(f"proof-triage:{attempt-1}", {"triage": disposition,
                    "old_candidate_sha256": fvs_profile.digest(candidate), "new_candidate_sha256": fvs_profile.digest(proposed)})
            if statement(proposed) != canon:
                raise ContractError("FVS proof role changed frozen statement identity")
            target = fvs_packet.review_snapshot(self.baseline, path=self.path, patch=proposed["patch"])["overlay"]["content"]
            proof_scope(frozen, target, previous, canon=canon)
            text, diagnostic = self.gate_author(proposed, f"proof-gates:{attempt}", specification=False)
            review = self.review(proposed, "proof_reviewer", f"proof-review:{attempt}", fingerprint,
                                 history=history, diagnostic=diagnostic)
            if review["verdict"] == "PASS" and diagnostic.startswith("sealed_runtime:exit=0:"):
                # The authoritative acceptance/verifier still checks proof holes
                # and axioms; unrelated baseline placeholders are not this proof.
                author = self.invoke("repair", f"proof-pass-triage:{attempt}", candidate=proposed,
                    fingerprint=fingerprint, context={"review": review,
                        "task": "author-owned proof triage only; preserve reviewed statement and patch exactly"})
                if author["patch"] != proposed["patch"] or statement(author) != canon:
                    raise ContractError("FVS proof PASS triage changed reviewed candidate")
                from . import worker
                if worker.read_lane_file(self.state["run"], self.lane, self.path, [self.path]) != text:
                    raise ContractError("FVS proof PASS triage mutated the reviewed source")
                self.record(f"proof-triage:{attempt}", {"triage": triage(author, review),
                    "old_candidate_sha256": fvs_profile.digest(proposed), "new_candidate_sha256": fvs_profile.digest(author)})
                self.record("proof-approved", {"candidate": author, "review_sha256": review["raw_sha256"],
                                               "frozen_statement": canon})
                return author
            if attempt == 2:
                raise ContractInconclusive("FVS proof/review cap exhausted")
            history.append({"review": review["raw"], "parsed_review": review, "diagnostic": diagnostic})
            previous, candidate = text, proposed
        raise ContractInconclusive("FVS proof cap exhausted")
