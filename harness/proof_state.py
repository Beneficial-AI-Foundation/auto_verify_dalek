"""Durable proof handoff. Notes and compilation evidence are not acceptance.

Standard-library only: also copied beside lean_check.py inside the sandbox.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

REPORT_MARKER = "PROOF_STATE_JSON:"
INSTRUCTIONS = """
Proof progress handoff:
After a meaningful milestone, a failed proof approach, and before ending a
round, emit PROOF_STATE_JSON: followed by one JSON object in assistant text.
Keep it concise and update it during work, not only in your final answer:
{"current_node":"lemma or obligation being worked on",
 "completed_nodes":[{"name":"helper_name","file":"relative/path.lean"}],
 "remaining_goals":["precise remaining obligation"],
 "failed_attempts":[{"approach":"what was tried","reason":"why it failed",
                     "evidence":"check result/log path or concrete observation"}],
 "next_check":"specific next edit/check to try"}
These are progress notes, not proof certificates. Do not claim independent
helper verification from a module build or from absence of a direct sorry.
The harness saves notes, code hashes, diagnostics and recoverable snapshots.
The local check tool snapshots editable sources when compilation succeeds on
unchanged inputs. A snapshot can still depend on sorry or unbuilt modules.
On recovery, use the handoff below but recheck stale/unknown evidence. Current
Lean errors take precedence over any earlier claim that a lemma was completed.
Do not create state files in proof sources or modify the acceptance inputs.
"""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def source_path(work, relative):
    work = Path(work).resolve()
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".lean":
        raise ValueError(f"invalid proof source path: {relative}")
    candidate = work / path
    if not candidate.resolve().is_relative_to(work):
        raise ValueError(f"proof source escapes workspace: {relative}")
    return candidate


def capture(work, paths):
    return {p: source_path(work, p).read_bytes() for p in paths
            if source_path(work, p).is_file()}


def hashes(sources):
    return {p: hashlib.sha256(data).hexdigest() for p, data in sources.items()}


def context(work):
    """Conservative project-source + pinned-configuration fingerprint.

    Excludes caches/history/run artifacts; package source contents and external
    toolchain binaries are not audited here. The independent gate still applies.
    """
    work = Path(work).resolve()
    files = {}
    for root, dirs, names in os.walk(work):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and
                         not d.endswith(".checkpoint") and
                         d not in {"ledger", "node_modules", "target", "harness"})
        for name in sorted(names):
            if name.endswith(".lean") or (Path(root) == work and name in {
                    "lean-toolchain", "lake-manifest.json", "lakefile.toml"}):
                path = Path(root) / name
                files[str(path.relative_to(work))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"sha256": digest(files), "files": files,
            "scope": "project Lean sources and pinned Lake/toolchain configuration; excludes package contents"}


def snapshot(directory, sources, kind, **evidence):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    for relative, data in sources.items():
        path = source_path(directory / "files", relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {"kind": kind, "source_hashes": hashes(sources),
                "acceptance_checked": False, **evidence}
    write_json(directory / "manifest.json", manifest)
    return str(directory / "manifest.json")


def reports(transcript):
    """Only assistant text/result, never tool output, can supply model notes."""
    found = []
    path = Path(transcript)
    if not path.is_file():
        return found
    for line in path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        texts = []
        if event.get("type") == "assistant":
            content = (event.get("message") or {}).get("content") or []
            texts = [b.get("text", "") for b in content
                     if isinstance(b, dict) and b.get("type") == "text"]
        elif event.get("type") == "result" and isinstance(event.get("result"), str):
            texts = [event["result"]]
        for text in texts:
            for match in re.finditer(re.escape(REPORT_MARKER), text):
                try:
                    obj, _ = json.JSONDecoder().raw_decode(text[match.end():].lstrip())
                    if isinstance(obj, dict):
                        found.append(clean_notes(obj))
                except ValueError:
                    continue
    return found


def clean_notes(obj):
    def string(value):
        return value[:2000] if isinstance(value, str) else ""
    return {
        "current_node": string(obj.get("current_node")),
        "next_check": string(obj.get("next_check")),
        "remaining_goals": [string(x) for x in obj.get("remaining_goals", [])[:20]
                            if isinstance(x, str)] if isinstance(obj.get("remaining_goals"), list) else [],
        "completed_nodes": [{"name": string(x.get("name")), "file": string(x.get("file"))}
                            for x in obj.get("completed_nodes", [])[:30] if isinstance(x, dict)]
                           if isinstance(obj.get("completed_nodes"), list) else [],
        "failed_attempts": [{k: string(x.get(k)) for k in ("approach", "reason", "evidence")}
                            for x in obj.get("failed_attempts", [])[:20] if isinstance(x, dict)]
                           if isinstance(obj.get("failed_attempts"), list) else []}


def merge_notes(previous, updates):
    notes = dict(previous or clean_notes({}))
    for update in updates:
        failed = notes.get("failed_attempts", []) + update["failed_attempts"]
        unique = {digest(x): x for x in failed}
        notes = {**update, "failed_attempts": list(unique.values())[-20:]}
    return notes


def handoff(state, work):
    current = context(work)
    matched = current["sha256"] == state.get("context", {}).get("sha256")
    last = state.get("last_check") or {}
    check_matches = current["sha256"] == last.get("context_after", {}).get("sha256")
    view = {"notes_are_model_reports": True,
            "recorded_sources_match_current": matched,
            "progress": state.get("progress", {}),
            "diagnosis_review_advisory_only": state.get("diagnosis_review"),
            "last_check": {k: last.get(k) for k in (
                "status", "module", "first_error", "goal_text", "last_output", "log_path")},
            "check_matches_current_sources": check_matches,
            "last_gate": state.get("last_gate"),
            "gate_matches_current_sources": current["sha256"] ==
                (state.get("last_gate") or {}).get("context_sha256"),
            "last_checked_checkpoint": state.get("last_checked_checkpoint"),
            "node_evidence": state.get("node_evidence", []) if matched and check_matches else
                [{"name": n.get("name"), "status": "stale_or_unverified"}
                 for n in state.get("progress", {}).get("completed_nodes", [])]}
    return ("\nProof-state handoff (advisory; current Lean diagnostics take precedence):\n"
            + json.dumps(view, ensure_ascii=False, indent=2)
            + "\nA checkpoint is recoverable source code, not an accepted proof. "
              "Recheck before relying on it, especially if sources differ. "
              "Diagnosis review advice is unverified and cannot change the fixed "
              "target, edit scope, budget, or acceptance gates.\n")


class Recorder:
    """Host-owned state: agent emits notes but cannot write this record directly."""
    def __init__(self, directory, work, paths, target, g1_base, prompt, resume=None):
        self.root = Path(directory)
        self.work, self.paths = str(work), tuple(paths)
        self.root.mkdir(parents=True, exist_ok=False)
        self.task_id = uuid.uuid4().hex
        identity = {"target": target, "editable_paths": list(paths),
                    "statement_fingerprints": {
                        module: {name: {k: spec.get(k) for k in ("kind", "canon")}
                                 for name, spec in declarations.items()}
                        for module, declarations in (g1_base or {}).items()}}
        self.identity = digest(identity)
        write_json(self.root / "inputs.json", {**identity, "identity_sha256": self.identity,
                   "task_id": self.task_id, "original_prompt": prompt})
        self.state = {"schema_version": 1, "identity_sha256": self.identity,
                      "fixed_inputs": identity,
                      "task_id": self.task_id, "context": context(work),
                      "progress": clean_notes({}), "node_evidence": []}
        if resume:
            prior = json.loads(Path(resume).read_text())
            previous = prior.get("fixed_inputs", {})
            same_task = all(previous.get(k) == identity[k] for k in ("target", "editable_paths"))
            same_statements = all(
                identity["statement_fingerprints"].get(module, {}).get(name) == spec
                for module, declarations in previous.get("statement_fingerprints", {}).items()
                for name, spec in declarations.items())
            if not same_task or not same_statements:
                raise ValueError("proof-state target/statements/allowlist differ; refusing recovery")
            self.state = {**prior, "task_id": self.task_id, "fixed_inputs": identity,
                          "identity_sha256": self.identity,
                          "resumed_from": str(Path(resume).resolve())}
        write_json(self.root / "state.json", self.state)

    def record(self, transcript, round_record, log_dir=None):
        self.state["progress"] = merge_notes(self.state.get("progress"), reports(transcript))
        self.state["context"] = context(self.work)
        checks = []
        if log_dir and Path(log_dir).is_dir():
            for path in Path(log_dir).glob("*.json"):
                if not path.resolve().is_relative_to(Path(log_dir).resolve()):
                    continue
                try:
                    result = json.loads(path.read_text())
                except (OSError, ValueError):
                    continue
                if (isinstance(result, dict) and result.get("task_id") == self.task_id
                        and isinstance(result.get("started_at_ns", 0), int)
                        and result.get("workspace") == str(Path(self.work).resolve())):
                    checks.append((path.name, result))
        checks.sort(key=lambda item: (item[1].get("started_at_ns", 0), item[0]))
        executed = [c for _, c in checks if c.get("status") != "busy"]
        if executed:
            self.state["last_check"] = executed[-1]
        for result in executed:
            checkpoint = result.get("checkpoint_path")
            if checkpoint and result.get("status") == "success" and result.get("sources_unchanged"):
                # Restrict references to this tool's log directory. Never read
                # arbitrary agent-provided paths with host filesystem access.
                if Path(checkpoint).resolve().is_relative_to(Path(log_dir).resolve()):
                    self.state["last_checked_checkpoint"] = {
                        "manifest": checkpoint, "module": result.get("module"),
                        "context_sha256": result["context_after"]["sha256"],
                        "verification": "module compilation only; sorry/dependency closure not audited"}
        last = self.state.get("last_check") or {}
        detail = round_record.get("detail") or {}
        outcome = round_record.get("outcome")
        self.state["last_gate"] = {"outcome": outcome,
                                  "errors": detail.get("errors", []),
                                  "build_error_tail": detail.get("build_error_tail"),
                                  "context_sha256": self.state["context"]["sha256"]}
        evidence = []
        for node in self.state["progress"]["completed_nodes"]:
            relative = node["file"]
            module = relative.removesuffix(".lean").replace("/", ".")
            related = [c for c in executed if c.get("module") == module or
                       (c.get("module") is None and c.get("status") != "success")]
            # A later success in another module cannot clear this module's
            # failure. A full build alone does not establish module membership.
            matching = [c for c in related[-1:] if c.get("status") == "success"
                        and c.get("sources_unchanged")
                        and c.get("context_after", {}).get("sha256") == self.state["context"]["sha256"]
                        and c.get("module") == module
                        and relative in c.get("source_hashes", {})]
            # A newer failure or independent rejection must never be hidden by
            # a completion claim / an older successful build of the same text.
            contradicted = (last.get("status") not in (None, "success") or
                            outcome not in ("accepted", "rejected_sorry_remains", "rejected_no_spec"))
            evidence.append({**node, "status": "module_compiled" if matching and not contradicted else "unverified",
                             "file_sha256": self.state["context"]["files"].get(relative),
                             "check_result": matching[-1].get("result_path") if matching else None,
                             "dependency_closure_checked": False})
        self.state["node_evidence"] = evidence
        self.state["round"] = round_record["round"]
        self.state["draft_checkpoint"] = snapshot(
            self.root / f"round-{round_record['round']}-draft", capture(self.work, self.paths),
            "draft", context_sha256=self.state["context"]["sha256"])
        write_json(self.root / f"round-{round_record['round']}.json", self.state)
        write_json(self.root / "state.json", self.state)
        (self.root / "state.md").write_text(handoff(self.state, self.work))
        return str(self.root / "state.json")
