"""Compact, best-effort display of Claude stream-json; raw logs stay untouched."""
import hashlib
import json
import re
import threading
import time


def compact(value, limit=180):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def content_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text")
    return ""


class ProgressRenderer:
    def __init__(self, emit):
        self.emit = emit
        self.turn = 0
        self.messages = {}
        self.seen = set()
        self.tools = {}

    def event(self, event):
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        message = event.get("message") or {}
        if kind not in ("assistant", "user") or not isinstance(message, dict):
            return
        blocks = message.get("content", [])
        if not isinstance(blocks, list):
            return
        mid = message.get("id") or event.get("uuid")
        if kind == "assistant":
            if mid not in self.messages or mid is None:
                self.turn += 1
                self.messages[mid] = self.turn
            turn = self.messages[mid]
        for block in blocks:
            if not isinstance(block, dict):
                continue
            typ = block.get("type")
            # Ignore reasoning, token deltas, metadata, and repeated snapshots.
            if typ not in ("text", "tool_use", "tool_result"):
                continue
            key = (kind, mid, hashlib.sha256(
                json.dumps(block, sort_keys=True).encode()).digest())
            if key in self.seen:
                continue
            self.seen.add(key)
            if kind == "assistant" and typ == "text" and block.get("text", "").strip():
                self.emit(f"[turn {turn}] {compact(block['text'], 500)}")
            elif kind == "assistant" and typ == "tool_use":
                name = block.get("name", "tool")
                data = block.get("input") or {}
                if not isinstance(data, dict):
                    data = {}
                detail = next((data[k] for k in ("command", "file_path", "path", "pattern", "skill", "description", "task_id") if data.get(k)), "")
                self.tools[block.get("id")] = (turn, name, time.monotonic())
                self.emit(f"[turn {turn}] {name}  {compact(detail)}")
            elif kind == "user" and typ == "tool_result":
                turn_id, name, started = self.tools.pop(block.get("tool_use_id"), ("?", "tool", time.monotonic()))
                text = content_text(block.get("content"))
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                errors = [line for line in lines if re.search(r"error:|error\b|timeout|timed out|failed|maximum number of heartbeats", line, re.I)]
                failed = block.get("is_error", False)
                status = "ERROR" if failed else "returned"
                self.emit(f"[turn {turn_id}] {name} {status} ({time.monotonic() - started:.1f}s)")
                # Never dump file reads or edit payloads. Bash/build diagnostics
                # are the important evidence; show at most three bounded lines.
                if name in ("Bash", "TaskOutput") or failed:
                    selected = errors[:3] if errors else lines[-3:]
                    for line in selected:
                        self.emit(f"  | {compact(line, 240)}")


class LiveTranscript:
    """Tail the existing file, so display never backpressures the child pipe."""
    def __init__(self, path, emit):
        self.path = path
        self.renderer = ProgressRenderer(emit)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)

    def _watch(self):
        try:
            with open(self.path, encoding="utf-8", errors="replace") as source:
                pending = ""
                while True:
                    finished = self.stop.is_set()
                    pending += source.read()
                    lines = pending.split("\n")
                    pending = lines.pop()
                    if finished and pending:
                        lines.append(pending)
                    for line in lines:
                        try:
                            event = json.loads(line)
                        except ValueError:
                            continue
                        try:
                            self.renderer.event(event)
                        except (TypeError, AttributeError, KeyError):
                            continue
                    if finished:
                        break
                    self.stop.wait(0.1)
        except Exception:
            # A closed terminal or unrecognized event must not abort a proof.
            return
