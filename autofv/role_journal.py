"""Trusted, authenticated outcomes for replay of bounded lane tool calls.

An interrupted intent is deliberately not re-executed: a tool may already have
mutated its lane. Completed outcomes reconstruct the exact original transcript.
The journal and its key live outside all candidate mounts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

from .contracts import ContractError, canonical_json_bytes
from .run_state import _checkpoint_if_enabled, _state_lock


def _directory(state):
    root = state.get("run", {}).get("run_root")
    if root is None:
        if state.get("checkpoint_enabled"):
            raise ContractError("durable role journal requires a trusted run root")
        return None
    directory = Path(root) / "role-journal"
    # Never resolve away a caller-visible symlink in the trusted evidence chain.
    for path in (directory, *directory.parents):
        if path.is_symlink():
            raise ContractError("role journal path contains a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def _key(directory):
    path = directory / ".key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            key = source.read(33)
        if len(key) != 32:
            raise ContractError("role journal key is invalid")
        return key
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as destination:
        destination.write(key)
        destination.flush()
        os.fsync(destination.fileno())
    return key


def _write(path, key, body):
    raw = canonical_json_bytes(body)
    record = {"body": body, "auth": hmac.new(key, raw, hashlib.sha256).hexdigest()}
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as destination:
        destination.write(canonical_json_bytes(record))
        destination.flush()
        os.fsync(destination.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read(path, key):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        raw = source.read(1_100_000)
    try:
        record = json.loads(raw)
        body = record["body"]
        expected = hmac.new(key, canonical_json_bytes(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(record["auth"], expected):
            raise ValueError("signature")
    except (ValueError, KeyError, TypeError) as exc:
        raise ContractError("role tool journal authentication failed") from exc
    return body


def reconcile_lane_snapshots(state):
    """Pin restore to completed tool snapshots, including post-checkpoint writes."""
    with _state_lock(state):
        directory = _directory(state)
        if directory is None:
            return
        key = _key(directory)
        for journal_id in state.get("role_tool_outcomes", {}):
            if not (directory / f"{journal_id}.json").is_file():
                raise ContractError("role tool journal is missing")
        snapshots = state.setdefault("lane_snapshots", {})
        for path in sorted(directory.glob("*.json")):
            body = _read(path, key)
            if body.get("identity", {}).get("run_id") != state["run"].get("run_id"):
                raise ContractError("role tool journal run identity changed")
            snapshot = body.get("lane_snapshot")
            if body.get("status") != "completed" or snapshot is None:
                continue
            node, receipt = snapshot["node"], snapshot["receipt"]
            prior = snapshots.get(node)
            if prior is None or receipt["sequence"] > prior["sequence"]:
                snapshots[node] = receipt
            elif receipt["sequence"] == prior["sequence"] and receipt != prior:
                raise ContractError("role snapshot sequence changed")


def tool_outcome(state, conversation_id, request_id, action, invoke, *, lane_node=None) -> Any:
    identity = {
        "run_id": state.get("run", {}).get("run_id"),
        "conversation_id": conversation_id,
        "request_id": request_id,
        "action_sha256": hashlib.sha256(canonical_json_bytes(action)).hexdigest(),
    }
    journal_id = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    with _state_lock(state):
        directory = _directory(state)
        key = _key(directory) if directory else None
        path = directory / f"{journal_id}.json" if directory else None
        outcomes = state.setdefault("role_tool_outcomes", {})
        prior = outcomes.get(journal_id)
        if path is not None and path.exists():
            prior = _read(path, key)
        elif prior is not None and path is not None:
            raise ContractError("role tool journal is missing")
        if prior is not None:
            if prior.get("identity") != identity:
                raise ContractError("role tool journal identity changed")
            if prior.get("status") != "completed":
                raise ContractError("ambiguous role tool outcome requires reconciliation")
            return prior["result"]
        intent = {"identity": identity, "status": "started"}
        if path is not None:
            _write(path, key, intent)
        outcomes[journal_id] = intent
        _checkpoint_if_enabled(state, f"tool:{request_id}:started")
    result = invoke()
    with _state_lock(state):
        completed = {**intent, "status": "completed", "result": result}
        snapshot = state.get("lane_snapshots", {}).get(lane_node)
        if snapshot is not None:
            completed["lane_snapshot"] = {"node": lane_node, "receipt": snapshot}
        if path is not None:
            _write(path, key, completed)
        outcomes[journal_id] = completed
        _checkpoint_if_enabled(state, f"tool:{request_id}:completed")
    return result
