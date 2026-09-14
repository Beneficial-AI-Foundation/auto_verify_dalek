"""Narrow, candidate-only tools for one role-local agent conversation."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from . import worker


_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_MAX_PATH_CHARS = 1024
_MAX_QUERY_CHARS = 1024
_MAX_PATCH_BYTES = 1_000_000
_MAX_EVIDENCE_CHARS = 4096
_MAX_TOOL_OUTPUT_BYTES = 16_384

_ROLES = frozenset(
    {
        "scout",
        "dependency_planner",
        "specifier",
        "spec_reviewer",
        "prover",
        "proof_reviewer",
        "repair",
        "verification_adviser",
    }
)
_JOB_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "declaration",
        "role",
        "assigned_path",
        "allowed_read_paths",
        "graph_sha256",
        "statement_sha256",
        "contract_fingerprint",
        "input_hashes",
        "accepted_commit",
    }
)
_CANDIDATE_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "declaration",
        "role",
        "assigned_path",
        "graph_sha256",
        "statement_sha256",
        "contract_fingerprint",
        "input_hashes",
        "accepted_commit",
        "patch",
        "claimed_status",
        "evidence",
    }
)
_TOOL_SCHEMAS = (
    {
        "name": "read_allowed",
        "description": "Read one allowlisted project file.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_allowed",
        "description": "Search bounded allowlisted project context.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "edit_assigned",
        "description": "Edit only the assigned project file.",
        "input_schema": {
            "type": "object",
            "properties": {"patch": {"type": "string"}},
            "required": ["patch"],
            "additionalProperties": False,
        },
    },
    {
        "name": "check_lean",
        "description": "Run the fixed Lean diagnostic.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "submit_candidate",
        "description": "Return an untrusted candidate for controller review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "patch": {"type": "string"},
                "claimed_status": {
                    "type": "string",
                    "enum": ["candidate", "blocked", "false_spec"],
                },
                "evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 32,
                },
            },
            "required": ["patch", "claimed_status", "evidence"],
            "additionalProperties": False,
        },
    },
)


def _text(value: Any, label: str, *, limit: int | None = None) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\r" in value:
        raise worker.WorkerError(f"{label} is invalid")
    if limit is not None and len(value) > limit:
        raise worker.WorkerError(f"{label} exceeds its bound")
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    path = _text(value, label, limit=_MAX_PATH_CHARS)
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or "\\" in path
        or pure.as_posix() != path
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise worker.WorkerError(f"{label} is unsafe")
    return path


def _hashes(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
        or value != sorted(set(value))
        or any(_HEX_SHA256.fullmatch(item) is None for item in value)
    ):
        raise worker.WorkerError(f"{label} are invalid")
    return value


def validate_role_job(job: Any) -> dict[str, Any]:
    """Validate and copy the complete immutable identity for one role job."""
    if not isinstance(job, dict) or set(job) != _JOB_FIELDS:
        raise worker.WorkerError("role job fields mismatch")
    if job["schema"] != "autofv-role-job/v1":
        raise worker.WorkerError("role job schema mismatch")
    _text(job["run_id"], "role job run id")
    _text(job["declaration"], "role job declaration")
    if not isinstance(job["role"], str) or job["role"] not in _ROLES:
        raise worker.WorkerError("role job role is invalid")
    assigned_path = _safe_relative_path(job["assigned_path"], "assigned path")
    paths = job["allowed_read_paths"]
    if (
        not isinstance(paths, list)
        or any(not isinstance(path, str) for path in paths)
        or paths != sorted(set(paths))
        or any(_safe_relative_path(path, "allowed read path") != path for path in paths)
        or assigned_path not in paths
    ):
        raise worker.WorkerError("allowed read paths are invalid")
    for field in ("graph_sha256", "statement_sha256", "contract_fingerprint"):
        if not isinstance(job[field], str) or _HEX_SHA256.fullmatch(job[field]) is None:
            raise worker.WorkerError(f"role job {field} is invalid")
    _hashes(job["input_hashes"], "role job input hashes")
    if (
        not isinstance(job["accepted_commit"], str)
        or _GIT_COMMIT.fullmatch(job["accepted_commit"]) is None
    ):
        raise worker.WorkerError("role job accepted commit is invalid")
    return copy.deepcopy(job)


def _validate_evidence(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise worker.WorkerError("candidate evidence is invalid")
    for item in value:
        _text(item, "candidate evidence item", limit=_MAX_EVIDENCE_CHARS)
    return value


def validate_candidate(candidate: Any, job: Any) -> dict[str, Any]:
    """Revalidate a lane candidate against its trusted role-job identity."""
    trusted_job = validate_role_job(job)
    if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_FIELDS:
        raise worker.WorkerError("lane candidate fields mismatch")
    if candidate["schema"] != "autofv-lane-candidate/v1":
        raise worker.WorkerError("lane candidate schema mismatch")
    for field in (
        "run_id",
        "declaration",
        "role",
        "assigned_path",
        "graph_sha256",
        "statement_sha256",
        "contract_fingerprint",
        "input_hashes",
        "accepted_commit",
    ):
        if candidate[field] != trusted_job[field]:
            raise worker.WorkerError(f"lane candidate {field} mismatch")
    patch = _text(candidate["patch"], "lane candidate patch")
    if len(patch.encode("utf-8")) > _MAX_PATCH_BYTES:
        raise worker.WorkerError("lane candidate patch exceeds its bound")
    worker.validate_assigned_patch(trusted_job["assigned_path"], patch)
    if (
        not isinstance(candidate["claimed_status"], str)
        or candidate["claimed_status"] not in {"candidate", "blocked", "false_spec"}
    ):
        raise worker.WorkerError("lane candidate status is invalid")
    _validate_evidence(candidate["evidence"])
    return copy.deepcopy(candidate)


def _bounded_output(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise worker.WorkerError(f"{label} did not return text")
    raw = value.encode("utf-8")
    if len(raw) <= _MAX_TOOL_OUTPUT_BYTES:
        return value
    return raw[:_MAX_TOOL_OUTPUT_BYTES].decode("utf-8", "ignore")


def _resolved_lane_file(lane_root: Path, relative: str) -> Path:
    if lane_root.is_symlink():
        raise worker.WorkerError("lane root must not be a symlink")
    try:
        root = lane_root.resolve(strict=True)
    except OSError as exc:
        raise worker.WorkerError("lane root is unavailable") from exc
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise worker.WorkerError("lane path must not contain a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise worker.WorkerError("lane path is unavailable") from exc
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise worker.WorkerError("lane path escapes its root or is not a file")
    return resolved


def _candidate(job: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    patch = _text(arguments["patch"], "candidate patch")
    if len(patch.encode("utf-8")) > _MAX_PATCH_BYTES:
        raise worker.WorkerError("candidate patch exceeds its bound")
    worker.validate_assigned_patch(job["assigned_path"], patch)
    candidate = {
        "schema": "autofv-lane-candidate/v1",
        **{
            field: copy.deepcopy(job[field])
            for field in (
                "run_id",
                "declaration",
                "role",
                "assigned_path",
                "graph_sha256",
                "statement_sha256",
                "contract_fingerprint",
                "input_hashes",
                "accepted_commit",
            )
        },
        "patch": patch,
        "claimed_status": arguments["claimed_status"],
        "evidence": copy.deepcopy(arguments["evidence"]),
    }
    return validate_candidate(candidate, job)


def build_lane_tools(
    job: Any,
    *,
    lane_root: Path,
    read_file: Callable[[str], Any],
    search_files: Callable[[str], Any],
    edit_assigned: Callable[[str], Any],
    check_lean: Callable[[], Any],
) -> dict[str, dict[str, Any]]:
    """Build the five tools for one job without granting acceptance authority."""
    trusted_job = validate_role_job(job)
    root = Path(lane_root)
    allowed_paths = frozenset(trusted_job["allowed_read_paths"])

    def read_allowed(arguments: dict[str, Any]) -> str:
        relative = _safe_relative_path(arguments["path"], "read path")
        if relative not in allowed_paths:
            raise worker.WorkerError("read path is not allowlisted")
        _resolved_lane_file(root, relative)
        return _bounded_output(read_file(relative), "read tool")

    def search_allowed(arguments: dict[str, Any]) -> str:
        query = _text(arguments["query"], "search query", limit=_MAX_QUERY_CHARS)
        for relative in allowed_paths:
            _resolved_lane_file(root, relative)
        return _bounded_output(search_files(query), "search tool")

    def edit_only_assigned(arguments: dict[str, Any]) -> str:
        _resolved_lane_file(root, trusted_job["assigned_path"])
        worker.validate_assigned_patch(trusted_job["assigned_path"], arguments["patch"])
        return _bounded_output(edit_assigned(arguments["patch"]), "edit tool")

    def fixed_lean_check(arguments: dict[str, Any]) -> str:
        return _bounded_output(check_lean(), "Lean diagnostic tool")

    handlers = (
        read_allowed,
        search_allowed,
        edit_only_assigned,
        fixed_lean_check,
        lambda arguments: _candidate(trusted_job, arguments),
    )
    return {
        schema["name"]: {"schema": copy.deepcopy(schema), "invoke": handler}
        for schema, handler in zip(_TOOL_SCHEMAS, handlers, strict=True)
    }


def capture_tool_schemas(tools: Any) -> list[dict[str, Any]]:
    """Fail closed unless the effective tool surface exactly matches the allowlist."""
    if not isinstance(tools, Mapping) or set(tools) != {
        schema["name"] for schema in _TOOL_SCHEMAS
    }:
        raise worker.WorkerError("effective lane tool names mismatch")
    for expected in _TOOL_SCHEMAS:
        tool = tools[expected["name"]]
        if (
            not isinstance(tool, dict)
            or set(tool) != {"schema", "invoke"}
            or tool["schema"] != expected
            or not callable(tool["invoke"])
        ):
            raise worker.WorkerError("effective lane tool schema mismatch")
    return copy.deepcopy(list(_TOOL_SCHEMAS))


def _validate_tool_arguments(schema: dict[str, Any], arguments: Any) -> dict[str, Any]:
    properties = schema["input_schema"]["properties"]
    if not isinstance(arguments, dict) or set(arguments) != set(properties):
        raise worker.WorkerError(f"{schema['name']} arguments mismatch")
    for name, definition in properties.items():
        value = arguments[name]
        expected_type = definition["type"]
        if expected_type == "string" and not isinstance(value, str):
            raise worker.WorkerError(f"{schema['name']} argument type mismatch")
        if expected_type == "array" and not isinstance(value, list):
            raise worker.WorkerError(f"{schema['name']} argument type mismatch")
        if "enum" in definition and value not in definition["enum"]:
            raise worker.WorkerError(f"{schema['name']} argument value mismatch")
        if "maxItems" in definition and len(value) > definition["maxItems"]:
            raise worker.WorkerError(f"{schema['name']} argument exceeds its bound")
    if "evidence" in arguments:
        _validate_evidence(arguments["evidence"])
    return arguments


def invoke_lane_tool(tools: Any, name: Any, arguments: Any) -> Any:
    """Validate a model-selected tool and its exact arguments before any callback."""
    capture_tool_schemas(tools)
    if not isinstance(name, str) or name not in tools:
        raise worker.WorkerError("lane tool is not allowlisted")
    tool = tools[name]
    validated = _validate_tool_arguments(tool["schema"], arguments)
    return tool["invoke"](validated)
