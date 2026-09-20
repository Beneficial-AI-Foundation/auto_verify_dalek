"""Pinned Deep Agents adapter for the trusted role-lane controller."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.metadata
import json
from types import SimpleNamespace
from typing import Any

from deepagents import (
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, convert_to_openai_messages
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables.config import ensure_config
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.errors import NodeCancelledError
from pydantic import PrivateAttr

from . import agent_lane as lane
from . import model, worker
from .contracts import canonical_json_bytes
from .role_journal import tool_outcome
from .run_state import _state_lock


_EXPECTED_VERSIONS = {
    "deepagents": "0.7.15",
    "langgraph": "1.2.11",
    "langchain": "1.4.2",
    "langchain-core": "1.6.3",
}
_EXCLUDED_TOOLS = frozenset(
    {
        "delete",
        "edit_file",
        "execute",
        "glob",
        "grep",
        "ls",
        "read_file",
        "task",
        "write_file",
    }
)
_MODEL_KEY = "autofv:autofv-role-lane"
_MODEL_NAME = "autofv-role-lane"


register_harness_profile(
    _MODEL_KEY,
    HarnessProfile(
        excluded_tools=_EXCLUDED_TOOLS,
        general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
    ),
)


def runtime_compatibility() -> dict[str, Any]:
    """Return the exact selected runtime, failing closed on dependency drift."""
    observed = {
        distribution: importlib.metadata.version(distribution)
        for distribution in _EXPECTED_VERSIONS
    }
    if observed != _EXPECTED_VERSIONS:
        raise worker.WorkerError("Deep Agents role-lane dependency drift")
    return {
        "runtime": "deepagents",
        "deepagents": observed["deepagents"],
        "langgraph": observed["langgraph"],
        "langchain": observed["langchain"],
        "langchain_core": observed["langchain-core"],
        "excluded_tools": sorted(_EXCLUDED_TOOLS),
        "general_purpose_subagent": False,
        "execution_location": "trusted_controller",
        "alternate_runtime": False,
    }


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _normalize_messages(messages: Any) -> list[dict[str, Any]]:
    """Project LangChain messages onto AutoFV's strict provider transcript."""
    converted = convert_to_openai_messages(messages)
    if not isinstance(converted, list):
        converted = [converted]
    normalized: list[dict[str, Any]] = []
    for item in converted:
        if not isinstance(item, dict):
            raise worker.WorkerError("Deep Agents emitted an invalid message")
        role = item.get("role")
        if role in {"system", "user"}:
            normalized.append({"role": role, "content": item.get("content")})
        elif role == "assistant":
            normalized.append(
                {
                    "role": role,
                    "content": item.get("content"),
                    "tool_calls": item.get("tool_calls", []),
                }
            )
        elif role == "tool":
            normalized.append(
                {
                    "role": role,
                    "tool_call_id": item.get("tool_call_id"),
                    "content": item.get("content"),
                }
            )
        else:
            raise worker.WorkerError("Deep Agents emitted an unsupported message role")
    if not normalized or normalized[0].get("role") != "system":
        normalized.insert(
            0,
            {"role": "system", "content": "AutoFV framework compaction call."},
        )
    return normalized


class _RoutedRoleModel(BaseChatModel):
    """LangChain model whose only dispatch path is AutoFV's receipt seam."""

    model_name: str = _MODEL_NAME
    profile: dict[str, Any] = {"max_input_tokens": 65_536}
    max_tokens: int = 8_192
    _state: dict[str, Any] = PrivateAttr()
    _job: dict[str, Any] = PrivateAttr()
    _spec: dict[str, Any] = PrivateAttr()
    _schemas: list[dict[str, Any]] = PrivateAttr()
    _context_hashes: list[str] = PrivateAttr()
    _progress: dict[str, Any] = PrivateAttr()
    _turn: int = PrivateAttr(default=0)
    _seen_internal: set[str] = PrivateAttr(default_factory=set)
    _bound_once: bool = PrivateAttr(default=False)
    _last_request_id: str | None = PrivateAttr(default=None)

    def __init__(
        self,
        state: dict[str, Any],
        job: dict[str, Any],
        spec: dict[str, Any],
        schemas: list[dict[str, Any]],
        context_hashes: list[str],
        progress: dict[str, Any],
    ) -> None:
        super().__init__(max_tokens=spec["max_output_tokens"])
        self._state = state
        self._job = job
        self._spec = spec
        self._schemas = schemas
        self._context_hashes = context_hashes
        self._progress = progress

    @property
    def _llm_type(self) -> str:
        return "autofv-receipted-role-lane"

    def _get_ls_params(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "ls_provider": "autofv",
            "ls_model_name": self.model_name,
            "ls_model_type": "chat",
        }

    @property
    def last_request_id(self) -> str:
        if self._last_request_id is None:
            raise worker.WorkerError("Deep Agents invoked a tool before its model call")
        return self._last_request_id

    @property
    def bound_once(self) -> bool:
        return self._bound_once

    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> _RoutedRoleModel:
        del tool_choice, kwargs
        effective: list[dict[str, Any]] = []
        for item in tools:
            function = convert_to_openai_tool(item, strict=True)["function"]
            effective.append(
                {
                    "name": function["name"],
                    "description": function["description"],
                    "input_schema": function["parameters"],
                }
            )
        expected = {entry["name"]: entry for entry in self._schemas}
        if {entry["name"]: entry for entry in effective} != expected:
            raise worker.WorkerError("effective Deep Agents tool schema mismatch")
        self._bound_once = True
        return self

    def _call_kind(self, normalized: list[dict[str, Any]], run_manager: Any) -> str:
        metadata = getattr(run_manager, "metadata", {}) or {}
        source = metadata.get("lc_source")
        if source == "summarization":
            digest = _sha256(normalized)
            if digest in self._seen_internal:
                return "retry"
            self._seen_internal.add(digest)
            return "compaction"
        if source is None:
            return "explicit"
        return "framework"

    def _invoke(self, messages: Any, run_manager: Any) -> ChatResult:
        normalized = _normalize_messages(messages)
        call_kind = self._call_kind(normalized, run_manager)
        corrections = 0
        expected = {entry["name"]: entry for entry in self._schemas}
        while True:
            self._turn += 1
            if self._turn > lane._MAX_ROLE_TURNS:
                raise worker.WorkerError("invalid_agent_output: role turn limit exhausted")
            request_id = (
                f"lane-{self._spec['conversation_id'][:16]}-{self._turn:03d}"
            )
            self._last_request_id = request_id
            with _state_lock(self._state):
                self._progress.update(
                    {"last_turn": self._turn, "last_request_id": request_id}
                )
            response, _receipt = model._model_request(
                self._state,
                request_id=request_id,
                role=self._job["role"],
                input_hashes=self._context_hashes,
                call_kind=call_kind,
                messages=copy.deepcopy(normalized),
            )
            if response.get("kind") != "tool_call":
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content=json.dumps(
                                    response.get("payload"),
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                            )
                        )
                    ]
                )
            try:
                name, arguments = lane._conversation_action(response)
                if name not in expected:
                    raise worker.WorkerError("lane tool is not allowlisted")
                lane._validate_tool_arguments(expected[name], arguments)
            except worker.WorkerError:
                if corrections >= 2:
                    raise worker.WorkerError("invalid_agent_output") from None
                corrections += 1
                call_kind = "schema_correction"
                continue
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "name": name,
                                    "args": arguments,
                                    "id": f"{request_id}-tool",
                                    "type": "tool_call",
                                }
                            ],
                        )
                    )
                ]
            )

    def _generate(
        self,
        messages: Any,
        stop: Any = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        del stop, kwargs
        return self._invoke(messages, run_manager)

    async def _agenerate(
        self,
        messages: Any,
        stop: Any = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        del stop, kwargs
        return self._invoke(messages, run_manager)

    def invoke(
        self,
        input: Any,
        config: Any = None,
        *,
        stop: Any = None,
        **kwargs: Any,
    ) -> AIMessage:
        del stop, kwargs
        resolved = ensure_config(config)
        result = self._invoke(
            self._convert_input(input).to_messages(),
            SimpleNamespace(metadata=resolved.get("metadata", {})),
        )
        return result.generations[0].message

    async def ainvoke(
        self,
        input: Any,
        config: Any = None,
        *,
        stop: Any = None,
        **kwargs: Any,
    ) -> AIMessage:
        del stop, kwargs
        resolved = ensure_config(config)
        result = self._invoke(
            self._convert_input(input).to_messages(),
            SimpleNamespace(metadata=resolved.get("metadata", {})),
        )
        return result.generations[0].message


def _langchain_tools(
    state: dict[str, Any],
    trusted_job: dict[str, Any],
    raw_tools: Any,
    routed: _RoutedRoleModel,
    progress: dict[str, Any],
    event: Any,
    captured: dict[str, Any],
) -> list[StructuredTool]:
    result: list[StructuredTool] = []
    identity = routed._spec["conversation_id"]
    for schema in lane.capture_tool_schemas(raw_tools):
        name = schema["name"]

        def invoke(_name: str = name, **arguments: Any) -> Any:
            value = tool_outcome(
                state,
                identity,
                routed.last_request_id,
                {"name": _name, "arguments": arguments},
                lambda: lane.invoke_lane_tool(raw_tools, _name, arguments),
                lane_node=trusted_job["declaration"],
            )
            event(
                f"tool:{routed._turn}",
                f"lane_tool:{trusted_job['role']}:{_name}",
            )
            with _state_lock(state):
                progress["last_tool"] = _name
            if _name == "submit_candidate":
                captured["candidate"] = lane.validate_candidate(value, trusted_job)
            return value

        async def ainvoke(
            _name: str = name,
            _invoke: Any = invoke,
            **arguments: Any,
        ) -> Any:
            return _invoke(_name=_name, **arguments)

        result.append(
            StructuredTool.from_function(
                func=invoke,
                coroutine=ainvoke,
                name=name,
                description=schema["description"],
                args_schema=schema["input_schema"],
                infer_schema=False,
                return_direct=name == "submit_candidate",
            )
        )
    return result


def _caused_by_cancellation(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, asyncio.CancelledError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


async def run_role_conversation(
    state: dict[str, Any], job: Any, tools: Any
) -> dict[str, Any]:
    """Run one role through the exact receipted Deep Agents lane."""
    runtime_compatibility()
    trusted_job = lane.validate_role_job(job)
    schemas = lane.capture_tool_schemas(tools)
    spec = lane.role_conversation_spec(trusted_job)
    identity = spec["conversation_id"]
    run = state.get("run")
    events = run.setdefault("events", []) if isinstance(run, dict) else None
    all_progress = state.setdefault("role_progress", {})
    prior_progress = all_progress.get(identity)
    progress_identity = {
        "conversation_id": identity,
        "job_sha256": _sha256(trusted_job),
        "role": trusted_job["role"],
        "declaration": trusted_job["declaration"],
    }
    if isinstance(prior_progress, dict) and any(
        prior_progress.get(key) != value for key, value in progress_identity.items()
    ):
        raise worker.WorkerError("resumed role progress identity changed")
    with _state_lock(state):
        all_progress[identity] = {
            **progress_identity,
            "status": "running",
            "last_turn": int((prior_progress or {}).get("last_turn", 0)),
            "last_request_id": (prior_progress or {}).get("last_request_id"),
            "last_tool": (prior_progress or {}).get("last_tool"),
            "candidate_sha256": (prior_progress or {}).get("candidate_sha256"),
            "events": (prior_progress or {}).get("events", []),
        }
    progress = all_progress[identity]

    def event(key: str, value: str) -> None:
        with _state_lock(state):
            recorded = progress["events"]
            if key not in recorded:
                recorded.append(key)
                if events is not None:
                    events.append(value)

    event("started", f"role:{trusted_job['role']}:started")
    context_hashes = set(trusted_job["input_hashes"])
    context_hashes.update(
        {
            trusted_job["graph_sha256"],
            trusted_job["statement_sha256"],
            trusted_job["contract_fingerprint"],
            _sha256(spec),
            _sha256(schemas),
        }
    )
    routed = _RoutedRoleModel(
        state,
        trusted_job,
        spec,
        schemas,
        sorted(context_hashes),
        progress,
    )
    captured: dict[str, Any] = {}
    graph = create_deep_agent(
        model=routed,
        tools=_langchain_tools(
            state,
            trusted_job,
            tools,
            routed,
            progress,
            event,
            captured,
        ),
        subagents=[],
        system_prompt=spec["system_prompt"],
    )
    user_message = lane.initial_role_messages(spec)[1]
    try:
        await graph.ainvoke(
            {"messages": [user_message]},
            config={"recursion_limit": lane._MAX_ROLE_TURNS * 4},
        )
    except NodeCancelledError as exc:
        if _caused_by_cancellation(exc):
            raise asyncio.CancelledError from exc
        raise
    candidate = captured.get("candidate")
    if not routed.bound_once:
        raise worker.WorkerError("Deep Agents did not bind the role-lane tools")
    if candidate is None:
        raise worker.WorkerError("invalid_agent_output: no candidate submitted")
    candidate = lane.validate_candidate(candidate, trusted_job)
    with _state_lock(state):
        progress.update(
            {"status": "completed", "candidate_sha256": _sha256(candidate)}
        )
    event("candidate", f"role:{trusted_job['role']}:candidate")
    lane._checkpoint_if_enabled(state, f"role:{identity}:completed")
    return candidate
