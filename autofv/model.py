"""Authenticated model requests and proxy receipt accounting."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from . import worker
from .contracts import (
    BudgetExhausted,
    ContractError,
    HEX_SHA256,
    _exact_dict,
    _sha256,
    _text,
    canonical_json_bytes,
    validate_proxy_receipt,
)
from .run_state import (
    _RunState,
    _canonical_sha256,
    _charge_wall,
    _check_budget,
    _check_wall_budget,
    _checkpoint_if_enabled,
    _event_once,
)

try:
    from harness import agentproc
except ModuleNotFoundError as exc:
    if exc.name != "harness":
        raise

    def _missing_run_round(*args, **kwargs):
        raise ContractError("hashed control bundle is missing harness/agentproc.py")

    agentproc = SimpleNamespace(run_round=_missing_run_round)

def _prompt_sha256(run_id: str, request_id: str, role: str) -> str:
    raw = f"{run_id}\0{request_id}\0{role}\0bounded-v1".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _next_model_sequence(state: _RunState) -> int:
    sequences = [item["sequence"] for item in state.get("receipts", [])]
    for exchanges in (
        state.get("model_exchanges", {}),
        state.get("pending_model_exchanges", {}),
    ):
        sequences.extend(
            exchange["request"]["sequence"]
            for exchange in exchanges.values()
            if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict)
        )
    return max(sequences, default=0) + 1


def _model_envelope(
    state: _RunState,
    *,
    request_id: str,
    role: str,
    input_hashes: list[str],
    batch_id: str | None = None,
    sequence: int | None = None,
) -> dict[str, Any]:
    run, config = state["run"], state["config"]
    return {
        "schema": "autofv-model-request/v1",
        "run_id": run["run_id"],
        "sequence": sequence if sequence is not None else _next_model_sequence(state),
        "batch_id": batch_id,
        "request_id": request_id,
        "role": role,
        "model_id": config["model"],
        "input_hashes": sorted(set(input_hashes)),
        "prompt_sha256": _prompt_sha256(run["run_id"], request_id, role),
    }


def _validate_model_exchange(
    state: _RunState,
    request: dict[str, Any],
    response: Any,
    receipt: Any,
    *,
    enforce_sequence: bool,
) -> tuple[dict[str, Any], dict[str, Any], Decimal]:
    run, config = state["run"], state["config"]
    request_id = request.get("request_id")
    pending = [
        exchange
        for stored_id, exchange in state.get("pending_model_exchanges", {}).items()
        if stored_id != request_id and isinstance(exchange, dict)
    ]
    seen_sequences = {
        item.get("sequence") for item in state["receipts"] if isinstance(item, dict)
    } | {
        exchange["request"].get("sequence")
        for exchange in pending
        if isinstance(exchange.get("request"), dict)
    }
    if request.get("sequence") in seen_sequences:
        raise ContractError("duplicate proxy receipt sequence")
    response = _validate_model_response(response, request, run["base_commit"])
    amount = validate_proxy_receipt(
        receipt,
        run_id=run["run_id"],
        sequence=request["sequence"],
        request_id=request["request_id"],
        model_id=config["model"],
        request_sha256=_canonical_sha256(request),
        response_sha256=_canonical_sha256(response),
        seen_receipt_sha256={item["receipt_sha256"] for item in state["receipts"]}
        | {
            exchange["receipt"].get("receipt_sha256")
            for exchange in pending
            if isinstance(exchange.get("receipt"), dict)
        },
        seen_request_ids={item["request_id"] for item in state["receipts"]}
        | set(state.get("pending_model_exchanges", {})) - {request_id},
    )
    if enforce_sequence and request["sequence"] != len(state["receipts"]) + 1:
        raise ContractError("proxy receipt sequence is not next for this run")
    return (
        json.loads(canonical_json_bytes(response)),
        json.loads(canonical_json_bytes(receipt)),
        amount,
    )


def _record_model_rejection(
    state: _RunState,
    request: dict[str, Any],
    receipt: Any,
    error: ContractError,
    *,
    checkpoint: bool,
) -> None:
    try:
        payload_sha256 = _canonical_sha256(receipt)
    except ContractError:
        payload_sha256 = hashlib.sha256(
            f"noncanonical:{type(receipt).__name__}".encode()
        ).hexdigest()
    state.setdefault("pending_model_exchanges", {}).pop(
        request.get("request_id"), None
    )
    state.setdefault("receipt_rejections", []).append(
        {
            "request_id": request.get("request_id"),
            "sequence": request.get("sequence"),
            "receipt_payload_sha256": payload_sha256,
            "reason": str(error)[:1000],
        }
    )
    if checkpoint:
        _checkpoint_if_enabled(state, f"receipt:{request.get('request_id')}:rejected")


def _invoke_model(
    state: _RunState,
    request: dict[str, Any],
    *,
    checkpoint: bool = True,
    call_kind: str = "explicit",
) -> tuple[dict[str, Any], dict[str, Any]]:
    if checkpoint:
        _check_budget(state)
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:before")
    runner = state["run_round"]
    try:
        if runner is agentproc.run_round:
            exchange = worker.proxy_round(state["run"], request)
        else:
            exchange = runner(request)
    except Exception:
        if checkpoint:
            _charge_wall(state)
            _checkpoint_if_enabled(state, f"model:{request['request_id']}:failed")
        raise
    try:
        response, receipt, _ = _validate_model_exchange(
            state,
            request,
            exchange[0],
            exchange[1],
            enforce_sequence=False,
        )
    except ContractError as exc:
        if checkpoint:
            _charge_wall(state)
        _record_model_rejection(
            state, request, exchange[1], exc, checkpoint=checkpoint
        )
        raise
    if checkpoint:
        _charge_wall(state)
        state.setdefault("pending_model_exchanges", {})[request["request_id"]] = {
            "request": request,
            "response": response,
            "receipt": receipt,
            "call_kind": call_kind,
        }
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:after")
    return response, receipt


def _accept_model_exchange(
    state: _RunState,
    request: dict[str, Any],
    response: dict[str, Any],
    receipt: dict[str, Any],
    *,
    enforce_budget: bool = True,
    allow_out_of_order: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        response, receipt, amount = _validate_model_exchange(
            state,
            request,
            response,
            receipt,
            enforce_sequence=not allow_out_of_order,
        )
    except ContractError as exc:
        _record_model_rejection(state, request, receipt, exc, checkpoint=True)
        raise

    request = json.loads(canonical_json_bytes(request))
    run, config = state["run"], state["config"]
    pending = state.setdefault("pending_model_exchanges", {}).get(
        request["request_id"], {}
    )
    call_kind = pending.get("call_kind", "explicit")
    if call_kind not in _MODEL_CALL_KINDS:
        raise ContractError("stored model call kind is invalid")
    new_cost = state["cost"] + amount
    state["cost"] = new_cost
    state["receipts"].append(receipt)
    state["receipts"].sort(key=lambda item: item["sequence"])
    exchange = {
        "request": request,
        "response": response,
        "receipt": receipt,
        "call_kind": call_kind,
    }
    state.setdefault("model_exchanges", {})[request["request_id"]] = exchange
    state.setdefault("pending_model_exchanges", {}).pop(request["request_id"], None)
    _event_once(run, f"proxy:{request['request_id']}")
    if enforce_budget and new_cost > config["max_cost_usd"]:
        _checkpoint_if_enabled(state, "budget:cost_usd")
        raise BudgetExhausted("cost_usd", config["max_cost_usd"], new_cost)
    if receipt["status"] != "ok":
        _checkpoint_if_enabled(state, f"model:{request['request_id']}:rejected")
        raise ContractError("model proxy returned a non-success status")
    if enforce_budget:
        try:
            _check_wall_budget(state)
        except BudgetExhausted:
            _checkpoint_if_enabled(state, "budget:wall_seconds")
            raise
    _checkpoint_if_enabled(state, f"model:{request['request_id']}:accepted")
    return response, receipt


_MODEL_CALL_KINDS = frozenset(
    {"explicit", "retry", "schema_correction", "compaction", "framework"}
)


def _bind_model_call_kind(
    state: _RunState,
    request_id: str,
    call_kind: str,
    stored: dict[str, Any] | None,
    *,
    record_event: bool,
) -> None:
    if call_kind not in _MODEL_CALL_KINDS:
        raise ContractError("model call kind is invalid")
    prefix = f"model:{request_id}:reserved:"
    reserved = {
        event.removeprefix(prefix)
        for event in state["run"].setdefault("events", [])
        if isinstance(event, str) and event.startswith(prefix)
    }
    if reserved and reserved != {call_kind}:
        raise ContractError(f"resumed model call kind changed: {request_id}")
    if stored is not None:
        stored_kind = stored.get("call_kind", "explicit")
        if stored_kind != call_kind:
            raise ContractError(f"resumed model call kind changed: {request_id}")
        stored.setdefault("call_kind", call_kind)
    if record_event:
        _event_once(state["run"], f"{prefix}{call_kind}")
        _checkpoint_if_enabled(state, f"model:{request_id}:reserved")


def _model_request(
    state: _RunState,
    *,
    request_id: str,
    role: str,
    input_hashes: list[str],
    batch_id: str | None = None,
    call_kind: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    classified_kind = "explicit" if call_kind is None else call_kind
    completed = state.setdefault("model_exchanges", {}).get(request_id)
    pending = state.setdefault("pending_model_exchanges", {}).get(request_id)
    stored = completed or pending
    try:
        stored_sequence = stored["request"]["sequence"] if stored is not None else None
    except (KeyError, TypeError) as exc:
        raise ContractError(f"stored model request is invalid: {request_id}") from exc
    try:
        request = _model_envelope(
            state,
            request_id=request_id,
            role=role,
            input_hashes=input_hashes,
            batch_id=batch_id,
            sequence=stored_sequence,
        )
        if completed is not None:
            if completed.get("request") != request:
                raise ContractError(f"resumed model request changed: {request_id}")
        if pending is not None and pending.get("request") != request:
            raise ContractError(f"pending model request changed: {request_id}")
        _bind_model_call_kind(
            state,
            request_id,
            classified_kind,
            stored,
            record_event=call_kind is not None,
        )
        if completed is not None:
            return completed["response"], completed["receipt"]
        if pending is not None:
            return _accept_model_exchange(
                state, request, pending.get("response"), pending.get("receipt")
            )
        return _accept_model_exchange(
            state,
            request,
            *_invoke_model(state, request, call_kind=classified_kind),
        )
    except asyncio.CancelledError:
        incomplete = state.setdefault("pending_model_exchanges", {}).get(request_id)
        if not isinstance(incomplete, dict) or not {
            "request",
            "response",
            "receipt",
        } <= incomplete:
            state["pending_model_exchanges"].pop(request_id, None)
        _event_once(
            state["run"], f"model:{request_id}:reserved:{classified_kind}"
        )
        _event_once(state["run"], f"model:{request_id}:cancelled")
        try:
            _charge_wall(state)
            _checkpoint_if_enabled(state, f"model:{request_id}:cancelled")
        except Exception:
            pass
        raise


def _parallel_model_requests(
    state: _RunState, requests: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Run one proof frontier concurrently and account for it serially."""
    if len(requests) < 2:
        raise ContractError("a parallel proof frontier needs at least two lanes")
    stored = {
        **state.setdefault("model_exchanges", {}),
        **state.setdefault("pending_model_exchanges", {}),
    }
    used_sequences = [
        exchange["request"]["sequence"]
        for exchange in stored.values()
        if isinstance(exchange, dict) and isinstance(exchange.get("request"), dict)
    ] + [item["sequence"] for item in state["receipts"]]
    next_sequence = max(used_sequences, default=0) + 1
    envelopes = []
    for spec in requests:
        previous = stored.get(spec["request_id"])
        sequence = (
            previous["request"]["sequence"] if previous is not None else next_sequence
        )
        envelope = _model_envelope(state, sequence=sequence, **spec)
        if previous is not None and previous.get("request") != envelope:
            raise ContractError(f"resumed model request changed: {spec['request_id']}")
        if previous is None:
            next_sequence += 1
        envelopes.append(envelope)

    missing = [
        (index, request)
        for index, request in enumerate(envelopes)
        if request["request_id"] not in stored
    ]
    start_barrier = threading.Barrier(len(missing)) if len(missing) > 1 else None

    def invoke(request):
        started = time.monotonic_ns()
        if start_barrier is not None:
            start_barrier.wait()
        response, receipt = _invoke_model(state, request, checkpoint=False)
        return response, receipt, started, time.monotonic_ns()

    raw: list[tuple[dict[str, Any], dict[str, Any], int, int] | None] = [
        None
    ] * len(envelopes)
    for index, request in enumerate(envelopes):
        previous = stored.get(request["request_id"])
        if previous is not None:
            raw[index] = (previous["response"], previous["receipt"], 0, 0)
    if missing:
        _check_budget(state)
        _checkpoint_if_enabled(state, "model:proof-leaves:before")
        try:
            if len(missing) == 1:
                index, request = missing[0]
                raw[index] = invoke(request)
            else:
                with ThreadPoolExecutor(
                    max_workers=len(missing), thread_name_prefix="autofv-proof-lane"
                ) as pool:
                    futures = [
                        (index, request, pool.submit(invoke, request))
                        for index, request in missing
                    ]
                    for index, _request, future in futures:
                        raw[index] = future.result()
        except Exception:
            _charge_wall(state)
            _checkpoint_if_enabled(state, "model:proof-leaves:failed")
            raise
        _charge_wall(state)
        for index, request in missing:
            response, receipt, _, _ = raw[index]
            state["pending_model_exchanges"][request["request_id"]] = {
                "request": request,
                "response": response,
                "receipt": receipt,
                "call_kind": "explicit",
            }
            _checkpoint_if_enabled(state, f"model:{request['request_id']}:after")

    intervals = {
        request["request_id"]: {
            "started_monotonic_ns": item[2],
            "finished_monotonic_ns": item[3],
        }
        for request, item in zip(envelopes, raw, strict=True)
        if item is not None and item[2]
    }
    if len(missing) > 1 and max(
        item["started_monotonic_ns"] for item in intervals.values()
    ) >= min(item["finished_monotonic_ns"] for item in intervals.values()):
        raise ContractError("parallel proof lanes did not overlap")
    state.setdefault("lane_intervals", {}).update(intervals)
    for request, (response, receipt, _, _) in zip(envelopes, raw, strict=True):
        if request["request_id"] in state["model_exchanges"]:
            continue
        _accept_model_exchange(
            state, request, response, receipt, enforce_budget=False
        )
    if state["cost"] > state["config"]["max_cost_usd"]:
        _checkpoint_if_enabled(state, "budget:cost_usd")
        raise BudgetExhausted(
            "cost_usd", state["config"]["max_cost_usd"], state["cost"]
        )
    try:
        _check_wall_budget(state)
    except BudgetExhausted:
        _checkpoint_if_enabled(state, "budget:wall_seconds")
        raise
    exchanges = [
        (
            state["model_exchanges"][request["request_id"]]["response"],
            state["model_exchanges"][request["request_id"]]["receipt"],
        )
        for request in envelopes
    ]
    if len(missing) > 1:
        _event_once(state["run"], "proof_lanes:overlapped")
    elif missing:
        _event_once(state["run"], "proof_lanes:resumed")
    _checkpoint_if_enabled(state, "model:proof-leaves:accepted")
    return exchanges


def _validate_model_response(
    response: Any, request: dict[str, Any], base_commit: str
) -> dict[str, Any]:
    response = _exact_dict(
        response,
        {
            "schema",
            "run_id",
            "sequence",
            "batch_id",
            "request_id",
            "role",
            "model_id",
            "input_hashes",
            "prompt_sha256",
            "kind",
            "assigned_path",
            "base_commit",
            "statement_fingerprints",
            "payload",
            "payload_sha256",
        },
        "model response",
    )
    linked = {
        key: request[key]
        for key in (
            "run_id",
            "sequence",
            "batch_id",
            "request_id",
            "role",
            "model_id",
            "input_hashes",
            "prompt_sha256",
        )
    }
    if response["schema"] != "autofv-model-response/v1" or any(
        response[key] != value for key, value in linked.items()
    ):
        raise ContractError("model response request identity mismatch")
    if response["base_commit"] != base_commit:
        raise ContractError("model response base commit mismatch")
    if response["kind"] not in {
        "scout",
        "dependency_plan",
        "statement",
        "patch",
        "tool_call",
    }:
        raise ContractError("model response kind is unsupported")
    fingerprints = response["statement_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or fingerprints != sorted(set(fingerprints))
        or any(HEX_SHA256.fullmatch(value) is None for value in fingerprints)
    ):
        raise ContractError("model response statement fingerprints are invalid")
    if not isinstance(response["payload"], dict):
        raise ContractError("model response payload must be an object")
    payload_sha256 = _sha256(response["payload_sha256"], "model response payload hash")
    if not hmac.compare_digest(payload_sha256, _canonical_sha256(response["payload"])):
        raise ContractError("model response payload hash mismatch")
    payload = response["payload"]
    if response["kind"] == "statement":
        if payload.get("schema") != "autofv-statement-candidate/v1":
            raise ContractError("statement candidate schema mismatch")
        text = _text(payload.get("text"), "statement candidate text")
        if payload.get("text_sha256") != hashlib.sha256(text.encode()).hexdigest():
            raise ContractError("statement candidate text hash mismatch")
    elif response["kind"] == "patch":
        if payload.get("schema") != "autofv-candidate-patch/v1":
            raise ContractError("patch candidate schema mismatch")
        patch = payload.get("patch")
        if (
            not isinstance(patch, str)
            or not patch
            or "\r" in patch
            or "\x00" in patch
        ):
            raise ContractError("candidate patch must be canonical UTF-8 text")
        if payload.get("patch_sha256") != hashlib.sha256(patch.encode()).hexdigest():
            raise ContractError("candidate patch hash mismatch")
        if (
            payload.get("assigned_path") != response["assigned_path"]
            or payload.get("base_commit") != base_commit
            or payload.get("statement_fingerprints") != fingerprints
        ):
            raise ContractError("candidate patch bindings mismatch")
    elif response["kind"] == "tool_call":
        payload = _exact_dict(
            payload,
            {"schema", "name", "arguments"},
            "lane tool call",
        )
        if payload["schema"] != "autofv-lane-tool-call/v1":
            raise ContractError("lane tool call schema mismatch")
        _text(payload["name"], "lane tool call name")
        if not isinstance(payload["arguments"], dict):
            raise ContractError("lane tool call arguments must be an object")
    return response
