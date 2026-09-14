"""Generic progress, timing, and authenticated-accounting reduction."""

from __future__ import annotations

import copy
import hashlib
from decimal import Decimal, InvalidOperation
from typing import Any

from .contracts import ContractError, canonical_json_bytes, validate_proxy_receipt


class SummaryError(RuntimeError):
    """Mutable run state cannot be reduced to authenticated result data."""


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def receipt_cost(receipts: Any) -> Decimal:
    total = Decimal("0.000000")
    if not isinstance(receipts, list):
        return total
    try:
        for receipt in receipts:
            total += Decimal(receipt["cost"]["amount"])
    except (KeyError, TypeError, InvalidOperation) as exc:
        raise SummaryError("accepted model receipt cost is invalid") from exc
    return total


def receipt_tokens(receipts: Any) -> dict[str, int]:
    totals = {"input": 0, "output": 0, "total": 0}
    if not isinstance(receipts, list):
        return totals
    for receipt in receipts:
        usage = receipt.get("usage", {}) if isinstance(receipt, dict) else {}
        for target, source in (
            ("input", "input_tokens"),
            ("output", "output_tokens"),
            ("total", "total_tokens"),
        ):
            value = usage.get(source)
            if type(value) is int and value >= 0:
                totals[target] += value
    return totals


def model_summary(state: dict[str, Any]) -> dict[str, Any]:
    exchanges = state.get("model_exchanges")
    accepted = list(exchanges.values()) if isinstance(exchanges, dict) else []
    rejections = state.get("receipt_rejections")
    rejected = rejections if isinstance(rejections, list) else []
    request_ids = [
        item.get("request", {}).get("request_id")
        for item in accepted
        if isinstance(item, dict)
    ] + [
        item.get("request_id") for item in rejected if isinstance(item, dict)
    ]
    request_ids = [item for item in request_ids if isinstance(item, str)]
    prompts = [
        item.get("request", {}).get("prompt_sha256")
        for item in accepted
        if isinstance(item, dict)
    ]
    return {
        "attempts": len(request_ids),
        "retries": len(request_ids) - len(set(request_ids)),
        "prompt_sha256": [item for item in prompts if isinstance(item, str)],
    }


def _cost_classification(run: dict[str, Any]) -> str | None:
    lock = run.get("lock")
    fixed_proxy = lock.get("fixed_proxy") if isinstance(lock, dict) else None
    locked = (
        fixed_proxy.get("cost_classification")
        if isinstance(fixed_proxy, dict)
        else None
    )
    actual = run.get("cost_classification")
    if actual != locked:
        raise SummaryError("run cost classification does not match toolchain lock")
    return locked if isinstance(locked, str) else None


def validate_model_exchanges(
    run: dict[str, Any], state: dict[str, Any]
) -> list[dict[str, Any]]:
    receipts = state.get("receipts")
    exchanges = state.get("model_exchanges")
    model_id = state.get("config", {}).get("model")
    if (
        not isinstance(receipts, list)
        or not receipts
        or not isinstance(exchanges, dict)
        or len(exchanges) != len(receipts)
        or not isinstance(model_id, str)
    ):
        raise SummaryError("provider receipt exchange binding is incomplete")
    if state.get("pending_model_exchanges"):
        raise SummaryError("provider model exchanges are not reconciled")

    accepted: list[dict[str, Any]] = []
    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    seen_sequences: set[int] = set()
    try:
        for receipt in receipts:
            request_id = receipt.get("request_id") if isinstance(receipt, dict) else None
            exchange = exchanges.get(request_id)
            if not isinstance(exchange, dict) or exchange.get("receipt") != receipt:
                raise SummaryError("provider receipt exchange binding mismatch")
            request = exchange.get("request")
            response = exchange.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                raise SummaryError("provider receipt exchange is incomplete")
            sequence = request.get("sequence")
            binding = {
                "run_id": run["run_id"],
                "request_id": request_id,
                "model_id": model_id,
                "sequence": sequence,
            }
            if (
                type(sequence) is not int
                or sequence in seen_sequences
                or any(request.get(name) != value for name, value in binding.items())
                or any(response.get(name) != value for name, value in binding.items())
            ):
                raise SummaryError("provider receipt exchange identity mismatch")
            validate_proxy_receipt(
                receipt,
                run_id=run["run_id"],
                sequence=sequence,
                request_id=request_id,
                model_id=model_id,
                request_sha256=_sha(request),
                response_sha256=_sha(response),
                seen_receipt_sha256=seen_receipts,
                seen_request_ids=seen_requests,
            )
            seen_receipts.add(receipt["receipt_sha256"])
            seen_requests.add(request_id)
            seen_sequences.add(sequence)
            accepted.append(copy.deepcopy(exchange))
    except (ContractError, KeyError, TypeError) as exc:
        raise SummaryError("provider receipt authentication failed") from exc
    if seen_requests != set(exchanges):
        raise SummaryError("provider receipt exchange set mismatch")
    sequences = [exchange["request"]["sequence"] for exchange in accepted]
    if sequences != sorted(sequences):
        raise SummaryError("provider receipt sequence order mismatch")
    return accepted


def reduce_accounting(
    run: dict[str, Any], state: dict[str, Any]
) -> dict[str, Any]:
    classification = _cost_classification(run)
    receipts = state.get("receipts")
    receipts = receipts if isinstance(receipts, list) else []
    signed = any(
        isinstance(receipt, dict)
        and (
            receipt.get("schema") == "autofv-model-proxy-receipt/v1"
            or "auth" in receipt
        )
        for receipt in receipts
    )
    if signed:
        if classification not in {"provider_authenticated", "synthetic_fixture"}:
            raise SummaryError("signed receipt cost classification is invalid")
        exchanges = validate_model_exchanges(run, state)
        reduced_receipts = [exchange["receipt"] for exchange in exchanges]
    else:
        if classification == "provider_authenticated":
            raise SummaryError("provider-authenticated receipts are missing")
        exchanges = []
        reduced_receipts = receipts

    totals = {
        "requests": len(reduced_receipts),
        "tokens": receipt_tokens(reduced_receipts),
        "cost_usd": f"{receipt_cost(reduced_receipts):.6f}",
    }
    zero = {
        "requests": 0,
        "tokens": {"input": 0, "output": 0, "total": 0},
        "cost_usd": "0.000000",
    }
    accounting = {
        "provider_authenticated": (
            copy.deepcopy(totals)
            if classification == "provider_authenticated"
            else copy.deepcopy(zero)
        ),
        "synthetic": (
            copy.deepcopy(totals)
            if classification == "synthetic_fixture"
            else copy.deepcopy(zero)
        ),
        "estimated": copy.deepcopy(state.get("estimated_accounting")),
    }
    return {
        "classification": classification,
        "requests": totals["requests"],
        "tokens": totals["tokens"],
        "cost": Decimal(totals["cost_usd"]),
        "accounting": accounting,
        "model_exchanges": exchanges,
    }


def _six_decimal(value: Any, label: str) -> str:
    try:
        return f"{Decimal(value):.6f}"
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise SummaryError(f"{label} is invalid") from exc


def render_generic_summary(
    run: dict[str, Any],
    state: dict[str, Any],
    report: dict[str, Any],
    *,
    verifier_bound: bool,
    accounting: dict[str, Any],
) -> dict[str, Any]:
    target_states = copy.deepcopy(
        state["target_states"] if isinstance(state.get("target_states"), dict) else {}
    )
    accepted = {
        node
        for node, target in target_states.items()
        if isinstance(target, dict) and target.get("status") == "accepted"
    }
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    verified = (
        verifier_bound
        and report.get("verdict") == "PASS"
        and all(checks.get(name) is True for name in ("clean_build", "target_closure", "holes"))
    )
    graph = state.get("graph") if isinstance(state.get("graph"), dict) else {}
    frozen = graph.get("frozen_targets") if isinstance(graph.get("frozen_targets"), list) else []
    selected = graph.get("selected_nodes") if isinstance(graph.get("selected_nodes"), list) else []
    model = model_summary(state)
    timing = state.get("timing_seconds")
    timing = timing if isinstance(timing, dict) else {}
    contracts = state.get("contracts")
    contracts = contracts if isinstance(contracts, dict) else {}
    tool_calls = state.get("tool_calls")
    compactions = state.get("compaction_calls")
    return {
        "target_states": target_states,
        "verified_counts": {
            "targets": len(accepted.intersection(frozen)) if verified else 0,
            "declarations": len(accepted) if verified else 0,
            "closure": len(accepted.intersection(selected)) if verified else 0,
        },
        "block_chains": copy.deepcopy(state.get("block_chains", {})),
        "contract_history": {
            "revision_lineage": copy.deepcopy(contracts.get("revision_lineage", [])),
            "invalidated_fingerprints": copy.deepcopy(
                contracts.get("invalidated_fingerprints", [])
            ),
            "invalidated_consumers": copy.deepcopy(
                state.get("invalidated_consumers", [])
            ),
        },
        "calls": {
            "model": model["attempts"],
            "tool": len(tool_calls) if isinstance(tool_calls, (list, dict)) else 0,
            "retry": model["retries"],
            "compaction": len(compactions) if isinstance(compactions, (list, dict)) else 0,
        },
        "timing_seconds": {
            name: _six_decimal(timing.get(name, 0), f"{name} timing")
            for name in ("provider", "queue", "lean", "build")
        }
        | {"wall": _six_decimal(state.get("wall_seconds_used", 0), "wall timing")},
        "accounting": copy.deepcopy(accounting),
    }
