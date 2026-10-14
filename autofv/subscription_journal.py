"""Run-wide, authenticated subscription admission and atomic completion.

One process-shared file lock spans admission and the one-generation callback.
The signed private journal is durable before dispatch and is never reset by a
role change or restart. A dispatched record without a completion is uncertain;
all new generation then stops. Public evidence contains continuation digests,
never native opaque reasoning state.
"""

from __future__ import annotations

import copy
import fcntl
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from . import provider_config, provider_messages, provider_receipts, subscription_receipts
from .contracts import canonical_json_bytes


ProviderError = provider_config.ProviderConfigError
SCHEMA = "autofv-subscription-journal/v1"
PUBLIC_SCHEMA = "autofv-subscription-journal-summary/v1"
MAX_JOURNAL_BYTES = 128 * 1024 * 1024
_FIELDS = {"schema", "run_id", "binding_sha256", "grant", "records", "auth", "record_sha256"}
_RECORD_FIELDS = {"status", "invocation", "request", "request_sha256", "history_sha256",
                  "admission", "response", "receipt", "continuation", "continuation_sha256",
                  "record_sha256"}


def _sha(value: Any) -> str:
    return provider_config.canonical_sha256(value)


def _paths(run: dict[str, Any]) -> tuple[Path, Path]:
    root = Path(run["run_root"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProviderError("subscription run root is unsafe")
    private = root / "provider-private"
    public = Path(run.get("evidence_dir", root / "evidence"))
    if public != root / "evidence":
        raise ProviderError("subscription evidence directory mismatch")
    for path in (private, public):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ProviderError("subscription journal directory is unsafe")
    if private.exists() and (stat.S_IMODE(private.stat().st_mode) & 0o077
                             or private.stat().st_uid != os.getuid()):
        raise ProviderError("subscription private journal permissions are unsafe")
    return private / "subscription-journal.json", public / "subscription-journal.json"


def _read(path: Path) -> dict[str, Any] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProviderError("subscription journal cannot be opened safely") from exc
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_JOURNAL_BYTES:
            raise ProviderError("subscription journal is not a bounded regular file")
        if path.parent.name == "provider-private" and (stat.S_IMODE(info.st_mode) & 0o077
                                                       or info.st_uid != os.getuid()):
            raise ProviderError("subscription private journal permissions are unsafe")
        raw = stream.read(MAX_JOURNAL_BYTES + 1)
    try:
        value = json.loads(raw)
        if len(raw) > MAX_JOURNAL_BYTES or raw != canonical_json_bytes(value) + b"\n":
            raise ValueError("noncanonical")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ProviderError("subscription journal is invalid") from exc
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    raw = canonical_json_bytes(value) + b"\n"
    if len(raw) > MAX_JOURNAL_BYTES:
        raise ProviderError("subscription journal exceeds its bound")
    path.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise ProviderError("subscription journal path is unsafe")
    descriptor, temporary = tempfile.mkstemp(prefix=".subscription-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _sign(binding: provider_config.ProviderBinding, body: dict[str, Any]) -> dict[str, Any]:
    signed = {**body, "auth": provider_receipts._sign(binding, body)}
    return {**signed, "record_sha256": _sha(signed)}


def _record(body: dict[str, Any]) -> dict[str, Any]:
    return {**body, "record_sha256": _sha(body)}


def _journal(binding: provider_config.ProviderBinding, records: list[dict[str, Any]],
             *, public: bool = False) -> dict[str, Any]:
    if public:
        records = [{key: copy.deepcopy(value) for key, value in record.items()
                    if key != "continuation"} for record in records]
    return _sign(binding, {
        "schema": PUBLIC_SCHEMA if public else SCHEMA,
        "run_id": binding.public["run_id"], "binding_sha256": binding.public["binding_sha256"],
        "grant": copy.deepcopy(binding.public["grant"]), "records": records,
    })


def _verify(value: Any, public: dict[str, Any], *, private: bool) -> dict[str, Any]:
    value = provider_config.exact_dict(value, _FIELDS, "subscription journal")
    if (value["schema"] != (SCHEMA if private else PUBLIC_SCHEMA)
        or value["run_id"] != public["run_id"]
        or value["binding_sha256"] != public["binding_sha256"]
        or value["grant"] != public["grant"]
        or not isinstance(value["records"], list)
        or len(value["records"]) > public["grant"]["max_invocations"]):
        raise ProviderError("subscription journal grant or binding mismatch")
    signed = {key: item for key, item in value.items() if key != "record_sha256"}
    body = {key: item for key, item in signed.items() if key != "auth"}
    if value["record_sha256"] != _sha(signed):
        raise ProviderError("subscription journal digest mismatch")
    provider_receipts.verify_signature(body, value["auth"], public["receipt_authentication"],
                                       "subscription journal")
    seen_receipts: set[str] = set()
    seen_requests: set[str] = set()
    sequences: set[int] = set()
    last_sequence = 0
    uncertain = False
    for index, record in enumerate(value["records"], 1):
        provider_config.exact_dict(record, _RECORD_FIELDS if private else _RECORD_FIELDS - {"continuation"},
                                   "subscription journal record")
        request = record["request"]
        subscription_receipts._request_identity(public, request)
        if (record["invocation"] != index or type(record["invocation"]) is not int
            or record["request_sha256"] != _sha(request)
            or record["history_sha256"] != request["history_sha256"]
            or request["request_id"] in seen_requests or request["sequence"] in sequences
            or request["sequence"] <= last_sequence
            or record["status"] not in {"dispatched", "completed"} or uncertain):
            raise ProviderError("subscription journal record identity mismatch")
        expected_admission = _admission(public, request, index)
        if record["admission"] != expected_admission:
            raise ProviderError("subscription admission binding mismatch")
        if private and record["record_sha256"] != _sha({key: item for key, item in record.items()
                                                        if key != "record_sha256"}):
            raise ProviderError("subscription record digest mismatch")
        if record["status"] == "dispatched":
            if any(record[key] is not None for key in
                   (("response", "receipt", "continuation_sha256", "continuation") if private
                    else ("response", "receipt", "continuation_sha256"))):
                raise ProviderError("subscription incomplete record contains terminal data")
            uncertain = True
        else:
            response, receipt = record["response"], record["receipt"]
            if not isinstance(response, dict) or any(response.get(key) != request[key]
                    for key in ("run_id", "sequence", "request_id", "model_id", "role")):
                raise ProviderError("subscription response identity mismatch")
            subscription_receipts.validate_receipt(
                receipt, binding=public, run_id=public["run_id"], sequence=request["sequence"],
                request_id=request["request_id"], model_id=request["model_id"],
                request_sha256=_sha(request), response_sha256=_sha(response),
                seen_receipt_sha256=seen_receipts, seen_request_ids=seen_requests,
                request=request, continuation=record["continuation"] if private else None)
            if record["continuation_sha256"] != receipt["continuation_sha256"]:
                raise ProviderError("subscription record continuation binding mismatch")
            if private:
                from .pi_process import validate_continuation
                validate_continuation(record["continuation"], request, response)
            seen_receipts.add(receipt["receipt_sha256"])
        seen_requests.add(request["request_id"])
        sequences.add(request["sequence"])
        last_sequence = request["sequence"]
    return value


def _admission(public: dict[str, Any], request: dict[str, Any], invocation: int) -> dict[str, Any]:
    return {
        "schema": "autofv-pi-admission/v1", "run_id": public["run_id"],
        "request_id": request["request_id"], "sequence": request["sequence"],
        "binding_sha256": public["binding_sha256"], "grant_sha256": _sha(public["grant"]),
        "request_sha256": _sha(request), "history_sha256": request["history_sha256"],
        "deadline_epoch_ms": public["grant"]["original_deadline_epoch_ms"],
        "invocation": invocation, "max_invocations": public["grant"]["max_invocations"],
    }


def _check_memory(run: dict[str, Any], records: list[dict[str, Any]], public: dict[str, Any]) -> None:
    remembered = run.get("subscription_journal")
    if remembered is None:
        return
    _verify(remembered, public, private=False)
    if run.get("subscription_journal_sha256", remembered["record_sha256"]) != remembered["record_sha256"]:
        raise ProviderError("subscription remembered journal digest mismatch")
    disk = {record["request"]["request_id"]: record for record in records}
    for prior in remembered["records"]:
        current = disk.get(prior["request"]["request_id"])
        if (current is None or prior["request_sha256"] != current["request_sha256"]
            or prior["admission"] != current["admission"]
            or (prior["status"] == "completed" and prior["record_sha256"] != current["record_sha256"])):
            raise ProviderError("subscription journal rollback or missing record")


@contextmanager
def _locked(path: Path, deadline_ms: int):
    path.parent.mkdir(mode=0o700, exist_ok=True)
    if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise ProviderError("subscription private journal permissions are unsafe")
    try:
        descriptor = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ProviderError("subscription journal lock is unsafe") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProviderError("subscription journal lock is unsafe")
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time_ns() // 1_000_000 >= deadline_ms:
                    raise ProviderError("subscription original deadline expired", classification="timeout")
                time.sleep(0.01)
        yield
    finally:
        os.close(descriptor)


def _publish(run: dict[str, Any], binding: provider_config.ProviderBinding,
             public_path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _journal(binding, records, public=True)
    # Remember before publication: failure cannot erase durable dispatched state.
    run["subscription_journal"] = copy.deepcopy(summary)
    run["subscription_journal_sha256"] = summary["record_sha256"]
    _write(public_path, summary)
    return summary


def initialize(run: dict[str, Any], binding: provider_config.ProviderBinding) -> None:
    """Create the original signed empty journal, or recover the same grant."""
    public = subscription_receipts._public(binding)
    if run.get("run_id") != public["run_id"] or run.get("provider_binding") != public:
        raise ProviderError("subscription run binding mismatch")
    private_path, public_path = _paths(run)
    with _locked(private_path, public["grant"]["original_deadline_epoch_ms"]):
        stored = _read(private_path)
        records = _verify(stored, public, private=True)["records"] if stored is not None else []
        _check_memory(run, records, public)
        if stored is None:
            if _read(public_path) is not None:
                raise ProviderError("subscription private journal is missing")
            _write(private_path, _journal(binding, []))
        _publish(run, binding, public_path, records)


def dispatch(
    run: dict[str, Any], binding: provider_config.ProviderBinding,
    request: dict[str, Any], messages: list[dict[str, Any]],
    generate: Callable[[dict[str, Any], list[dict[str, Any]]], Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Admit one generation or replay a complete exchange without another call.

generate(admission, continuations) returns (response, raw_usage, continuation)
or the same tuple plus keyword metadata accepted by build_receipt. All ordinary
or fatal exceptions after durable dispatch leave an unresolved record.
"""
    public = subscription_receipts._public(binding)
    subscription_receipts._request_identity(public, request)
    if run.get("run_id") != public["run_id"] or run.get("provider_binding") != public:
        raise ProviderError("subscription run binding mismatch")
    messages = provider_messages.validate_messages(messages, binding)
    if _sha(messages) != request["history_sha256"]:
        raise ProviderError("subscription canonical history digest mismatch")
    private_path, public_path = _paths(run)
    with _locked(private_path, public["grant"]["original_deadline_epoch_ms"]):
        stored = _read(private_path)
        records = _verify(stored, public, private=True)["records"] if stored is not None else []
        _check_memory(run, records, public)
        request_id = request["request_id"]
        existing = next((record for record in records if record["request"]["request_id"] == request_id), None)
        if existing is not None:
            if existing["request"] != request:
                raise ProviderError("subscription replay request mismatch")
            if existing["status"] != "completed":
                raise ProviderError("subscription dispatch outcome is ambiguous")
            _publish(run, binding, public_path, records)
            return copy.deepcopy(existing["response"]), copy.deepcopy(existing["receipt"])
        if any(record["status"] != "completed" for record in records):
            raise ProviderError("subscription unresolved dispatch blocks generation")
        if any(record["request"]["sequence"] >= request["sequence"] for record in records):
            raise ProviderError("subscription sequence is duplicated or stale")
        if len(records) >= public["grant"]["max_invocations"]:
            raise ProviderError("subscription run invocation ceiling exhausted", classification="quota_exhausted")
        if time.time_ns() // 1_000_000 >= public["grant"]["original_deadline_epoch_ms"]:
            raise ProviderError("subscription original deadline expired", classification="timeout")
        if time.time_ns() // 1_000_000 < public["grant"]["original_started_epoch_ms"]:
            raise ProviderError("subscription original grant has not started")
        # Enforce exact history-to-native metadata pairing before dispatch. A
        # conversation may not invent, omit, reorder, or alter completed calls.
        conversation = [record for record in records if record["request"]["conversation_id"] == request["conversation_id"]]
        from .pi_process import validate_continuation
        continuations = []
        assistant_calls = [(index, item) for index, item in enumerate(messages)
                           if item["role"] == "assistant" and item.get("tool_calls")]
        if len(assistant_calls) != len(conversation):
            raise ProviderError("subscription continuation history count mismatch")
        for prior, (message_index, assistant) in zip(conversation, assistant_calls):
            if prior["request"]["role"] != request["role"] or prior["request"]["model_id"] != request["model_id"]:
                raise ProviderError("subscription conversation role or model changed")
            continuation = prior["continuation"]
            validate_continuation(continuation, prior["request"], prior["response"])
            calls = assistant["tool_calls"]
            expected_call = continuation["tool_call"]
            if (assistant["content"] not in {None, ""}
                or prior["history_sha256"] != _sha(messages[:message_index])
                or len(calls) != 1 or calls[0].get("id") != continuation["canonical_tool_id"]
                or calls[0].get("function", {}).get("name") != expected_call["name"]
                or calls[0].get("function", {}).get("arguments") != canonical_json_bytes(expected_call["arguments"]).decode()):
                raise ProviderError("subscription canonical tool history mismatch")
            continuations.append(copy.deepcopy(continuation))
        admission = _admission(public, request, len(records) + 1)
        dispatched = _record({
            "status": "dispatched", "invocation": len(records) + 1,
            "request": copy.deepcopy(request), "request_sha256": _sha(request),
            "history_sha256": request["history_sha256"], "admission": admission,
            "response": None, "receipt": None, "continuation": None, "continuation_sha256": None,
        })
        records.append(dispatched)
        _write(private_path, _journal(binding, records))
        _publish(run, binding, public_path, records)
        result = generate(copy.deepcopy(admission), continuations)
        if not isinstance(result, tuple) or len(result) not in {3, 4}:
            raise ProviderError("subscription generation terminal result is invalid")
        response, raw_usage, continuation = result[:3]
        metadata = result[3] if len(result) == 4 else {}
        if not isinstance(metadata, dict) or set(metadata) - {"provider_response_id", "termination", "observed_effort"}:
            raise ProviderError("subscription terminal metadata is invalid")
        receipt = subscription_receipts.build_receipt(binding, request, response, raw_usage, continuation, **metadata)
        completed = _record({**{key: value for key, value in dispatched.items() if key != "record_sha256"},
            "status": "completed", "response": copy.deepcopy(response), "receipt": receipt,
            "continuation": copy.deepcopy(continuation), "continuation_sha256": _sha(continuation),
        })
        records[-1] = completed
        # One atomic replace publishes response + attestation + continuation.
        _write(private_path, _journal(binding, records))
        _publish(run, binding, public_path, records)
        return copy.deepcopy(response), copy.deepcopy(receipt)


def validate_recovery_artifacts(
    run: dict[str, Any], state: dict[str, Any], *, binding: Any, require_private: bool = True,
) -> dict[str, Any]:
    """Verify retained signed summaries; runtime additionally validates private state."""
    public = subscription_receipts._public(binding)
    pinned = binding if isinstance(binding, provider_config.ProviderBinding) else None
    if (run.get("run_id") != public["run_id"] or run.get("provider_binding") != public
        or run.get("provider_binding_sha256") != public["binding_sha256"]):
        raise ProviderError("subscription recovery binding mismatch")
    private_path, public_path = _paths(run)
    summary = _read(public_path)
    if summary is None:
        raise ProviderError("subscription journal summary is missing")
    summary = _verify(summary, public, private=False)
    records = summary["records"]
    if require_private:
        private = _read(private_path)
        if private is None:
            raise ProviderError("subscription private journal is missing")
        private = _verify(private, public, private=True)
        _check_memory(run, private["records"], public)
        projection = [{key: value for key, value in record.items() if key != "continuation"}
                      for record in private["records"]]
        if projection != summary["records"]:
            # Atomic private completion can precede public publication. Only the
            # still-pinned signer may repair that exact authenticated transition.
            _check_memory({"subscription_journal": summary}, private["records"], public)
            if pinned is None:
                try:
                    pinned = provider_config.provider_binding(run)
                except provider_config.ProviderConfigError:
                    pass
            if pinned is None or pinned.public != public:
                raise ProviderError("subscription private/public journal mismatch")
            summary = _publish(run, pinned, public_path, private["records"])
        records = private["records"]
    _check_memory(run, records, public)
    journal = {record["request"]["request_id"]: copy.deepcopy(record) for record in records}
    for collection in (state.get("model_exchanges", {}), state.get("pending_model_exchanges", {})):
        if not isinstance(collection, dict):
            raise ProviderError("subscription recovery exchange collection mismatch")
        for request_id, exchange in collection.items():
            if not isinstance(exchange, dict) or not isinstance(exchange.get("request"), dict):
                raise ProviderError("subscription recovery exchange mismatch")
            record = journal.get(request_id)
            if record is not None and record["request"] != exchange["request"]:
                raise ProviderError("subscription recovery request mismatch")
    return {"journal": journal, "summary": summary, "journal_sha256": summary["record_sha256"]}


def validate_completed(run: dict[str, Any], request: dict[str, Any],
                       response: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Validate native private continuation even for checkpoint-only replay."""
    recovered = validate_recovery_artifacts(run, {}, binding=run["provider_binding"])
    record = recovered["journal"].get(request.get("request_id"))
    if record is None or record["status"] != "completed" or any(
            record[key] != value for key, value in
            (("request", request), ("response", response), ("receipt", receipt))):
        raise ProviderError("subscription completed checkpoint replay mismatch")


def completed_exchange(
    run: dict[str, Any], binding: provider_config.ProviderBinding,
    request: dict[str, Any], messages: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Recover a completed private exchange without admission, clock renewal or SDK."""
    public = subscription_receipts._public(binding)
    subscription_receipts._request_identity(public, request)
    if run.get("run_id") != public["run_id"] or run.get("provider_binding") != public:
        raise ProviderError("subscription run binding mismatch")
    validated_messages = provider_messages.validate_messages(messages, binding)
    if _sha(validated_messages) != request["history_sha256"]:
        raise ProviderError("subscription replay history mismatch")
    private_path, public_path = _paths(run)
    with _locked(private_path, public["grant"]["original_deadline_epoch_ms"]):
        stored = _read(private_path)
        records = _verify(stored, public, private=True)["records"] if stored is not None else []
        _check_memory(run, records, public)
        if stored is None and _read(public_path) is not None:
            raise ProviderError("subscription private journal is missing")
        existing = next((record for record in records
                         if record["request"]["request_id"] == request["request_id"]), None)
        if existing is not None:
            if existing["request"] != request:
                raise ProviderError("subscription replay request mismatch")
            if existing["status"] != "completed":
                raise ProviderError("subscription dispatch outcome is ambiguous")
            _publish(run, binding, public_path, records)
            return copy.deepcopy(existing["response"]), copy.deepcopy(existing["receipt"])
        if any(record["status"] != "completed" for record in records):
            raise ProviderError("subscription unresolved dispatch blocks generation")
        return None
