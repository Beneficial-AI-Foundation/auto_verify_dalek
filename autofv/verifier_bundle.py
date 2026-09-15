"""Hostile verifier-bundle parsing and deterministic report reduction."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import PurePosixPath
from typing import Any, Callable

from . import axiom_audit, contracts as contract_rules, probes, worker

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_MEMBERS = 16
BUNDLE_PAYLOAD_MEMBERS = frozenset(
    {
        "accepted/repository.bundle",
        "evidence/probe-aeneas.json",
        "evidence/probe-rust.json",
        "input/autofv.json",
        "state/verification.json",
    }
)
INVOCATION_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "invocation_id",
        "agent_worker_id",
        "verifier_worker_id",
        "snapshot_sha256",
        "manifest_sha256",
        "probe_rust_sha256",
        "probe_aeneas_sha256",
        "graph_sha256",
        "image_digest",
        "control_bundle_sha256",
        "native_decide_policy_sha256",
        "axiom_scope_sha256",
        "toolchain_lock_sha256",
        "accepted_commit",
        "accepted_tree_sha256",
        "bundle_sha256",
        "reference_sha256",
    }
)
STATE_FIELDS = frozenset(
    {
        "schema",
        "base_commit",
        "graph",
        "accepted_nodes",
        "frozen_contracts",
        "native_decide_uses",
        "compiler_assumptions",
    }
)
MEANING_FIELDS = frozenset(
    {
        "reference_integrity",
        "statement_equivalence",
        "non_vacuity",
        "broken_implementation_rejected",
    }
)
REPORT_CHECKS = frozenset(
    {
        "bundle",
        "reference_integrity",
        "runtime_identity",
        "exact_commit",
        "exact_tree",
        "fresh_cache",
        "clean_build",
        "target_closure",
        "statements",
        "scope",
        "holes",
        "trust",
        "native_decide",
        "kernel_axioms",
        "meaning",
    }
)
OBSERVED_FIELDS = frozenset(
    {
        "verifier_worker_id",
        "runtime_identity",
        "snapshot_sha256",
        "accepted_commit",
        "accepted_tree_sha256",
        "image_digest",
        "fresh_cache",
        "clean_build",
        "accepted_nodes",
        "status_by_node",
        "statement_fingerprints",
        "changed_paths",
        "holes",
        "trust_passed",
        "native_decide_policy_sha256",
        "native_decide_uses",
        "accepted_native_decide_uses",
        "hidden_native_decide_uses",
        "compiler_assumptions",
        "axiom_inventory",
        "meaning",
        "sorry_count_before",
        "sorry_count_after",
    }
)


class VerifierError(RuntimeError):
    """The clean verifier failed or returned an unauthoritative report."""

    report: dict[str, Any] | None = None


class VerifierInfrastructureError(VerifierError):
    """The clean verifier boundary could not be started or reached."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_float=lambda _: (_ for _ in ()).throw(
                ValueError("floating point values are forbidden")
            ),
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite value {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerifierError(f"invalid_{label}") from exc
    if not isinstance(value, dict):
        raise VerifierError(f"invalid_{label}")
    return value


def _safe_path(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(
        name
        and not path.is_absolute()
        and "\\" not in name
        and path.as_posix() == name
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(entries.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o444
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


def build_bundle(members: dict[str, bytes]) -> bytes:
    """Build the deterministic, exact-member clean-verifier bundle."""
    if set(members) != BUNDLE_PAYLOAD_MEMBERS or any(
        not isinstance(raw, bytes) for raw in members.values()
    ):
        raise VerifierError("member_set_mismatch")
    entries = [
        {"path": name, "sha256": _sha256(raw), "size": len(raw)}
        for name, raw in sorted(members.items())
    ]
    return _tar_bytes(
        {
            "manifest.json": _canonical_bytes(
                {"schema": "autofv-verifier-bundle/v1", "entries": entries}
            ),
            **members,
        }
    )


def _read_bundle(raw: bytes, expected_sha256: str) -> dict[str, bytes]:
    if not isinstance(raw, bytes) or len(raw) > MAX_BUNDLE_BYTES:
        raise VerifierError("bundle_too_large")
    if _sha256(raw) != expected_sha256:
        raise VerifierError("bundle_hash_mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members: dict[str, bytes] = {}
            total_size = 0
            for member in archive:
                if len(members) >= MAX_BUNDLE_MEMBERS:
                    raise VerifierError("member_count_exceeded")
                if not _safe_path(member.name):
                    raise VerifierError("unsafe_path")
                if not member.isreg():
                    raise VerifierError("unsafe_type")
                if member.name in members:
                    raise VerifierError("duplicate_member")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise VerifierError("member_too_large")
                total_size += member.size
                if total_size > MAX_BUNDLE_BYTES:
                    raise VerifierError("bundle_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise VerifierError("unsafe_type")
                content = source.read(MAX_MEMBER_BYTES + 1)
                if len(content) != member.size:
                    raise VerifierError("member_size_mismatch")
                members[member.name] = content
    except (tarfile.TarError, OSError) as exc:
        raise VerifierError("invalid_bundle") from exc

    if set(members) != BUNDLE_PAYLOAD_MEMBERS | {"manifest.json"}:
        raise VerifierError("member_set_mismatch")
    manifest = _strict_json(members.pop("manifest.json"), "bundle_manifest")
    if set(manifest) != {"schema", "entries"} or manifest.get("schema") != (
        "autofv-verifier-bundle/v1"
    ):
        raise VerifierError("bundle_manifest_mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(BUNDLE_PAYLOAD_MEMBERS):
        raise VerifierError("bundle_manifest_mismatch")
    observed_entries = []
    for name, content in sorted(members.items()):
        observed_entries.append(
            {"path": name, "sha256": _sha256(content), "size": len(content)}
        )
    if entries != observed_entries:
        recorded = {
            item.get("path"): item
            for item in entries
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        if set(recorded) == set(members) and any(
            recorded[name].get("sha256") != _sha256(content)
            for name, content in members.items()
        ):
            raise VerifierError("member_hash_mismatch")
        raise VerifierError("bundle_manifest_mismatch")
    return members


def _append(failures: list[str], reason: str, condition: bool) -> None:
    if condition and reason not in failures:
        failures.append(reason)


def _report(
    invocation: dict[str, Any],
    failures: list[str],
    *,
    checks: dict[str, bool] | None = None,
    state: dict[str, Any] | None = None,
    meaning: dict[str, Any] | None = None,
    axiom_inventory: list[dict[str, Any]] | None = None,
    sorry_count_before: int | None = None,
    sorry_count_after: int | None = None,
) -> dict[str, Any]:
    inventory = axiom_inventory or []
    try:
        accepted_uses, hidden_uses, all_uses = axiom_audit.native_use_provenance(
            inventory
        )
        inventory_sha256 = axiom_audit.inventory_identity_sha256(inventory)
    except contract_rules.ContractError:
        accepted_uses, hidden_uses, all_uses = [], [], []
        inventory_sha256 = _sha256(_canonical_bytes(inventory))
    body = {
        "schema": "autofv-verifier-report/v1",
        **{key: invocation[key] for key in sorted(INVOCATION_FIELDS - {"schema"})},
        "checks": checks or {},
        "failures": failures,
        "native_decide_uses": all_uses,
        "accepted_native_decide_uses": accepted_uses,
        "hidden_native_decide_uses": hidden_uses,
        "compiler_assumptions": (state or {}).get("compiler_assumptions", []),
        "axiom_inventory": inventory,
        "axiom_inventory_sha256": inventory_sha256,
        "meaning": meaning or {},
        "sorry_count_before": sorry_count_before,
        "sorry_count_after": sorry_count_after,
        "evidence_level": "L4" if not failures else "L0",
        "verdict": "PASS" if not failures else "FAIL",
    }
    return {**body, "report_sha256": _sha256(_canonical_bytes(body))}


def _valid_invocation(invocation: Any) -> dict[str, Any]:
    if not isinstance(invocation, dict) or set(invocation) != INVOCATION_FIELDS:
        raise VerifierError("verifier invocation fields mismatch")
    if invocation.get("schema") != "autofv-verifier-invocation/v1":
        raise VerifierError("verifier invocation schema mismatch")
    for field in (
        "run_id",
        "invocation_id",
        "agent_worker_id",
        "verifier_worker_id",
    ):
        if not isinstance(invocation[field], str) or not invocation[field]:
            raise VerifierError(f"verifier invocation {field} mismatch")
    for field in (
        "snapshot_sha256",
        "manifest_sha256",
        "probe_rust_sha256",
        "probe_aeneas_sha256",
        "graph_sha256",
        "control_bundle_sha256",
        "native_decide_policy_sha256",
        "axiom_scope_sha256",
        "toolchain_lock_sha256",
        "accepted_tree_sha256",
        "bundle_sha256",
        "reference_sha256",
    ):
        value = invocation[field]
        if not isinstance(value, str) or len(value) != 64 or any(
            char not in "0123456789abcdef" for char in value
        ):
            raise VerifierError(f"verifier invocation {field} mismatch")
    commit = invocation["accepted_commit"]
    if not isinstance(commit, str) or len(commit) not in {40, 64} or any(
        char not in "0123456789abcdef" for char in commit
    ):
        raise VerifierError("verifier invocation accepted_commit mismatch")
    if not isinstance(invocation["image_digest"], str) or not invocation[
        "image_digest"
    ].startswith("sha256:"):
        raise VerifierError("verifier invocation image_digest mismatch")
    return invocation


def verify_bundle(
    bundle: bytes,
    invocation: dict[str, Any],
    *,
    reference_bytes: bytes,
    run_checks: Callable[
        [dict[str, bytes], dict[str, Any], bytes], dict[str, Any]
    ],
) -> dict[str, Any]:
    """Validate hostile input, then reduce clean-worker observations to a report."""
    invocation = _valid_invocation(invocation)
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        members = _read_bundle(bundle, invocation["bundle_sha256"])
    except VerifierError as exc:
        return _report(invocation, [str(exc)], checks={"bundle": False})
    checks["bundle"] = True

    if _sha256(reference_bytes) != invocation["reference_sha256"]:
        return _report(
            invocation,
            ["reference_hash_mismatch"],
            checks={**checks, "reference_integrity": False},
        )
    checks["reference_integrity"] = True

    try:
        manifest = _strict_json(members["input/autofv.json"], "target_manifest")
        state = _strict_json(members["state/verification.json"], "verifier_state")
        reference = _strict_json(reference_bytes, "verifier_reference")
    except VerifierError as exc:
        return _report(invocation, [str(exc)], checks=checks)

    _append(
        failures,
        "manifest_hash_mismatch",
        _sha256(members["input/autofv.json"]) != invocation["manifest_sha256"],
    )
    _append(
        failures,
        "probe_rust_hash_mismatch",
        _sha256(members["evidence/probe-rust.json"])
        != invocation["probe_rust_sha256"],
    )
    _append(
        failures,
        "probe_aeneas_hash_mismatch",
        _sha256(members["evidence/probe-aeneas.json"])
        != invocation["probe_aeneas_sha256"],
    )
    if set(state) != STATE_FIELDS or state.get("schema") != "autofv-verifier-state/v1":
        return _report(invocation, failures + ["verifier_state_mismatch"], checks=checks)

    try:
        recomputed_graph = probes.parse_probe_bytes(
            manifest,
            members["evidence/probe-rust.json"],
            members["evidence/probe-aeneas.json"],
        )
    except probes.ProbeError:
        return _report(invocation, failures + ["probe_recompute_failed"], checks=checks)
    _append(
        failures,
        "graph_mismatch",
        state["graph"] != recomputed_graph
        or recomputed_graph["graph_sha256"] != invocation["graph_sha256"],
    )

    accepted_nodes = state.get("accepted_nodes")
    _append(
        failures,
        "accepted_nodes_mismatch",
        not isinstance(accepted_nodes, list)
        or accepted_nodes != sorted(set(accepted_nodes))
        or accepted_nodes != recomputed_graph["selected_nodes"],
    )

    contracts = state.get("frozen_contracts")
    contract_fingerprints: dict[str, str] = {}
    contract_invalid = not isinstance(contracts, dict)
    if isinstance(contracts, dict):
        for name, record in contracts.items():
            if (
                not isinstance(name, str)
                or not isinstance(record, dict)
                or record.get("status") != "frozen"
                or not isinstance(record.get("canon"), str)
                or not isinstance(record.get("model_fingerprint"), str)
                or len(record.get("model_fingerprint", "")) != 64
                or _sha256(record.get("canon", "").encode())
                != record.get("model_fingerprint")
                or (
                    "declaration" in record and record["declaration"] != name
                )
            ):
                contract_invalid = True
                continue
            contract_fingerprints[name] = record["model_fingerprint"]
            _append(
                failures,
                "native_decide_policy_mismatch",
                record.get("native_decide_policy_sha256")
                != invocation["native_decide_policy_sha256"],
            )
    _append(failures, "frozen_contract_invalid", contract_invalid)

    reference_specs = {
        item.get("spec")
        for item in reference.get("leaves", [])
        if isinstance(item, dict)
    }
    _append(
        failures,
        "reference_contract_mismatch",
        reference.get("schema") != "autofv-verifier-reference/v1"
        or reference.get("delivery") != "clean-verifier-only"
        or reference_specs != set(contract_fingerprints),
    )

    from . import experiment

    lock = contract_rules.load_toolchain_lock()
    _append(
        failures,
        "toolchain_lock_mismatch",
        _sha256(_canonical_bytes(lock)) != invocation["toolchain_lock_sha256"],
    )
    _append(
        failures,
        "image_mismatch",
        lock.get("image", {}).get("image_digest") != invocation["image_digest"],
    )
    _append(
        failures,
        "control_bundle_mismatch",
        worker.control_manifest(lock)[0]["bundle_sha256"]
        != invocation["control_bundle_sha256"],
    )
    _append(
        failures,
        "native_decide_policy_mismatch",
        lock.get("native_decide_policy_sha256")
        != invocation["native_decide_policy_sha256"],
    )
    try:
        contract_rules.evaluate_native_decide_policy(
            lock,
            native_decide_uses=state["native_decide_uses"],
            compiler_assumptions=state["compiler_assumptions"],
        )
    except contract_rules.ContractError:
        _append(failures, "native_decide_inventory_invalid", True)

    if failures:
        return _report(invocation, failures, checks=checks, state=state)
    try:
        observed = run_checks(members, state, reference_bytes)
    except VerifierInfrastructureError:
        raise
    except Exception as exc:
        return _report(
            invocation,
            ["clean_worker_failed"],
            checks=checks,
            state=state,
            meaning={"error_sha256": _sha256(str(exc).encode())},
        )
    if not isinstance(observed, dict) or set(observed) != OBSERVED_FIELDS:
        return _report(invocation, ["clean_worker_report_invalid"], checks=checks, state=state)

    _append(
        failures,
        "verifier_worker_mismatch",
        observed.get("verifier_worker_id") != invocation["verifier_worker_id"],
    )
    _append(
        failures,
        "runtime_identity_mismatch",
        observed.get("runtime_identity") is not True,
    )
    _append(
        failures,
        "snapshot_mismatch",
        observed.get("snapshot_sha256") != invocation["snapshot_sha256"],
    )
    _append(
        failures,
        "accepted_commit_mismatch",
        observed.get("accepted_commit") != invocation["accepted_commit"],
    )
    _append(
        failures,
        "accepted_tree_mismatch",
        observed.get("accepted_tree_sha256") != invocation["accepted_tree_sha256"],
    )
    _append(
        failures,
        "image_mismatch",
        observed.get("image_digest") != invocation["image_digest"],
    )
    _append(failures, "cache_not_fresh", observed.get("fresh_cache") is not True)
    _append(failures, "clean_build_failed", observed.get("clean_build") is not True)
    _append(
        failures,
        "accepted_nodes_mismatch",
        observed.get("accepted_nodes") != recomputed_graph["selected_nodes"],
    )
    statuses = observed.get("status_by_node")
    _append(
        failures,
        "accepted_status_mismatch",
        not isinstance(statuses, dict)
        or set(statuses) != set(recomputed_graph["selected_nodes"])
        or any(value != "accepted" for value in statuses.values()),
    )
    _append(
        failures,
        "statement_mismatch",
        observed.get("statement_fingerprints") != contract_fingerprints,
    )
    allowed_paths = {
        recomputed_graph["source_paths"][node]
        for node in recomputed_graph["selected_nodes"]
    }
    changed_paths = observed.get("changed_paths")
    _append(
        failures,
        "scope_mismatch",
        not isinstance(changed_paths, list)
        or changed_paths != sorted(set(changed_paths))
        or not set(changed_paths) <= allowed_paths,
    )
    _append(failures, "holes_present", observed.get("holes") != [])
    _append(
        failures,
        "sorry_count_mismatch",
        type(observed.get("sorry_count_before")) is not int
        or observed["sorry_count_before"] < 0
        or observed.get("sorry_count_after") != 0,
    )
    _append(failures, "trust_failed", observed.get("trust_passed") is not True)
    _append(
        failures,
        "native_decide_policy_mismatch",
        observed.get("native_decide_policy_sha256")
        != invocation["native_decide_policy_sha256"],
    )
    _append(
        failures,
        "compiler_assumptions_mismatch",
        observed.get("compiler_assumptions") != state["compiler_assumptions"],
    )
    expected_contract = axiom_audit.expected_inventory(state, reference)
    observed_inventory = observed.get("axiom_inventory")
    try:
        if (
            axiom_audit.inventory_scope_sha256(expected_contract)
            != invocation["axiom_scope_sha256"]
            or not isinstance(observed_inventory, list)
        ):
            raise contract_rules.ContractError("kernel inventory binding mismatch")
        observed_closures = {
            record["declaration"]: sorted(
                {record["declaration"], *record["dependencies"]}
            )
            for record in observed_inventory
            if isinstance(record, dict)
        }
        expected_axioms = axiom_audit.expected_inventory(
            state,
            reference,
            observed_closures=observed_closures,
        )
        accepted_uses, hidden_uses, all_uses = (
            axiom_audit.native_use_provenance(observed_inventory)
        )
        expected_hidden_uses = axiom_audit.native_use_provenance(
            expected_contract
        )[1]
        if (
            accepted_uses
            != axiom_audit.canonical_native_uses(state["native_decide_uses"])
            or hidden_uses != expected_hidden_uses
            or observed.get("accepted_native_decide_uses") != accepted_uses
            or observed.get("hidden_native_decide_uses") != hidden_uses
            or observed.get("native_decide_uses") != all_uses
        ):
            raise contract_rules.ContractError(
                "native_decide provenance mismatch"
            )
    except (KeyError, TypeError, contract_rules.ContractError):
        _append(failures, "axiom_inventory_invalid", True)
        _append(failures, "native_decide_inventory_mismatch", True)
    else:
        try:
            axiom_audit.validate_inventory(
                observed_inventory,
                expected_axioms,
                lock=lock,
                compiler_assumptions=state["compiler_assumptions"],
            )
        except (KeyError, TypeError, contract_rules.ContractError):
            _append(failures, "axiom_inventory_invalid", True)
    meaning = observed.get("meaning")
    _append(
        failures,
        "meaning_incomplete",
        not isinstance(meaning, dict)
        or set(meaning) != MEANING_FIELDS
        or any(value is not True for value in meaning.values()),
    )
    checks.update(
        {
            "runtime_identity": "runtime_identity_mismatch" not in failures,
            "exact_commit": "accepted_commit_mismatch" not in failures,
            "exact_tree": "accepted_tree_mismatch" not in failures,
            "fresh_cache": "cache_not_fresh" not in failures,
            "clean_build": "clean_build_failed" not in failures,
            "target_closure": not {
                "accepted_nodes_mismatch",
                "accepted_status_mismatch",
            }
            & set(failures),
            "statements": "statement_mismatch" not in failures,
            "scope": "scope_mismatch" not in failures,
            "holes": "holes_present" not in failures,
            "trust": "trust_failed" not in failures,
            "native_decide": not {
                "native_decide_policy_mismatch",
                "native_decide_inventory_mismatch",
                "compiler_assumptions_mismatch",
            }
            & set(failures),
            "kernel_axioms": "axiom_inventory_invalid" not in failures,
            "meaning": "meaning_incomplete" not in failures,
        }
    )
    return _report(
        invocation,
        failures,
        checks=checks,
        state=state,
        meaning=meaning if isinstance(meaning, dict) else {},
        axiom_inventory=(
            observed["axiom_inventory"]
            if isinstance(observed.get("axiom_inventory"), list)
            else []
        ),
        sorry_count_before=observed["sorry_count_before"],
        sorry_count_after=observed["sorry_count_after"],
    )
