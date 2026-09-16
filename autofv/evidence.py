"""L0 evidence indexing, level assessment, and bounded claims."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes
from . import provider_config, provider_receipts
from .worker_runtime import NETWORK_ENFORCER


REQUIRED_L0_ITEMS = (
    "input",
    "image",
    "runtime",
    "tool",
    "probe",
    "mount",
    "network",
    "model_receipt",
    "patch",
    "scan",
    "build",
    "replay",
    "verifier",
    "export",
    "disposal",
)
EXCLUSIONS = (
    "cryptographic_security",
    "constant_time_or_side_channel_security",
    "rust_memory_safety",
    "training_data_cleanliness",
)
ISOLATION_ASSUMPTIONS = (
    "the dedicated Linux worker was empty and disposable",
    "Docker used the pinned OCI image through gVisor runsc",
    "the worker received no host checkout, runtime socket, reusable credential, or cloud role",
    "the fixed model proxy was the only external network path",
    "the clean verifier ran on a distinct worker without agent caches",
)
SHA256 = re.compile(r"[0-9a-f]{64}")

_PROVIDER_POLICY_FIELDS = {
    "schema",
    "run_id",
    "proxy_id",
    "route_id",
    "method",
    "path",
    "auth_scope",
    "provider_authorization_location",
    "proxy_endpoint_sha256",
    "proxy_client_identity_sha256",
    "receipt_schema_sha256",
    "fixed_proxy_sha256",
    "image_digest",
    "control_bundle_sha256",
    "native_decide_policy_sha256",
    "worker_inventory_sha256",
    "provider_binding",
    "provider_endpoint_sha256",
    "provider_receipt_schema",
    "policy_sha256",
}
_SYNTHETIC_POLICY_FIELDS = _PROVIDER_POLICY_FIELDS - {
    "provider_binding",
    "provider_endpoint_sha256",
    "provider_receipt_schema",
}

FILE_LOCATIONS = {
    "input": "evidence/l0/input.json",
    "image": "evidence/l0/image.json",
    "runtime": "evidence/worker-inventory.json",
    "tool": "evidence/l0/tool.json",
    "probe": "evidence/l0/probe.json",
    "mount": "evidence/scored-container.json",
    "network": "evidence/egress.json",
    "model_receipt": "evidence/l0/model-receipts.json",
    "patch": "evidence/l0/patches.json",
    "scan": "export/artifact-scan.json",
    "build": "evidence/l0/build.json",
    "replay": "evidence/l0/replay.json",
    "verifier": "evidence/verifier.json",
    "export": "export/manifest.json",
    "disposal": "disposal.json",
}
PERSISTED_SOURCE_ITEMS = (
    "input",
    "image",
    "tool",
    "probe",
    "model_receipt",
    "patch",
    "build",
    "replay",
)

_RECEIPT_CONTRACTS = {
    "runtime": ("autofv-worker-inventory/v1", "inventory_sha256"),
    "mount": ("autofv-scored-container/v1", "inspection_sha256"),
    "network": ("autofv-egress-evidence/v1", "evidence_sha256"),
    "scan": ("autofv-retained-state-scan/v1", "scan_sha256"),
    "verifier": ("autofv-verifier-report/v1", "report_sha256"),
    "export": ("autofv-export/v1", "manifest_sha256"),
    "disposal": ("autofv-disposal/v1", "disposal_sha256"),
}

_EVENTS = {
    "input": ("target_copied",),
    "image": ("control_bundle_verified",),
    "runtime": ("runsc_started",),
    "tool": ("control_bundle_verified",),
    "probe": ("targets_frozen",),
    "mount": ("runsc_started", "scored_container_inspected"),
    "network": ("egress_matrix_passed",),
    "model_receipt": ("proxy:",),
    "patch": ("candidate_accepted:", "candidate_accepted_reverified:"),
    "scan": ("artifacts_exported",),
    "build": (
        "clean_verifier:PASS",
        "clean_verifier:INCOMPLETE",
        "clean_verifier:FALSE_SPEC",
    ),
    "replay": (
        "clean_verifier:PASS",
        "clean_verifier:INCOMPLETE",
        "clean_verifier:FALSE_SPEC",
    ),
    "verifier": (
        "clean_verifier:PASS",
        "clean_verifier:INCOMPLETE",
        "clean_verifier:FALSE_SPEC",
    ),
    "export": ("artifacts_exported",),
    "disposal": ("worker_disposed",),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_provider_artifact(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
                raise provider_config.ProviderConfigError(
                    f"{label} is missing or unsafe"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(2_000_001)
        finally:
            os.close(descriptor)
        value = json.loads(raw)
        if (
            len(raw) > 2_000_000
            or not isinstance(value, dict)
            or raw != canonical_json_bytes(value) + b"\n"
        ):
            raise provider_config.ProviderConfigError(f"{label} is not canonical")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise provider_config.ProviderConfigError(f"{label} is unreadable") from exc
    return value, raw


def validate_retained_provider_policy(
    run: dict[str, Any],
) -> tuple[dict[str, Any], bytes] | None:
    """Authenticate a retained fixed policy and classify provider-only content."""
    evidence_dir = Path(run.get("evidence_dir", ""))
    policy_path = evidence_dir / "fixed-proxy-policy.json"
    try:
        policy, policy_raw = _read_provider_artifact(
            policy_path, "fixed proxy policy"
        )
    except provider_config.ProviderConfigError:
        if not os.path.lexists(policy_path):
            return None
        raise
    provider_fields = {
        "provider_binding",
        "provider_endpoint_sha256",
        "provider_receipt_schema",
    }
    has_provider_content = bool(set(policy) & provider_fields)
    legacy_synthetic_fields = {"schema", "run_id", "route_id", "policy_sha256"}
    if not has_provider_content and set(policy) == legacy_synthetic_fields:
        body = {key: value for key, value in policy.items() if key != "policy_sha256"}
        if (
            policy.get("schema") != "autofv-fixed-proxy-policy/v1"
            or policy.get("run_id") != run.get("run_id")
            or not isinstance(policy.get("route_id"), str)
            or not policy["route_id"]
            or policy.get("policy_sha256")
            != provider_config.canonical_sha256(body)
            or policy.get("policy_sha256") != run.get("proxy_policy_sha256")
        ):
            raise provider_config.ProviderConfigError(
                "fixed proxy policy binding mismatch"
            )
        return None
    expected_fields = (
        _PROVIDER_POLICY_FIELDS if has_provider_content else _SYNTHETIC_POLICY_FIELDS
    )
    policy = provider_config.exact_dict(
        policy, expected_fields, "fixed proxy policy"
    )
    route = run.get("lock", {}).get("fixed_proxy")
    if not isinstance(route, dict):
        raise provider_config.ProviderConfigError("fixed route is missing")
    fixed_proxy_sha256 = provider_config.canonical_sha256(route)
    expected_route = {
        "proxy_id": route.get("proxy_id"),
        "route_id": route.get("route_id"),
        "method": route.get("method"),
        "path": route.get("path"),
        "provider_authorization_location": route.get(
            "provider_authorization_location"
        ),
    }
    policy_body = {
        key: value for key, value in policy.items() if key != "policy_sha256"
    }
    receipt_schema = (
        provider_receipts.PROVIDER_RECEIPT_SCHEMA
        if has_provider_content
        else route.get("receipt_schema")
    )
    if (
        policy.get("schema") != "autofv-fixed-proxy-policy/v1"
        or policy.get("run_id") != run.get("run_id")
        or any(policy.get(name) != value for name, value in expected_route.items())
        or policy.get("auth_scope") != "run-scoped-fixed-inference"
        or policy.get("policy_sha256")
        != provider_config.canonical_sha256(policy_body)
        or policy.get("policy_sha256") != run.get("proxy_policy_sha256")
        or policy.get("fixed_proxy_sha256") != fixed_proxy_sha256
        or run.get("fixed_proxy_sha256") != fixed_proxy_sha256
        or policy.get("receipt_schema_sha256")
        != provider_config.canonical_sha256(receipt_schema)
        or any(
            policy.get(name) != run.get(name)
            for name in (
                "image_digest",
                "control_bundle_sha256",
                "native_decide_policy_sha256",
                "worker_inventory_sha256",
            )
        )
        or not isinstance(policy.get("proxy_endpoint_sha256"), str)
        or SHA256.fullmatch(policy["proxy_endpoint_sha256"]) is None
        or not isinstance(policy.get("proxy_client_identity_sha256"), str)
        or SHA256.fullmatch(policy["proxy_client_identity_sha256"]) is None
    ):
        raise provider_config.ProviderConfigError("fixed proxy policy binding mismatch")
    if not has_provider_content:
        return None

    binding = provider_config.validate_public_binding(run.get("provider_binding"))
    binding_sha256 = run.get("provider_binding_sha256")
    if binding_sha256 != binding["binding_sha256"]:
        raise provider_config.ProviderConfigError("provider binding digest mismatch")
    if (
        binding.get("fixed_proxy_sha256") != fixed_proxy_sha256
        or binding.get("run_id") != run.get("run_id")
        or binding.get("proxy_id") != route.get("proxy_id")
        or binding.get("route_id") != route.get("route_id")
        or policy.get("provider_binding") != binding
        or policy.get("provider_endpoint_sha256") != binding.get("endpoint_sha256")
        or policy.get("proxy_client_identity_sha256")
        != binding.get("client_identity_sha256")
        or policy.get("provider_receipt_schema")
        != provider_receipts.PROVIDER_RECEIPT_SCHEMA
    ):
        raise provider_config.ProviderConfigError(
            "provider fixed proxy policy binding mismatch"
        )
    return policy, policy_raw


def authenticate_provider_evidence(
    run: dict[str, Any], *, allow_missing_preflight: bool = False
) -> dict[str, Any] | None:
    """Derive provider authentication only from retained public evidence."""
    evidence_dir = Path(run.get("evidence_dir", ""))
    policy_path = evidence_dir / "fixed-proxy-policy.json"
    preflight_path = evidence_dir / "provider-preflight.json"
    validated_policy = validate_retained_provider_policy(run)
    provider_marked = any(
        run.get(name) is not None
        for name in (
            "provider_binding",
            "provider_binding_sha256",
            "provider_preflight_sha256",
            "provider_journal",
        )
    ) or os.path.lexists(preflight_path)
    if validated_policy is None:
        if provider_marked:
            raise provider_config.ProviderConfigError(
                "provider fixed proxy policy is missing"
            )
        return None
    policy, policy_raw = validated_policy
    binding = provider_config.validate_public_binding(run.get("provider_binding"))
    binding_sha256 = run.get("provider_binding_sha256")

    expected_preflight_sha256 = run.get("provider_preflight_sha256")
    if allow_missing_preflight and expected_preflight_sha256 is None:
        if os.path.lexists(preflight_path):
            preflight = provider_receipts.validate_preflight(
                preflight_path, expected_binding=binding
            )
            preflight_sha256 = preflight.get("preflight_sha256")
            preflight_raw = canonical_json_bytes(preflight) + b"\n"
        else:
            preflight = None
            preflight_sha256 = None
            preflight_raw = None
    else:
        preflight = provider_receipts.validate_preflight(
            preflight_path, expected_binding=binding
        )
        preflight_sha256 = preflight.get("preflight_sha256")
        preflight_raw = canonical_json_bytes(preflight) + b"\n"
    if preflight_sha256 != expected_preflight_sha256:
        raise provider_config.ProviderConfigError("provider preflight digest mismatch")
    journal = run.get("provider_journal")
    if not isinstance(journal, dict) or not journal or any(
        not isinstance(request_id, str)
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        for request_id, digest in journal.items()
    ):
        raise provider_config.ProviderConfigError(
            "provider journal identity is invalid"
        )
    files = {
        "policy": {
            "path": "evidence/fixed-proxy-policy.json",
            "sha256": _sha(policy_raw),
            "size": len(policy_raw),
            "type": "application/json",
        },
    }
    if preflight_raw is not None:
        files["preflight"] = {
            "path": "evidence/provider-preflight.json",
            "sha256": _sha(preflight_raw),
            "size": len(preflight_raw),
            "type": "application/json",
        }
    return {
        "schema": "autofv-provider-evidence/v1",
        "provider_binding": json.loads(canonical_json_bytes(binding)),
        "provider_binding_sha256": binding_sha256,
        "provider_preflight_sha256": preflight_sha256,
        "provider_journal": json.loads(canonical_json_bytes(journal)),
        "provider_journal_sha256": provider_config.canonical_sha256(journal),
        "proxy_policy_sha256": policy["policy_sha256"],
        "route_id": binding["route_id"],
        "model_id": binding["model_id"],
        "files": files,
    }


def authenticate_provider_transport_evidence(
    run: dict[str, Any],
) -> dict[str, Any]:
    """Authenticate old provider route, egress, and firewall evidence for rotation."""
    validated_policy = validate_retained_provider_policy(run)
    if validated_policy is None:
        raise provider_config.ProviderConfigError(
            "provider transport policy is missing"
        )
    policy, policy_raw = validated_policy
    if run.get("proxy_policy_receipt") != policy:
        raise provider_config.ProviderConfigError(
            "provider transport policy memory mismatch"
        )
    evidence_dir = Path(run.get("evidence_dir", ""))
    egress, egress_raw = _read_provider_artifact(
        evidence_dir / "egress.json", "provider egress evidence"
    )
    egress_body = {
        key: value for key, value in egress.items() if key != "evidence_sha256"
    }
    egress_policy = egress.get("policy")
    egress_policy_body = (
        {
            key: value
            for key, value in egress_policy.items()
            if key != "policy_sha256"
        }
        if isinstance(egress_policy, dict)
        else None
    )
    upstream = egress.get("upstream_policy")
    upstream_body = (
        {key: value for key, value in upstream.items() if key != "policy_sha256"}
        if isinstance(upstream, dict)
        else None
    )
    firewall = (
        egress_policy.get("firewall")
        if isinstance(egress_policy, dict)
        else None
    )
    retained_firewall = run.get("proxy_firewall")
    firewall_fields = {
        "base",
        "network_id",
        "internal_address",
        "bridge_address",
        "upstream_address",
        "upstream_port",
    }
    if (
        egress != run.get("egress_receipt")
        or egress.get("schema") != "autofv-egress-evidence/v1"
        or egress.get("run_id") != run.get("run_id")
        or egress.get("evidence_sha256")
        != provider_config.canonical_sha256(egress_body)
        or not isinstance(egress_policy_body, dict)
        or egress_policy.get("schema") != "autofv-egress-policy/v1"
        or egress_policy.get("enforcer") != NETWORK_ENFORCER
        or egress_policy.get("policy_sha256")
        != provider_config.canonical_sha256(egress_policy_body)
        or egress_policy.get("policy_sha256") != run.get("egress_policy_sha256")
        or not isinstance(upstream_body, dict)
        or upstream.get("schema") != "autofv-upstream-egress-policy/v1"
        or upstream.get("run_id") != run.get("run_id")
        or upstream.get("policy_sha256")
        != provider_config.canonical_sha256(upstream_body)
        or upstream.get("policy_sha256") != run.get("upstream_policy_sha256")
        or egress_policy.get("upstream_policy_sha256")
        != upstream.get("policy_sha256")
        or egress.get("fixed_proxy_sha256") != run.get("fixed_proxy_sha256")
        or egress.get("proxy_policy_sha256") != policy.get("policy_sha256")
        or not isinstance(firewall, dict)
        or not isinstance(retained_firewall, dict)
        or any(
            firewall.get(name) != retained_firewall.get(name)
            for name in firewall_fields
        )
    ):
        raise provider_config.ProviderConfigError(
            "provider transport egress binding mismatch"
        )
    files = {
        "fixed-proxy-policy.json": policy_raw,
        "egress.json": egress_raw,
    }
    matrix_path = evidence_dir / "proxy-policy-matrix.json"
    if os.path.lexists(matrix_path):
        matrix, matrix_raw = _read_provider_artifact(
            matrix_path, "provider proxy policy matrix"
        )
        matrix_body = {
            key: value for key, value in matrix.items() if key != "matrix_sha256"
        }
        if (
            matrix.get("schema") != "autofv-proxy-policy-matrix/v1"
            or matrix.get("run_id") != run.get("run_id")
            or matrix.get("proxy_policy_sha256") != policy.get("policy_sha256")
            or matrix.get("matrix_sha256")
            != provider_config.canonical_sha256(matrix_body)
        ):
            raise provider_config.ProviderConfigError(
                "provider proxy policy matrix binding mismatch"
            )
        files["proxy-policy-matrix.json"] = matrix_raw
    return {
        "policy": policy,
        "egress": egress,
        "firewall": retained_firewall,
        "files": files,
    }


def _event(events: list[Any], names: tuple[str, ...]) -> str | None:
    for event in events:
        if isinstance(event, str) and any(
            event == name or event.startswith(name) for name in names
        ):
            return event
    return None


def _exchange_order(exchange: Any) -> tuple[int, str]:
    request = exchange.get("request") if isinstance(exchange, dict) else None
    request = request if isinstance(request, dict) else {}
    sequence = request.get("sequence")
    request_id = request.get("request_id")
    return (
        sequence if type(sequence) is int else 0,
        request_id if isinstance(request_id, str) else "",
    )


def source_values(run: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    graph = state.get("graph") if isinstance(state.get("graph"), dict) else {}
    report = (
        state.get("verifier_report")
        if isinstance(state.get("verifier_report"), dict)
        else None
    )
    lock = run.get("lock") if isinstance(run.get("lock"), dict) else {}
    accepted = state.get("accepted") or run.get("accepted")
    export = run.get("export_receipt")
    receipts = state.get("receipts")
    exchanges = state.get("model_exchanges")
    candidates = state.get("candidate_receipts")
    transitions = state.get("accepted_sequence")

    input_value = None
    if run.get("snapshot_sha256") and run.get("manifest_sha256"):
        input_value = {
            "snapshot_sha256": run["snapshot_sha256"],
            "manifest_sha256": run["manifest_sha256"],
            "targets": (run.get("manifest") or state.get("manifest") or {}).get(
                "targets", []
            ),
        }
    image_value = None
    if run.get("image_digest") and run.get("control_bundle_sha256"):
        image_value = {
            "image_digest": run["image_digest"],
            "control_bundle_sha256": run["control_bundle_sha256"],
            "native_decide_policy_sha256": run.get(
                "native_decide_policy_sha256"
            ),
        }
    probe_value = None
    if all(
        graph.get(name)
        for name in (
            "probe_rust_sha256",
            "probe_aeneas_sha256",
            "graph_sha256",
        )
    ):
        probe_value = {
            name: graph[name]
            for name in (
                "probe_rust_sha256",
                "probe_aeneas_sha256",
                "graph_sha256",
                "selected_nodes",
            )
        }
    runtime_value = run.get("worker_inventory")
    if not isinstance(runtime_value, dict) or runtime_value.get(
        "inventory_sha256"
    ) != run.get("worker_inventory_sha256"):
        runtime_value = None
    mount_value = run.get("scored_container_receipt")
    if not isinstance(mount_value, dict) or mount_value.get("volume") != run.get(
        "volume"
    ):
        mount_value = None
    network_value = run.get("egress_receipt")
    policy = network_value.get("policy") if isinstance(network_value, dict) else None
    upstream = (
        network_value.get("upstream_policy")
        if isinstance(network_value, dict)
        else None
    )
    upstream_body = (
        {key: value for key, value in upstream.items() if key != "policy_sha256"}
        if isinstance(upstream, dict)
        else None
    )
    if (
        not isinstance(policy, dict)
        or not isinstance(upstream_body, dict)
        or upstream.get("schema") != "autofv-upstream-egress-policy/v1"
        or upstream.get("run_id") != run.get("run_id")
        or upstream.get("enforcer") != "macos-seatbelt-network-outbound"
        or upstream.get("policy_sha256")
        != _sha(canonical_json_bytes(upstream_body))
        or policy.get("upstream_policy_sha256")
        != upstream.get("policy_sha256")
        or policy.get("enforcer") != NETWORK_ENFORCER
        or policy.get("policy_sha256") != run.get("egress_policy_sha256")
        or policy.get("upstream_policy_sha256")
        != run.get("upstream_policy_sha256")
        or network_value.get("fixed_proxy_sha256")
        != run.get("fixed_proxy_sha256")
        or network_value.get("proxy_policy_sha256")
        != run.get("proxy_policy_sha256")
    ):
        network_value = None
    patch_value = None
    if (
        isinstance(candidates, list)
        and candidates
        and isinstance(transitions, list)
        and transitions
    ):
        patch_value = {
            "candidate_receipts": candidates,
            "accepted_sequence": transitions,
        }
    scan_value = None
    if isinstance(export, dict) and export.get("scan_sha256"):
        scan_value = {"scan_sha256": export["scan_sha256"]}
    build_value = None
    if isinstance(accepted, dict) and isinstance(report, dict):
        build_value = {
            "accepted_checks": accepted.get("checks", []),
            "verifier_checks": report.get("checks", {}),
        }
    model_value = None
    if isinstance(exchanges, dict) and exchanges:
        model_value = sorted(
            exchanges.values(),
            key=_exchange_order,
        )
    elif isinstance(receipts, list) and receipts:
        model_value = receipts

    return {
        "input": input_value,
        "image": image_value,
        "runtime": runtime_value,
        "tool": lock.get("tools"),
        "probe": probe_value,
        "mount": mount_value,
        "network": network_value,
        "model_receipt": model_value,
        "patch": patch_value,
        "scan": run.get("artifact_scan_receipt") or scan_value,
        "build": build_value,
        "replay": report,
        "verifier": report,
        "export": export if isinstance(export, dict) else None,
        "disposal": (
            run.get("disposal_receipt")
            if isinstance(run.get("disposal_receipt"), dict)
            else None
        ),
    }


def _item(
    name: str,
    run: dict[str, Any],
    value: Any,
    location: str | None,
) -> dict[str, Any]:
    observed_event = _event(run.get("events", []), _EVENTS[name])
    raw = canonical_json_bytes(value) if value is not None else None
    if location is not None:
        path = Path(run["run_root"]) / location
        if path.is_file() and not path.is_symlink():
            file_raw = path.read_bytes()
            expected = (
                canonical_json_bytes(value) + b"\n" if value is not None else None
            )
            raw = file_raw if file_raw == expected else None
        else:
            raw = None
    contract = _RECEIPT_CONTRACTS.get(name)
    if raw is not None and contract is not None:
        schema, digest_field = contract
        body = (
            {key: item for key, item in value.items() if key != digest_field}
            if isinstance(value, dict)
            else None
        )
        if (
            body is None
            or value.get("schema") != schema
            or value.get("run_id") != run["run_id"]
            or value.get(digest_field) != _sha(canonical_json_bytes(body))
        ):
            raw = None
    return {
        "name": name,
        "run_id": run["run_id"],
        "event": observed_event,
        "status": "present" if raw is not None and observed_event else "missing",
        "sha256": _sha(raw) if raw is not None else None,
        "size": len(raw) if raw is not None else None,
        "type": "application/json" if raw is not None else None,
        "location": location,
    }


def render_l0(run: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    values = source_values(run, state)
    items = [
        _item(name, run, values[name], FILE_LOCATIONS[name])
        for name in REQUIRED_L0_ITEMS
    ]
    missing = [item["name"] for item in items if item["status"] != "present"]
    body = {
        "schema": "autofv-evidence-l0/v1",
        "attempt_id": run["attempt_id"],
        "run_id": run["run_id"],
        "items": items,
        "complete": not missing,
        "missing": missing,
    }
    return {**body, "receipt_sha256": _sha(canonical_json_bytes(body))}


def assess_evidence(receipt: Any, verifier_report: Any) -> dict[str, Any]:
    records: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    if isinstance(receipt, dict) and isinstance(receipt.get("items"), list):
        for item in receipt["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            name = item["name"]
            if name in records:
                if records[name] != item:
                    duplicates.add(name)
                continue
            records[name] = item
    missing = []
    receipt_run_id = receipt.get("run_id") if isinstance(receipt, dict) else None
    for name in REQUIRED_L0_ITEMS:
        item = records.get(name)
        valid = bool(
            isinstance(item, dict)
            and name not in duplicates
            and item.get("status") == "present"
            and item.get("run_id") == receipt_run_id
            and isinstance(item.get("event"), str)
            and isinstance(item.get("sha256"), str)
            and SHA256.fullmatch(item["sha256"])
            and type(item.get("size")) is int
            and item["size"] >= 0
            and item.get("type") == "application/json"
            and item.get("location") == FILE_LOCATIONS[name]
        )
        if not valid:
            missing.append(name)
    if isinstance(receipt, dict):
        body = {
            key: value
            for key, value in receipt.items()
            if key != "receipt_sha256"
        }
        if receipt.get("receipt_sha256") != _sha(canonical_json_bytes(body)):
            missing.append("receipt_integrity")
    report = verifier_report if isinstance(verifier_report, dict) else None
    verifier_item = records.get("verifier")
    if report is None:
        missing.append("verifier_report")
    else:
        report_body = {
            key: value for key, value in report.items() if key != "report_sha256"
        }
        report_raw = canonical_json_bytes(report) + b"\n"
        if (
            report.get("run_id") != receipt_run_id
            or report.get("report_sha256") != _sha(canonical_json_bytes(report_body))
            or not isinstance(verifier_item, dict)
            or verifier_item.get("sha256") != _sha(report_raw)
            or verifier_item.get("size") != len(report_raw)
        ):
            missing.append("verifier_binding")
    if missing:
        return {"level": None, "scored": False, "missing": missing}

    level = "L0"
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    if report.get("verdict") == "PASS" and checks.get("clean_build") is True:
        level = "L1"
        if checks.get("target_closure") is True and checks.get("holes") is True:
            level = "L2"
            l3 = (
                "bundle",
                "reference_integrity",
                "exact_commit",
                "exact_tree",
                "fresh_cache",
                "statements",
                "scope",
                "trust",
                "native_decide",
            )
            if all(checks.get(name) is True for name in l3):
                level = "L3"
                meaning = report.get("meaning")
                if (
                    report.get("evidence_level") == "L4"
                    and checks.get("meaning") is True
                    and isinstance(meaning, dict)
                    and meaning
                    and all(value is True for value in meaning.values())
                ):
                    level = "L4"
    return {"level": level, "scored": True, "missing": []}


def render_claim(
    assessment: dict[str, Any],
    run: dict[str, Any],
    state: dict[str, Any],
    *,
    outcome: str,
) -> dict[str, Any]:
    supported = (
        outcome == "success"
        and assessment.get("scored") is True
        and assessment.get("level") == "L4"
    )
    frozen = state.get("contracts", {}).get("frozen", {})
    recovered = sorted(frozen) if supported and isinstance(frozen, dict) else []
    policy = run.get("lock", {}).get("native_decide_policy", {})
    return {
        "kind": "recovered_specification",
        "status": "supported" if supported else "withheld",
        "statement": (
            "The listed specifications have scoped Lean functional-correctness evidence."
            if supported
            else None
        ),
        "required_evidence_level": "L4",
        "achieved_evidence_level": assessment.get("level"),
        "recovered_specifications": recovered,
        "native_decide_effect": policy.get("claim_consequence"),
        "assumptions": list(ISOLATION_ASSUMPTIONS),
        "exclusions": list(EXCLUSIONS),
    }
