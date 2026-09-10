"""L0 evidence indexing, level assessment, and bounded claims."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes
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
    "build": ("clean_verifier:PASS",),
    "replay": ("clean_verifier:PASS",),
    "verifier": ("clean_verifier:PASS",),
    "export": ("artifacts_exported",),
    "disposal": ("worker_disposed",),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _event(events: list[Any], names: tuple[str, ...]) -> str | None:
    for event in events:
        if isinstance(event, str) and any(
            event == name or event.startswith(name) for name in names
        ):
            return event
    return None


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

    return {
        "input": input_value,
        "image": image_value,
        "runtime": runtime_value,
        "tool": lock.get("tools"),
        "probe": probe_value,
        "mount": mount_value,
        "network": network_value,
        "model_receipt": receipts if isinstance(receipts, list) and receipts else None,
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
