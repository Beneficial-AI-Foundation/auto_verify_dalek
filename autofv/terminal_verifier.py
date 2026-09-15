"""Phase-2 terminal bindings around the existing clean-verifier authority."""

from __future__ import annotations

import copy
import secrets
from typing import Any, Callable

from . import axiom_audit, contracts, counterexample, verifier_bundle
from .contracts import canonical_json_bytes


TERMINAL_REPORT_FIELDS = frozenset(
    {
        "core_report",
        "counterexample_certificate_sha256",
        "preparation_manifest_sha256",
        "preparation_tree_sha256",
        "target_states",
        "target_states_sha256",
        "terminal_status",
    }
)
TARGET_STATUSES = frozenset(
    {
        "accepted",
        "blocked",
        "failed",
        "false_spec",
        "pending",
        "unknown",
        "unverified",
    }
)
_INCOMPLETE_ACCEPTED_FIELD = "_counterexample_incomplete_accepted"
PREPARATION_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "source",
        "probes",
        "target_report_sha256",
        "probe_identities_sha256",
        "roots",
        "closures",
        "retained_declarations",
        "files",
        "tree_sha256",
        "gates",
        "manifest_sha256",
    }
)
PREPARATION_GATES = frozenset(
    {
        "build",
        "provenance",
        "reproducibility",
        "secret_scan",
        "spoiler_scan",
        "symlink_scan",
    }
)


def _sha(value: Any) -> str:
    return verifier_bundle._sha256(canonical_json_bytes(value))


def _preparation_identity(
    manifest: Any,
    graph: dict[str, Any],
    snapshot_sha256: str,
) -> dict[str, str]:
    if (
        not isinstance(manifest, dict)
        or set(manifest) != PREPARATION_FIELDS
        or manifest.get("schema") != "preparation-manifest/v1"
        or manifest.get("mode") not in {"full", "small"}
    ):
        raise verifier_bundle.VerifierError("preparation_manifest_invalid")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest_sha256 = manifest.get("manifest_sha256")
    if manifest_sha256 != _sha(body):
        raise verifier_bundle.VerifierError("preparation_manifest_hash_mismatch")
    roots = manifest.get("roots")
    closures = manifest.get("closures")
    selected = graph.get("selected_nodes")
    frozen = graph.get("frozen_targets")
    gates = manifest.get("gates")
    source = manifest.get("source")
    probes = manifest.get("probes")
    files = manifest.get("files")
    retained = manifest.get("retained_declarations")
    source_fields = {"repository", "revision", "tree_sha256"}
    probe_fields = source_fields | {"version"}
    valid_source = (
        isinstance(source, dict)
        and set(source) == source_fields
        and isinstance(source.get("repository"), str)
        and bool(source["repository"])
        and _is_sha256(source.get("tree_sha256"))
        and isinstance(source.get("revision"), str)
        and len(source["revision"]) in {40, 64}
        and all(character in "0123456789abcdef" for character in source["revision"])
    )
    valid_probes = (
        isinstance(probes, dict)
        and set(probes) == {"probe-aeneas", "probe-rust", "probe-lean"}
        and all(
            isinstance(identity, dict)
            and set(identity) == probe_fields
            and isinstance(identity.get("repository"), str)
            and bool(identity["repository"])
            and isinstance(identity.get("version"), str)
            and bool(identity["version"])
            and _is_sha256(identity.get("tree_sha256"))
            and isinstance(identity.get("revision"), str)
            and len(identity["revision"]) in {40, 64}
            and all(
                character in "0123456789abcdef"
                for character in identity["revision"]
            )
            for identity in probes.values()
        )
    )
    valid_files = (
        isinstance(files, list)
        and all(
            isinstance(entry, dict)
            and set(entry) == {"path", "sha256", "size"}
            and isinstance(entry.get("path"), str)
            and bool(entry["path"])
            and _is_sha256(entry.get("sha256"))
            and isinstance(entry.get("size"), int)
            and not isinstance(entry.get("size"), bool)
            and entry["size"] >= 0
            for entry in files
        )
        and [entry["path"] for entry in files]
        == sorted({entry["path"] for entry in files})
        and manifest.get("tree_sha256") == _sha(files)
    )
    if (
        manifest.get("tree_sha256") != snapshot_sha256
        or not _is_sha256(manifest.get("target_report_sha256"))
        or not _is_sha256(manifest.get("probe_identities_sha256"))
        or not valid_source
        or not valid_probes
        or not valid_files
        or not isinstance(roots, list)
        or not roots
        or roots != sorted(set(roots))
        or roots != frozen
        or not isinstance(closures, dict)
        or set(closures) != set(roots)
        or not isinstance(selected, list)
        or any(
            not isinstance(closures[root], list)
            or closures[root] != sorted(set(closures[root]))
            or not set(closures[root]) <= set(selected)
            for root in roots
        )
        or set().union(*(set(closures[root]) for root in roots)) != set(selected)
        or not isinstance(retained, list)
        or retained != sorted(set(retained))
        or retained != selected
        or not isinstance(gates, dict)
        or set(gates) != PREPARATION_GATES
        or any(value != "passed" for value in gates.values())
    ):
        raise verifier_bundle.VerifierError("preparation_manifest_identity_mismatch")
    return {
        "preparation_manifest_sha256": manifest_sha256,
        "preparation_tree_sha256": snapshot_sha256,
    }


def _target_states(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    value = state.get("target_states")
    graph = state.get("graph")
    selected = graph.get("selected_nodes") if isinstance(graph, dict) else None
    if (
        not isinstance(value, dict)
        or not isinstance(selected, list)
        or set(value) != set(selected)
        or any(
            not isinstance(node, str)
            or not isinstance(record, dict)
            or record.get("status") not in TARGET_STATUSES
            for node, record in value.items()
        )
    ):
        raise verifier_bundle.VerifierError("target_states_invalid")
    return copy.deepcopy(value)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _report_accepted_declaration_for_target(
    inventory: Any, target: str
) -> str:
    candidates = [
        record["declaration"]
        for record in inventory
        if isinstance(record, dict)
        and record.get("origin") == "accepted_spec"
        and isinstance(record.get("declaration"), str)
        and target
        in {
            f"probe:{record['declaration']}",
            f"probe:{record['declaration'].removesuffix('_spec')}",
        }
    ] if isinstance(inventory, list) else []
    if len(candidates) != 1:
        raise verifier_bundle.VerifierError(
            "counterexample_verifier_audit_failed"
        )
    return candidates[0]


def validate_counterexample_certificate(
    certificate: Any,
    *,
    target_states: dict[str, dict[str, Any]],
    accepted_commit: str,
    toolchain_lock_sha256: str,
    confirmed_sha256: str | None,
) -> dict[str, Any]:
    """Compatibility facade for the strict certificate validator."""
    return counterexample.validate_certificate(
        certificate,
        target_states=target_states,
        accepted_commit=accepted_commit,
        toolchain_lock_sha256=toolchain_lock_sha256,
        confirmed_sha256=confirmed_sha256,
    )


def confirm_counterexample_certificate(
    run: dict[str, Any],
    invocation: dict[str, Any],
    certificate: dict[str, Any],
    obligation: dict[str, Any],
    members: dict[str, bytes],
    state: dict[str, Any],
    *,
    docker: Callable[..., Any],
    runtime_argv: Callable[..., tuple[str, ...]],
    seed_file: Callable[..., None],
) -> str:
    """Reproduce one witness on a fresh offline volume of the clean worker."""
    if not isinstance(certificate, dict):
        raise verifier_bundle.VerifierError("counterexample certificate is missing")
    image = invocation["image_digest"]
    runtime = run["lock"]["tools"]["runsc"]["runtime_name"]
    nonce = secrets.token_hex(8)
    volume = f"autofv-counterexample-witness-{nonce}"
    audit_volume = f"autofv-counterexample-audit-{nonce}"
    created = []
    try:
        for isolated_volume in (audit_volume, volume):
            docker("volume", "create", isolated_volume)
            created.append(isolated_volume)
            axiom_audit.checkout_volume(
                image=image,
                volume=isolated_volume,
                repository_bundle=members["accepted/repository.bundle"],
                commit=state["base_commit"],
                runtime=runtime,
                docker=docker,
                runtime_argv=runtime_argv,
                seed_file=seed_file,
            )
        return counterexample.confirm(
            certificate,
            obligation,
            image=image,
            volume=volume,
            audit_volume=audit_volume,
            runtime=runtime,
            runtime_argv=runtime_argv,
            docker=docker,
            seed_file=seed_file,
            native_decide_policy_sha256=invocation[
                "native_decide_policy_sha256"
            ],
        )
    finally:
        for isolated_volume in reversed(created):
            try:
                docker("volume", "rm", isolated_volume)
            except verifier_bundle.VerifierError:
                pass


def terminal_expectations(
    run: dict[str, Any], state: dict[str, Any]
) -> dict[str, str]:
    """Return identities the controller must compare on report intake."""
    targets = _target_states(state)
    preparation = _preparation_identity(
        run.get("preparation_manifest"),
        state["graph"],
        run["snapshot_sha256"],
    )
    return {**preparation, "target_states_sha256": _sha(targets)}


def verify_terminal_bundle(
    bundle: bytes,
    invocation: dict[str, Any],
    *,
    preparation_manifest: dict[str, Any],
    reference_bytes: bytes,
    run_checks: Callable[[dict[str, bytes], dict[str, Any], bytes], dict[str, Any]],
    confirm_counterexample: Callable[
        [dict[str, Any], dict[str, bytes], dict[str, Any], dict[str, Any]], str
    ]
    | None = None,
) -> dict[str, Any]:
    """Bind prepared terminal state, then delegate the actual clean verification."""
    members = verifier_bundle._read_bundle(bundle, invocation["bundle_sha256"])
    state = verifier_bundle._strict_json(
        members["state/verification.json"], "verifier_state"
    )
    allowed_state_fields = verifier_bundle.STATE_FIELDS | {"target_states"}
    if frozenset(state) not in {
        frozenset(allowed_state_fields),
        frozenset(allowed_state_fields | {"counterexample_certificate"}),
    }:
        raise verifier_bundle.VerifierError("verifier_terminal_state_mismatch")
    targets = _target_states(state)
    preparation = _preparation_identity(
        preparation_manifest, state["graph"], invocation["snapshot_sha256"]
    )

    core_state = copy.deepcopy(state)
    core_state.pop("target_states")
    certificate = core_state.pop("counterexample_certificate", None)
    complete = all(record["status"] == "accepted" for record in targets.values())
    false_targets = [
        node for node, record in targets.items() if record["status"] == "false_spec"
    ]
    exact_counterexample_state = len(false_targets) == 1 and all(
        record["status"] == "accepted" or node == false_targets[0]
        for node, record in targets.items()
    )
    obligation = None
    permitted_incomplete_accepted: list[str] = []
    if (
        exact_counterexample_state
        and isinstance(certificate, dict)
        and confirm_counterexample is not None
    ):
        obligation = counterexample.resolve_obligation(
            reference_bytes, certificate, targets
        )
        if obligation is not None:
            reference = verifier_bundle._strict_json(
                reference_bytes, "verifier_reference"
            )
            try:
                declaration = axiom_audit.accepted_declaration_for_target(
                    core_state, reference, false_targets[0]
                )
            except contracts.ContractError as exc:
                raise verifier_bundle.VerifierError(
                    "counterexample_verifier_audit_failed"
                ) from exc
            if declaration is not None:
                permitted_incomplete_accepted = [declaration]
    # The legacy intake's all-or-nothing accepted-node field is not the Phase-2
    # completion claim. It is widened solely so the clean worker still rebuilds
    # and audits the entire frozen closure when controller progress is partial.
    core_state["accepted_nodes"] = core_state["graph"]["selected_nodes"]
    core_members = dict(members)
    core_members["state/verification.json"] = verifier_bundle._canonical_bytes(
        core_state
    )
    core_bundle = verifier_bundle.build_bundle(core_members)
    core_invocation = {
        **invocation,
        "bundle_sha256": verifier_bundle._sha256(core_bundle),
    }
    checked_run_checks = run_checks
    if permitted_incomplete_accepted:
        def checked_run_checks(
            checked_members: dict[str, bytes],
            checked_state: dict[str, Any],
            checked_reference: bytes,
        ) -> dict[str, Any]:
            audit_state = copy.deepcopy(checked_state)
            audit_state[_INCOMPLETE_ACCEPTED_FIELD] = (
                permitted_incomplete_accepted
            )
            return run_checks(checked_members, audit_state, checked_reference)

    core = verifier_bundle.verify_bundle(
        core_bundle,
        core_invocation,
        reference_bytes=reference_bytes,
        run_checks=checked_run_checks,
    )

    confirmed_certificate_sha256 = None
    if false_targets:
        if len(false_targets) != 1:
            raise verifier_bundle.VerifierError(
                "counterexample_certificate_confirmation_missing"
            )
        if (
            exact_counterexample_state
            and obligation is not None
            and confirm_counterexample is not None
        ):
            allowed_failures = {
                "accepted_status_mismatch",
                "axiom_inventory_invalid",
                "holes_present",
                "sorry_count_mismatch",
            }
            try:
                inventory = core.get("axiom_inventory")
                if (
                    axiom_audit.inventory_scope_sha256(inventory)
                    != invocation["axiom_scope_sha256"]
                ):
                    raise contracts.ContractError(
                        "kernel inventory binding mismatch"
                    )
                axiom_audit.validate_report_inventory(
                    inventory,
                    lock=contracts.load_toolchain_lock(),
                    compiler_assumptions=core.get("compiler_assumptions"),
                    require_complete=True,
                    expected_scope_sha256=invocation[
                        "axiom_scope_sha256"
                    ],
                    expected_identity_sha256=core[
                        "axiom_inventory_sha256"
                    ],
                    accepted_native_decide_uses=core.get(
                        "accepted_native_decide_uses"
                    ),
                    hidden_native_decide_uses=core.get(
                        "hidden_native_decide_uses"
                    ),
                    required_native_uses=core.get("native_decide_uses"),
                    allow_untrusted_axioms=True,
                    permitted_untrusted_declarations=frozenset(
                        permitted_incomplete_accepted
                    ),
                )
            except (KeyError, TypeError, contracts.ContractError, OSError) as exc:
                raise verifier_bundle.VerifierError(
                    "counterexample_verifier_audit_failed"
                ) from exc
            if core.get("verdict") != "PASS" and not set(
                core.get("failures", [])
            ) <= allowed_failures:
                raise verifier_bundle.VerifierError(
                    "counterexample_verifier_audit_failed"
                )
            validate_counterexample_certificate(
                certificate,
                target_states=targets,
                accepted_commit=invocation["accepted_commit"],
                toolchain_lock_sha256=invocation["toolchain_lock_sha256"],
                confirmed_sha256=certificate["certificate_sha256"],
            )
            confirmed_certificate_sha256 = confirm_counterexample(
                certificate, members, state, obligation
            )
            validate_counterexample_certificate(
                certificate,
                target_states=targets,
                accepted_commit=invocation["accepted_commit"],
                toolchain_lock_sha256=invocation["toolchain_lock_sha256"],
                confirmed_sha256=confirmed_certificate_sha256,
            )
    elif certificate is not None:
        raise verifier_bundle.VerifierError("counterexample_certificate_unexpected")
    verified = complete and core.get("verdict") == "PASS"
    failures = list(core.get("failures", []))
    checks = copy.deepcopy(core.get("checks", {}))
    if not complete and "target_state_incomplete" not in failures:
        failures.append("target_state_incomplete")
        checks["target_closure"] = False
    terminal_status = (
        "verified"
        if verified
        else "false_spec"
        if confirmed_certificate_sha256 is not None
        else "unverified"
    )
    body = {
        **{key: value for key, value in core.items() if key != "report_sha256"},
        "bundle_sha256": invocation["bundle_sha256"],
        "checks": checks,
        "failures": failures,
        "evidence_level": "L4" if verified else "L0",
        "verdict": "PASS" if verified else "FAIL",
        "core_report": copy.deepcopy(core),
        "counterexample_certificate_sha256": confirmed_certificate_sha256,
        **preparation,
        "target_states": targets,
        "target_states_sha256": _sha(targets),
        "terminal_status": terminal_status,
    }
    return {**body, "report_sha256": _sha(body)}


def validate_terminal_report(
    report: Any,
    run: dict[str, Any],
    expected: dict[str, Any],
    *,
    validate_core: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Validate the enriched report and its unchanged Phase-1 core report."""
    core_fields = (verifier_bundle.INVOCATION_FIELDS - {"schema"}) | {
        "schema",
        "checks",
        "failures",
        "native_decide_uses",
        "accepted_native_decide_uses",
        "hidden_native_decide_uses",
        "compiler_assumptions",
        "axiom_inventory",
        "axiom_inventory_sha256",
        "meaning",
        "sorry_count_before",
        "sorry_count_after",
        "evidence_level",
        "verdict",
        "report_sha256",
    }
    if not isinstance(report, dict) or set(report) != core_fields | TERMINAL_REPORT_FIELDS:
        raise verifier_bundle.VerifierError("clean verifier report fields mismatch")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != _sha(body):
        raise verifier_bundle.VerifierError("clean verifier report hash mismatch")
    if "reference_sha256" not in expected:
        raise verifier_bundle.VerifierError(
            "clean verifier reference_sha256 mismatch"
        )
    for field, value in expected.items():
        if field != "schema" and report.get(field) != value:
            raise verifier_bundle.VerifierError(f"clean verifier {field} mismatch")
    manifest = run.get("preparation_manifest")
    if isinstance(manifest, dict):
        actual = terminal_expectations(
            run,
            {
                "graph": {
                    "frozen_targets": manifest.get("roots"),
                    "selected_nodes": sorted(report["target_states"]),
                },
                "target_states": report["target_states"],
            },
        )
    else:
        # Offline validation has the hash-bound preparation identities in its
        # expected result record, but deliberately does not retain the full
        # preparation manifest.
        actual = {"target_states_sha256": _sha(report["target_states"])}
    for field, value in actual.items():
        if report.get(field) != value:
            raise verifier_bundle.VerifierError(f"clean verifier {field} mismatch")

    core = report.get("core_report")
    if not isinstance(core, dict) or set(core) != core_fields:
        raise verifier_bundle.VerifierError("clean verifier core report mismatch")
    for field in verifier_bundle.INVOCATION_FIELDS - {"schema", "bundle_sha256"}:
        if core.get(field) != report.get(field):
            raise verifier_bundle.VerifierError(
                f"clean verifier core {field} mismatch"
            )
    for field in {
        "schema",
        "native_decide_uses",
        "accepted_native_decide_uses",
        "hidden_native_decide_uses",
        "compiler_assumptions",
        "axiom_inventory",
        "axiom_inventory_sha256",
        "meaning",
        "sorry_count_before",
        "sorry_count_after",
    }:
        if core.get(field) != report.get(field):
            raise verifier_bundle.VerifierError(
                f"clean verifier core {field} mismatch"
            )
    complete = all(
        isinstance(record, dict) and record.get("status") == "accepted"
        for record in report["target_states"].values()
    )
    certificate_sha256 = report.get("counterexample_certificate_sha256")
    false_targets = [
        node
        for node, record in report["target_states"].items()
        if isinstance(record, dict) and record.get("status") == "false_spec"
    ]
    exact_counterexample_state = len(false_targets) == 1 and all(
        isinstance(record, dict)
        and (record.get("status") == "accepted" or node == false_targets[0])
        for node, record in report["target_states"].items()
    )
    allow_untrusted_axioms = exact_counterexample_state and _is_sha256(
        certificate_sha256
    )
    permitted_untrusted_declarations = frozenset()
    if allow_untrusted_axioms:
        inventory = core.get("axiom_inventory")
        untrusted = {
            record.get("declaration")
            for record in inventory
            if isinstance(record, dict)
            and set(record.get("axioms", [])) - axiom_audit.COMPILER_AXIOMS
        } if isinstance(inventory, list) else set()
        if untrusted:
            permitted_untrusted_declarations = frozenset(
                {
                    _report_accepted_declaration_for_target(
                        inventory, false_targets[0]
                    )
                }
            )
            if untrusted != set(permitted_untrusted_declarations):
                raise verifier_bundle.VerifierError(
                    "counterexample_verifier_audit_failed"
                )
    validate_core(
        core,
        run,
        {
            key: value
            for key, value in expected.items()
            if key in verifier_bundle.INVOCATION_FIELDS and key != "bundle_sha256"
        },
        require_pass=False,
        require_axiom_inventory=True,
        allow_untrusted_axioms=allow_untrusted_axioms,
        permitted_untrusted_declarations=permitted_untrusted_declarations,
    )
    expected_checks = copy.deepcopy(core["checks"])
    expected_failures = list(core["failures"])
    if not complete:
        expected_checks["target_closure"] = False
        if "target_state_incomplete" not in expected_failures:
            expected_failures.append("target_state_incomplete")
    if certificate_sha256 is not None and (
        not exact_counterexample_state or not _is_sha256(certificate_sha256)
    ):
        raise verifier_bundle.VerifierError("clean verifier terminal status mismatch")
    verified = complete and core["verdict"] == "PASS"
    expected_terminal = (
        "verified"
        if verified
        else "false_spec"
        if certificate_sha256 is not None
        else "unverified"
    )
    if (
        report.get("checks") != expected_checks
        or report.get("failures") != expected_failures
        or report.get("evidence_level") != ("L4" if verified else "L0")
        or report.get("verdict") != ("PASS" if verified else "FAIL")
        or report.get("terminal_status") != expected_terminal
    ):
        raise verifier_bundle.VerifierError("clean verifier terminal reduction mismatch")
    return report
