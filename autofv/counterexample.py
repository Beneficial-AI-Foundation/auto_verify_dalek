"""Trusted counterexample obligations and clean-worker witness confirmation."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Callable

from . import axiom_audit, contracts, verifier_bundle
from .contracts import canonical_json_bytes


CERTIFICATE_FIELDS = frozenset(
    {
        "schema",
        "target",
        "statement_sha256",
        "accepted_commit",
        "toolchain_lock_sha256",
        "concrete_inputs",
        "lean_witness",
        "diagnostics_sha256",
        "artifact_sha256",
        "verification_command",
        "native_decide_uses",
        "compiler_assumptions",
        "axiom_inventory",
        "axiom_audit_sha256",
        "certificate_sha256",
    }
)
THEOREM_NAME = "AutoFV.counterexample"
SOURCE_PATH = "AutoFVCounterexample.lean"
OLEAN_PATH = ".lake/build/lib/lean/AutoFVCounterexample.olean"
AUDIT_PATH = "AutoFVCounterexampleAudit.lean"
VERIFICATION_COMMAND = ["lake", "env", "lean", "-o", OLEAN_PATH, SOURCE_PATH]
OBLIGATION_FIELDS = frozenset(
    {
        "target",
        "statement_sha256",
        "concrete_inputs",
        "lean_prefix",
        "lean_suffix",
    }
)
_FORBIDDEN_WITNESS = re.compile(
    r"\b(?:sorry|sorryAx|admit|axiom|import|example|theorem|opaque|def|namespace|end|unsafe)\b"
    r"|@\[(?:extern|implemented_by)\b|#(?:eval|check|print)|set_option"
)


def _read_regular_file(path: str | Path) -> tuple[Path, bytes]:
    requested = Path(path)
    try:
        resolved = requested.resolve(strict=True)
        metadata = requested.lstat()
    except OSError as exc:
        raise verifier_bundle.VerifierError(
            "clean verifier reference path mismatch"
        ) from exc
    if (
        not requested.is_absolute()
        or requested != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise verifier_bundle.VerifierError("clean verifier reference path mismatch")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        try:
            before = os.fstat(descriptor)
            chunks = []
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 8 * 1024 * 1024:
                    raise verifier_bundle.VerifierError(
                        "clean verifier reference is too large"
                    )
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise verifier_bundle.VerifierError(
            "clean verifier reference read failed"
        ) from exc
    raw = b"".join(chunks)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or before.st_size != len(raw)
    ):
        raise verifier_bundle.VerifierError("clean verifier reference changed")
    return resolved, raw


def external_reference_identity(path: str | Path) -> dict[str, str]:
    """Return a canonical path/hash pair without retaining reference bytes."""
    resolved, raw = _read_regular_file(path)
    return {
        "reference_path": str(resolved),
        "reference_sha256": verifier_bundle._sha256(raw),
    }


def bind_reference(run: dict[str, Any], path: str | Path) -> dict[str, str]:
    """Bind an external hidden reference to one preparation manifest."""
    preparation = run.get("preparation_manifest")
    if not isinstance(preparation, dict):
        raise verifier_bundle.VerifierError("preparation manifest is missing")
    identity = external_reference_identity(path)
    binding = {
        "schema": "autofv-verifier-reference-binding/v1",
        **identity,
        "preparation_manifest_sha256": preparation.get("manifest_sha256"),
    }
    candidate = {**run, "verifier_reference": binding}
    trusted_reference(candidate, legacy_path=None)
    return binding


def trusted_reference(
    run: dict[str, Any], *, legacy_path: str | Path | None
) -> bytes:
    """Read only the exact external reference bound to this preparation."""
    preparation = run.get("preparation_manifest")
    if not isinstance(preparation, dict):
        if legacy_path is None:
            raise verifier_bundle.VerifierError("clean verifier reference is missing")
        return _read_regular_file(Path(legacy_path).resolve(strict=True))[1]
    binding = run.get("verifier_reference")
    required = {
        "schema",
        "reference_path",
        "preparation_manifest_sha256",
        "reference_sha256",
    }
    if (
        not isinstance(binding, dict)
        or set(binding) != required
        or binding.get("schema") != "autofv-verifier-reference-binding/v1"
        or binding.get("preparation_manifest_sha256")
        != preparation.get("manifest_sha256")
        or not isinstance(binding.get("reference_path"), str)
    ):
        raise verifier_bundle.VerifierError("clean verifier reference binding mismatch")
    path, raw = _read_regular_file(binding["reference_path"])
    for name in ("input_root", "run_root"):
        root = run.get(name)
        if isinstance(root, str):
            try:
                if path.is_relative_to(Path(root).resolve(strict=True)):
                    raise verifier_bundle.VerifierError(
                        "clean verifier reference path is not external"
                    )
            except OSError as exc:
                raise verifier_bundle.VerifierError(
                    "clean verifier reference boundary mismatch"
                ) from exc
    if verifier_bundle._sha256(raw) != binding.get("reference_sha256"):
        raise verifier_bundle.VerifierError("clean verifier reference hash mismatch")
    return raw


def _sha(value: Any) -> str:
    return verifier_bundle._sha256(canonical_json_bytes(value))


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _axiom_audit_sha256(inventory: list[str]) -> str:
    return _sha({"theorem": THEOREM_NAME, "axioms": inventory})


def _validate_axiom_inventory(
    inventory: Any, native_decide_uses: Any
) -> list[str]:
    if (
        not isinstance(inventory, list)
        or any(not isinstance(name, str) or not name for name in inventory)
        or inventory != sorted(set(inventory))
    ):
        raise verifier_bundle.VerifierError(
            "counterexample_axiom_inventory_invalid"
        )
    allowed = (
        {"Lean.ofReduceBool", "Lean.trustCompiler"}
        if isinstance(native_decide_uses, list) and native_decide_uses
        else set()
    )
    if set(inventory) - allowed:
        raise verifier_bundle.VerifierError(
            "counterexample_unauthorized_axiom"
        )
    return inventory


def validate_certificate(
    certificate: Any,
    *,
    target_states: dict[str, dict[str, Any]],
    accepted_commit: str,
    toolchain_lock_sha256: str,
    confirmed_sha256: str | None,
) -> dict[str, Any]:
    """Validate the certificate identity before or after clean confirmation."""
    if not isinstance(certificate, dict) or set(certificate) != CERTIFICATE_FIELDS:
        raise verifier_bundle.VerifierError("counterexample_certificate_invalid")
    body = {
        key: value for key, value in certificate.items() if key != "certificate_sha256"
    }
    target = certificate.get("target")
    target_state = target_states.get(target) if isinstance(target, str) else None
    witness = certificate.get("lean_witness")
    if (
        certificate.get("schema") != "autofv-counterexample-certificate/v1"
        or certificate.get("certificate_sha256") != _sha(body)
        or confirmed_sha256 != certificate.get("certificate_sha256")
        or not isinstance(target_state, dict)
        or target_state.get("status") != "false_spec"
        or certificate.get("statement_sha256")
        != target_state.get("statement_sha256")
        or certificate.get("accepted_commit") != accepted_commit
        or certificate.get("toolchain_lock_sha256") != toolchain_lock_sha256
        or not isinstance(certificate.get("concrete_inputs"), list)
        or not certificate["concrete_inputs"]
        or not isinstance(witness, str)
        or not witness.strip()
        or len(witness.encode()) > 64 * 1024
        or _FORBIDDEN_WITNESS.search(witness)
        or certificate.get("artifact_sha256")
        != verifier_bundle._sha256(witness.encode())
        or not _is_sha256(certificate.get("diagnostics_sha256"))
        or not isinstance(certificate.get("native_decide_uses"), list)
        or not isinstance(certificate.get("compiler_assumptions"), list)
        or not isinstance(certificate.get("axiom_inventory"), list)
        or certificate.get("axiom_audit_sha256")
        != _axiom_audit_sha256(certificate.get("axiom_inventory", []))
        or certificate.get("verification_command") != VERIFICATION_COMMAND
    ):
        raise verifier_bundle.VerifierError(
            "counterexample_certificate_binding_mismatch"
        )
    try:
        lock = contracts.load_toolchain_lock()
        if _sha(lock) != toolchain_lock_sha256:
            raise contracts.ContractError("toolchain lock mismatch")
        contracts.evaluate_native_decide_policy(
            lock,
            native_decide_uses=certificate["native_decide_uses"],
            compiler_assumptions=certificate["compiler_assumptions"],
        )
        _validate_axiom_inventory(
            certificate["axiom_inventory"], certificate["native_decide_uses"]
        )
    except (contracts.ContractError, OSError) as exc:
        raise verifier_bundle.VerifierError(
            "counterexample_native_decide_policy_invalid"
        ) from exc
    return certificate


def resolve_obligation(
    reference_bytes: bytes,
    certificate: dict[str, Any],
    target_states: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Resolve one target/input-specific obligation from hash-bound hidden bytes."""
    reference = verifier_bundle._strict_json(reference_bytes, "verifier_reference")
    obligations = reference.get("counterexample_obligations")
    if obligations is None:
        return None
    if not isinstance(obligations, list):
        raise verifier_bundle.VerifierError("counterexample_obligations_invalid")
    target = certificate.get("target")
    matches = []
    for obligation in obligations:
        if not isinstance(obligation, dict) or set(obligation) != OBLIGATION_FIELDS:
            raise verifier_bundle.VerifierError("counterexample_obligation_invalid")
        if obligation.get("target") == target:
            matches.append(obligation)
    if len(matches) != 1:
        if not matches:
            return None
        raise verifier_bundle.VerifierError("counterexample_obligation_ambiguous")
    obligation = matches[0]
    target_state = target_states.get(target) if isinstance(target, str) else None
    if (
        not isinstance(target_state, dict)
        or target_state.get("statement_sha256")
        != obligation.get("statement_sha256")
        or certificate.get("statement_sha256")
        != obligation.get("statement_sha256")
        or certificate.get("concrete_inputs") != obligation.get("concrete_inputs")
        or not _valid_obligation_wrapper(obligation)
    ):
        raise verifier_bundle.VerifierError("counterexample_obligation_binding_mismatch")
    return obligation


def _valid_obligation_wrapper(obligation: Any) -> bool:
    return bool(
        isinstance(obligation, dict)
        and isinstance(obligation.get("lean_prefix"), str)
        and "\nnamespace AutoFV\ntheorem counterexample : "
        in obligation["lean_prefix"]
        and obligation["lean_prefix"].endswith(":= by\n")
        and obligation.get("lean_suffix") == "\nend AutoFV\n"
    )


def _obligation_proposition(obligation: dict[str, Any]) -> str:
    marker = "\nnamespace AutoFV\ntheorem counterexample : "
    prefix = obligation.get("lean_prefix")
    if not _valid_obligation_wrapper(obligation) or not isinstance(prefix, str):
        raise verifier_bundle.VerifierError("counterexample_obligation_binding_mismatch")
    proposition = prefix.split(marker, 1)[1].removesuffix(" := by\n")
    if not proposition.strip():
        raise verifier_bundle.VerifierError("counterexample_obligation_binding_mismatch")
    return proposition


def _obligation_imports(obligation: dict[str, Any]) -> list[str]:
    """Extract the controller-supplied modules needed by the fixed proposition."""
    prefix = obligation.get("lean_prefix")
    if not _valid_obligation_wrapper(obligation) or not isinstance(prefix, str):
        raise verifier_bundle.VerifierError("counterexample_obligation_binding_mismatch")
    header = prefix.split("\nnamespace AutoFV\n", 1)[0]
    modules = re.findall(
        r"^import ([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)$",
        header,
        re.MULTILINE,
    )
    if not modules or len(modules) != len(set(modules)):
        raise verifier_bundle.VerifierError("counterexample_obligation_binding_mismatch")
    return sorted(modules)


def build_program(
    certificate: dict[str, Any], obligation: dict[str, Any] | None
) -> bytes:
    """Insert only an untrusted tactic body into a trusted obligation wrapper."""
    witness = certificate.get("lean_witness")
    if (
        obligation is None
        or not _valid_obligation_wrapper(obligation)
        or not isinstance(witness, str)
        or not witness.strip()
        or _FORBIDDEN_WITNESS.search(witness)
    ):
        raise verifier_bundle.VerifierError("counterexample_witness_unsafe")
    program = (
        obligation["lean_prefix"] + witness.rstrip() + obligation["lean_suffix"]
    ).encode()
    if re.search(rb"\b(?:sorry|sorryAx|admit|axiom)\b|@\[(?:extern|implemented_by)\b", program):
        raise verifier_bundle.VerifierError("counterexample_witness_trust_failed")
    return program


def _checked(completed: Any, label: str) -> Any:
    if getattr(completed, "returncode", None) != 0:
        raise verifier_bundle.VerifierError(f"counterexample_{label}_failed")
    return completed


def _compiler_assumptions(lock: dict[str, Any]) -> list[dict[str, str]]:
    evidence = {
        "Lean.ofReduceBool": (
            f"{lock['tools']['lean']['pin']} / {lock['tools']['lean']['observed_version']}"
        ),
        "Lean.trustCompiler": (
            f"{lock['tools']['rustc']['pin']} / {lock['tools']['rustc']['observed_version']}"
        ),
    }
    return [
        {
            "assumption": name,
            "evidence": evidence[name],
            "evidence_sha256": verifier_bundle._sha256(evidence[name].encode()),
        }
        for name in ("Lean.ofReduceBool", "Lean.trustCompiler")
    ]


def _native_decide_uses(
    certificate: dict[str, Any], obligation: dict[str, Any]
) -> list[dict[str, str]]:
    uses = []
    for source_path, source, origin in (
        (
            "counterexample-reference.lean",
            obligation["lean_prefix"] + obligation["lean_suffix"],
            "baseline",
        ),
        (
            "counterexample-witness.lean",
            certificate["lean_witness"],
            "agent_introduced",
        ),
    ):
        source_sha256 = verifier_bundle._sha256(source.encode())
        for line in source.splitlines():
            code = line.split("--", 1)[0]
            for _ in re.finditer(r"\bnative_decide\b", code):
                uses.append(
                    {
                        "spec": certificate["target"],
                        "declaration": certificate["target"],
                        "source_path": source_path,
                        "source_sha256": source_sha256,
                        "expression_sha256": verifier_bundle._sha256(
                            code.strip().encode()
                        ),
                        "origin": origin,
                    }
                )
    return axiom_audit.canonical_native_uses(uses)


def confirm(
    certificate: dict[str, Any],
    obligation: dict[str, Any],
    *,
    image: str,
    volume: str,
    audit_volume: str,
    runtime: str,
    runtime_argv: Callable[..., tuple[str, ...]],
    docker: Callable[..., Any],
    seed_file: Callable[..., None],
    native_decide_policy_sha256: str,
) -> str:
    """Build offline, emit an olean, then kernel-audit the fixed theorem."""
    program = build_program(certificate, obligation)
    lock = contracts.load_toolchain_lock()
    if lock.get("native_decide_policy_sha256") != native_decide_policy_sha256:
        raise verifier_bundle.VerifierError("counterexample_native_decide_policy_mismatch")
    discovered_uses = _native_decide_uses(certificate, obligation)
    expected_assumptions = _compiler_assumptions(lock)
    if (
        certificate.get("native_decide_uses") != discovered_uses
        or certificate.get("compiler_assumptions") != expected_assumptions
    ):
        raise verifier_bundle.VerifierError(
            "counterexample_native_decide_inventory_mismatch"
        )
    try:
        contracts.evaluate_native_decide_policy(
            lock,
            native_decide_uses=discovered_uses,
            compiler_assumptions=expected_assumptions,
        )
    except contracts.ContractError as exc:
        raise verifier_bundle.VerifierError(
            "counterexample_native_decide_policy_invalid"
        ) from exc
    audit_build_argv = runtime_argv(
        image,
        audit_volume,
        "lake",
        "build",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*audit_build_argv), "audit_dependency_build")
    pristine_argv = runtime_argv(
        image,
        audit_volume,
        "sh",
        "-eu",
        "-c",
        "test ! -e AutoFVCounterexample.lean; "
        "test ! -e AutoFVCounterexampleAudit.lean; "
        "test ! -e AutoFVExpected.lean; "
        f"test ! -e {OLEAN_PATH}",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*pristine_argv), "audit_pristine")
    proposition = _obligation_proposition(obligation)
    baseline_modules = _obligation_imports(obligation)
    bindings = [
        f"axiom AutoFVExpectedCounterexample : {proposition}",
        f"#autofv_same_type AutoFVExpectedCounterexample {THEOREM_NAME}",
    ]
    seed_file(
        image,
        audit_volume,
        f"repo/{axiom_audit.EXPECTED_SOURCE}",
        axiom_audit.expected_program(baseline_modules, bindings),
        runtime=runtime,
    )
    expected_argv = runtime_argv(
        image,
        audit_volume,
        "lake",
        "env",
        "lean",
        "-o",
        axiom_audit.EXPECTED_OLEAN,
        axiom_audit.EXPECTED_SOURCE,
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*expected_argv), "expected_type_build")
    preserve_expected_argv = runtime_argv(
        image,
        audit_volume,
        "sh",
        "-eu",
        "-c",
        "mkdir .autofv-baseline; "
        f"cp {axiom_audit.EXPECTED_OLEAN} "
        ".autofv-baseline/AutoFVExpected.olean",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*preserve_expected_argv), "expected_type_preserve")
    audit = axiom_audit.counterexample_audit_program(
        module="AutoFVCounterexample",
        theorem=THEOREM_NAME,
        proposition=proposition,
        baseline_modules=baseline_modules,
    )
    seed_file(
        image,
        audit_volume,
        f"repo/{AUDIT_PATH}",
        audit,
        runtime=runtime,
    )

    build_argv = runtime_argv(
        image,
        volume,
        "lake",
        "build",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*build_argv), "witness_dependency_build")
    witness_pristine_argv = runtime_argv(
        image,
        volume,
        "sh",
        "-eu",
        "-c",
        "test ! -e AutoFVCounterexample.lean; "
        "test ! -e AutoFVCounterexampleAudit.lean; "
        f"test ! -e {OLEAN_PATH}",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*witness_pristine_argv), "witness_pristine")
    seed_file(image, volume, f"repo/{SOURCE_PATH}", program, runtime=runtime)
    argv = runtime_argv(
        image,
        volume,
        *certificate["verification_command"],
        workdir="/project/repo",
        runtime=runtime,
    )
    if not argv or argv[0] != "run":
        raise verifier_bundle.VerifierError("counterexample_runtime_command_invalid")
    completed = _checked(docker(*argv), "compile")
    diagnostics = completed.stdout + b"\0" + completed.stderr
    if verifier_bundle._sha256(diagnostics) != certificate.get(
        "diagnostics_sha256"
    ):
        raise verifier_bundle.VerifierError("counterexample diagnostics mismatch")
    exists_argv = runtime_argv(
        image,
        volume,
        "test",
        "-s",
        f"/project/repo/{OLEAN_PATH}",
        workdir="/project/repo",
        runtime=runtime,
    )
    _checked(docker(*exists_argv), "artifact")
    read_argv = runtime_argv(
        image,
        volume,
        "cat",
        f"/project/repo/{OLEAN_PATH}",
        workdir="/project/repo",
        runtime=runtime,
        read_only_volume=True,
    )
    artifact = _checked(docker(*read_argv), "artifact_read").stdout
    if not artifact or len(artifact) > 16 * 1024 * 1024:
        raise verifier_bundle.VerifierError("counterexample_artifact_invalid")
    seed_file(
        image,
        audit_volume,
        f"repo/{OLEAN_PATH}",
        artifact,
        runtime=runtime,
    )
    audit_argv = runtime_argv(
        image,
        audit_volume,
        "lake",
        "env",
        "lean",
        "--run",
        AUDIT_PATH,
        workdir="/project/repo",
        runtime=runtime,
        read_only_volume=True,
    )
    audit_completed = _checked(docker(*audit_argv), "axiom_audit")
    expected_inventory = [
        {
            "declaration": THEOREM_NAME,
            "origin": "counterexample",
            "type_sha256": verifier_bundle._sha256(proposition.encode()),
            "semantic_dependencies": [certificate["target"]],
            "dependencies": [certificate["target"]],
            "axioms": [],
            "native_decide_uses": discovered_uses,
        }
    ]
    try:
        replayed, checked, _baseline_bound = (
            axiom_audit.parse_kernel_replay_provenance(
                audit_completed.stdout, audit_completed.stderr
            )
        )
        if THEOREM_NAME not in replayed or THEOREM_NAME not in checked:
            raise contracts.ContractError(
                "counterexample kernel replay is incomplete"
            )
        audited = axiom_audit.parse_inventory(
            audit_completed.stdout, audit_completed.stderr, expected_inventory
        )
        axiom_audit.validate_inventory(
            audited,
            expected_inventory,
            lock=lock,
            compiler_assumptions=expected_assumptions,
        )
    except contracts.ContractError as exc:
        raise verifier_bundle.VerifierError(
            "counterexample_unauthorized_axiom"
        ) from exc
    inventory = audited[0]["axioms"]
    if (
        inventory != certificate.get("axiom_inventory")
        or _axiom_audit_sha256(inventory)
        != certificate.get("axiom_audit_sha256")
    ):
        raise verifier_bundle.VerifierError(
            "counterexample_axiom_audit_mismatch"
        )
    return certificate["certificate_sha256"]
