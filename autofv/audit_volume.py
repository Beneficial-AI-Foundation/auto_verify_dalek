"""Trusted-volume checkout, auditor preparation, and artifact transfer."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Callable

from . import contracts
from .axiom_inventory import expected_inventory, parse_inventory
from .lean_audit_program import (
    AUDIT_SOURCE,
    BASELINE_SOURCE,
    EXPECTED_OLEAN,
    EXPECTED_SOURCE,
    REFERENCE_OLEAN,
    audit_program,
    baseline_program,
    expected_program,
    project_modules,
)
from .lean_kernel_audit import (
    _observation_names,
    _permitted_incomplete_accepted,
    compare_kernel_identities,
    parse_kernel_identities,
    parse_kernel_replay,
    parse_kernel_replay_provenance,
    parse_project_kernel_identities,
    proof_generated_project_dependencies,
    type_bindings,
)


def olean_paths(graph: dict[str, Any]) -> list[str]:
    paths = {REFERENCE_OLEAN}
    for source in graph.get("source_paths", {}).values():
        path = PurePosixPath(source)
        if path.is_absolute() or path.suffix != ".lean" or ".." in path.parts:
            raise contracts.ContractError("kernel audit source path is unsafe")
        paths.add(f".lake/build/lib/lean/{path.with_suffix('.olean')}")
    return sorted(paths)


def checkout_volume(
    *,
    image: str,
    volume: str,
    repository_bundle: bytes,
    commit: str,
    runtime: str,
    docker: Callable[..., Any],
    runtime_argv: Callable[..., tuple[str, ...]],
    seed_file: Callable[..., None],
) -> None:
    """Create an exact detached checkout with fixed audit names reserved."""
    seed_file(
        image, volume, "repository.bundle", repository_bundle, runtime=runtime
    )
    completed = docker(
        *runtime_argv(
            image,
            volume,
            "sh",
            "-eu",
            "-c",
            "mkdir repo; git init -q repo; "
            "git -C repo fetch -q /project/repository.bundle \"$1\"; "
            "git -C repo checkout -q --detach FETCH_HEAD; "
            "rm /project/repository.bundle; "
            "test \"$(git -C repo rev-parse HEAD)\" = \"$1\"; "
            "test ! -e repo/AutoFVReferenceCheck.lean; "
            "test ! -e repo/AutoFVExpected.lean; "
            "test ! -e repo/AutoFVBaselineAudit.lean; "
            "test ! -e repo/AutoFVAxiomAudit.lean",
            "autofv-checkout",
            commit,
            runtime=runtime,
        )
    )
    if completed.returncode:
        raise contracts.ContractError("kernel audit checkout failed")


def prepare_auditor(
    *,
    image: str,
    volume: str,
    repository_bundle: bytes,
    base_commit: str,
    verify_command: list[str],
    expected: list[dict[str, Any]],
    state: dict[str, Any],
    reference: dict[str, Any],
    runtime: str,
    docker: Callable[..., Any],
    runtime_argv: Callable[..., tuple[str, ...]],
    seed_file: Callable[..., None],
    permitted_incomplete_accepted: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build pristine baseline dependencies and install the auditor first."""
    checkout_volume(
        image=image,
        volume=volume,
        repository_bundle=repository_bundle,
        commit=base_commit,
        runtime=runtime,
        docker=docker,
        runtime_argv=runtime_argv,
        seed_file=seed_file,
    )
    pristine = docker(
        *runtime_argv(
            image,
            volume,
            "sh",
            "-eu",
            "-c",
            "test ! -e .lake/build",
            workdir="/project/repo",
            runtime=runtime,
        )
    )
    if pristine.returncode:
        raise contracts.ContractError("kernel baseline volume is not pristine")
    built = docker(
        *runtime_argv(
            image,
            volume,
            *verify_command,
            workdir="/project/repo",
            runtime=runtime,
        )
    )
    if built.returncode:
        raise contracts.ContractError("kernel baseline build failed")
    bindings = type_bindings(state, reference)
    seed_file(
        image,
        volume,
        f"repo/{EXPECTED_SOURCE}",
        expected_program(project_modules(state), bindings),
        runtime=runtime,
    )
    expected_built = docker(
        *runtime_argv(
            image,
            volume,
            "lake",
            "env",
            "lean",
            "-o",
            EXPECTED_OLEAN,
            EXPECTED_SOURCE,
            workdir="/project/repo",
            runtime=runtime,
        )
    )
    if expected_built.returncode:
        raise contracts.ContractError("kernel expected-type build failed")
    preserved = docker(
        *runtime_argv(
            image,
            volume,
            "sh",
            "-eu",
            "-c",
            "test ! -e .autofv-baseline; "
            "test -d .lake/build/lib/lean; "
            "mkdir .autofv-baseline; "
            "cp -R .lake/build/lib/lean/. .autofv-baseline/",
            workdir="/project/repo",
            runtime=runtime,
        )
    )
    if preserved.returncode:
        raise contracts.ContractError("kernel baseline preservation failed")
    baseline_source, definitions = baseline_program(state, reference)
    seed_file(
        image,
        volume,
        f"repo/{BASELINE_SOURCE}",
        baseline_source,
        runtime=runtime,
    )
    observed = docker(
        *runtime_argv(
            image,
            volume,
            "lake",
            "env",
            "lean",
            "--run",
            BASELINE_SOURCE,
            workdir="/project/repo",
            runtime=runtime,
            read_only_volume=True,
        )
    )
    if observed.returncode:
        raise contracts.ContractError("kernel baseline audit failed")
    replayed = parse_kernel_replay(observed.stdout, observed.stderr)
    identities = parse_project_kernel_identities(
        observed.stdout, observed.stderr, definitions
    )
    if not set(identities) <= replayed:
        raise contracts.ContractError("kernel declaration replay is incomplete")
    seed_file(
        image,
        volume,
        f"repo/{AUDIT_SOURCE}",
        audit_program(
            expected,
            bindings=bindings,
            project_modules=project_modules(state),
            permitted_incomplete_accepted=permitted_incomplete_accepted,
        ),
        runtime=runtime,
    )
    return identities


def audit_artifacts(
    *,
    image: str,
    witness_volume: str,
    audit_volume: str,
    artifacts: list[str],
    expected: list[dict[str, Any]],
    state: dict[str, Any] | None = None,
    reference: dict[str, Any] | None = None,
    baseline_identities: dict[str, dict[str, Any]] | None = None,
    runtime: str,
    max_artifact_bytes: int,
    docker: Callable[..., Any],
    runtime_argv: Callable[..., tuple[str, ...]],
    seed_file: Callable[..., None],
    permitted_incomplete_accepted: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Transfer only selected oleans, then query axioms on a read-only volume."""
    _permitted_incomplete_accepted(expected, permitted_incomplete_accepted)
    allowed = {f"repo/{path}" for path in artifacts}
    for path in artifacts:
        completed = docker(
            *runtime_argv(
                image,
                witness_volume,
                "cat",
                f"/project/repo/{path}",
                workdir="/project/repo",
                runtime=runtime,
                read_only_volume=True,
            )
        )
        if (
            completed.returncode
            or not completed.stdout
            or len(completed.stdout) > max_artifact_bytes
        ):
            raise contracts.ContractError("kernel audit artifact missing")
        seed_file(
            image,
            audit_volume,
            f"repo/{path}",
            completed.stdout,
            runtime=runtime,
            allowed_paths=allowed,
        )
    audited = docker(
        *runtime_argv(
            image,
            audit_volume,
            "lake",
            "env",
            "lean",
            "--run",
            AUDIT_SOURCE,
            workdir="/project/repo",
            runtime=runtime,
            read_only_volume=True,
        )
    )
    if audited.returncode:
        raise contracts.ContractError("kernel axiom audit failed")
    replayed, checked, _baseline_bound = parse_kernel_replay_provenance(
        audited.stdout, audited.stderr
    )
    if state is None or reference is None or baseline_identities is None:
        return parse_inventory(audited.stdout, audited.stderr, expected)
    observations = parse_kernel_identities(
        audited.stdout, audited.stderr, _observation_names(expected)
    )
    project_identities = parse_project_kernel_identities(
        audited.stdout, audited.stderr, _observation_names(expected)
    )
    roots = {record["declaration"] for record in expected}
    if not roots <= checked or not set(project_identities) <= replayed:
        raise contracts.ContractError("kernel declaration replay is incomplete")
    proof_generated = proof_generated_project_dependencies(
        project_identities,
        baseline_identities,
        observations,
        expected,
        state,
        checked,
    )
    compare_kernel_identities(
        baseline_identities,
        project_identities,
        frozen_types=set(state.get("frozen_contracts", {})),
        frozen_definitions=(
            set(baseline_identities) - set(state.get("frozen_contracts", {}))
        ),
        proof_generated=proof_generated,
    )
    observed_expected = expected_inventory(
        state,
        reference,
        observed_closures={
            root: observations[root]["dependencies"] for root in roots
        },
    )
    return parse_inventory(audited.stdout, audited.stderr, observed_expected)
