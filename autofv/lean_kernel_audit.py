"""Lean kernel-output parsing, type bindings, and identity comparison."""

from __future__ import annotations

import re
from typing import Any

from . import contracts


def _lean_name(name: Any) -> str:
    if not isinstance(name, str) or re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*", name
    ) is None:
        raise contracts.ContractError("kernel audit declaration name is invalid")
    return name


def _permitted_incomplete_accepted(
    expected: list[dict[str, Any]], declarations: list[str] | None
) -> list[str]:
    declarations = declarations or []
    if (
        len(declarations) > 1
        or declarations != sorted(set(declarations))
        or any(
            not isinstance(declaration, str)
            or not any(
                record.get("declaration") == declaration
                and record.get("origin") == "accepted_spec"
                for record in expected
                if isinstance(record, dict)
            )
            for declaration in declarations
        )
    ):
        raise contracts.ContractError(
            "kernel incomplete accepted declaration is invalid"
        )
    return declarations


def _observation_names(expected: list[dict[str, Any]]) -> list[str]:
    names = {
        _lean_name(name)
        for record in expected
        for name in [
            record.get("declaration"),
            *record.get("dependencies", []),
            *(
                use.get("declaration")
                for use in record.get("native_decide_uses", [])
                if isinstance(use, dict)
            ),
        ]
    }
    return sorted(names)


def _binding_pairs(
    bindings: list[str],
) -> tuple[
    list[tuple[str, str]],
    list[tuple[str, str]],
    list[tuple[str, str]],
]:
    kinds = {
        "same_type": [],
        "defeq_type": [],
        "same_value": [],
    }
    declaration = re.compile(
        r"#autofv_(same_type|defeq_type|same_value)\s+(\S+)\s+(\S+)"
    )
    for line in bindings:
        if line.startswith(("axiom ", "def ")):
            continue
        match = declaration.fullmatch(line)
        if match is None:
            raise contracts.ContractError("kernel audit binding is invalid")
        kind, expected, actual = match.groups()
        kinds[kind].append((_lean_name(expected), _lean_name(actual)))
    return kinds["same_type"], kinds["defeq_type"], kinds["same_value"]


def parse_kernel_identities(
    stdout: bytes, stderr: bytes, declarations: list[str]
) -> dict[str, dict[str, Any]]:
    """Parse controller-generated observation markers from Lean diagnostics."""
    text = (stdout + b"\n" + stderr).decode("utf-8", "strict")
    identities = {}
    for declaration in declarations:
        escaped = re.escape(declaration)

        def block(kind: str) -> str:
            match = re.search(
                rf"AUTOFV_{kind}_BEGIN:{escaped}[^\n]*\n"
                rf"(.*?)AUTOFV_{kind}_END:{escaped}",
                text,
                flags=re.DOTALL,
            )
            if match is None:
                raise contracts.ContractError(
                    "kernel declaration identity is incomplete"
                )
            value = match.group(1).strip()
            return re.sub(r"^.*?: info: ", "", value, count=1)

        dependency_match = re.search(
            rf"AUTOFV_DEPS:{escaped}:([^\n]*)", text
        )
        project_match = re.search(
            rf"AUTOFV_PROJECT_DEPS:{escaped}:([^\n]*)", text
        )
        if dependency_match is None or project_match is None:
            raise contracts.ContractError(
                "kernel declaration identity is incomplete"
            )
        dependencies = sorted(
            item for item in dependency_match.group(1).strip().split(",") if item
        )
        project_dependencies = sorted(
            item for item in project_match.group(1).strip().split(",") if item
        )
        if not set(project_dependencies) <= set(dependencies):
            raise contracts.ContractError(
                "kernel declaration identity is incomplete"
            )
        identities[declaration] = {
            "type_repr": block("TYPE"),
            "value_repr": block("VALUE"),
            "dependencies": dependencies,
            "project_dependencies": project_dependencies,
        }
    return identities


def parse_kernel_replay_provenance(
    stdout: bytes, stderr: bytes
) -> tuple[set[str], set[str], set[str]]:
    """Parse the exact kernel-checked versus pristine-bound declaration split."""
    text = (stdout + b"\n" + stderr).decode("utf-8", "strict")
    parsed = []
    for marker in (
        "AUTOFV_REPLAYED",
        "AUTOFV_KERNEL_CHECKED",
        "AUTOFV_BASELINE_BOUND",
    ):
        matches = re.findall(rf"{marker}:([^\n]*)", text)
        if len(matches) != 1:
            raise contracts.ContractError("kernel declaration replay is incomplete")
        names = [item for item in matches[0].strip().split(",") if item]
        if len(names) != len(set(names)) or any(
            _lean_name(name) != name for name in names
        ):
            raise contracts.ContractError("kernel declaration replay is incomplete")
        parsed.append(set(names))
    replayed, checked, baseline_bound = parsed
    if checked & baseline_bound or (checked | baseline_bound) != replayed:
        raise contracts.ContractError("kernel declaration replay is incomplete")
    return replayed, checked, baseline_bound


def parse_kernel_replay(stdout: bytes, stderr: bytes) -> set[str]:
    """Require the fresh checker to report every transferred declaration."""
    return parse_kernel_replay_provenance(stdout, stderr)[0]


def parse_project_kernel_identities(
    stdout: bytes, stderr: bytes, roots: list[str]
) -> dict[str, dict[str, Any]]:
    """Recover identities for every project constant in each full root closure."""
    root_identities = parse_kernel_identities(stdout, stderr, roots)
    project = sorted(
        {
            name
            for identity in root_identities.values()
            for name in identity["project_dependencies"]
        }
    )
    identities = {
        name: root_identities[name]
        for name in project
        if name in root_identities
    }
    text = (stdout + b"\n" + stderr).decode("utf-8", "strict")
    for declaration in project:
        if declaration in identities:
            continue
        escaped = re.escape(declaration)

        def block(kind: str) -> str:
            match = re.search(
                rf"AUTOFV_{kind}_BEGIN:{escaped}[^\n]*\n"
                rf"(.*?)AUTOFV_{kind}_END:{escaped}",
                text,
                flags=re.DOTALL,
            )
            if match is None:
                raise contracts.ContractError(
                    "kernel declaration identity is incomplete"
                )
            return re.sub(
                r"^.*?: info: ", "", match.group(1).strip(), count=1
            )

        identities[declaration] = {
            "type_repr": block("TYPE"),
            "value_repr": block("VALUE"),
            "dependencies": [],
            "project_dependencies": [],
        }
    return identities


def type_bindings(
    state: dict[str, Any], reference: dict[str, Any]
) -> list[str]:
    """Generate controller-owned exact-type checks for transferred declarations."""
    bindings = []
    for index, (declaration, contract) in enumerate(
        sorted(state.get("frozen_contracts", {}).items())
    ):
        canon = contract.get("canon")
        prefix = f"theorem {declaration}"
        if not isinstance(canon, str) or not canon.startswith(prefix):
            raise contracts.ContractError("kernel audit contract type invalid")
        bindings.extend(
            (
                f"axiom AutoFVExpectedAccepted{index}{canon[len(prefix):]}",
                f"#autofv_same_type AutoFVExpectedAccepted{index} {declaration}",
            )
        )
    for index, leaf in enumerate(reference.get("leaves", [])):
        statement = leaf.get("statement") if isinstance(leaf, dict) else None
        if not isinstance(statement, str) or not statement:
            raise contracts.ContractError("kernel audit reference type invalid")
        bindings.extend(
            (
                f"def AutoFVExpectedMeaning{index} : Prop := {statement}",
                f"axiom AutoFVExpectedHidden{index} : {statement}",
                f"#autofv_defeq_type AutoFVExpectedHidden{index} "
                f"AutoFVVerifier.hidden_{index}",
                f"#autofv_same_value AutoFVExpectedMeaning{index} "
                f"AutoFVVerifier.meaning_{index}",
            )
        )
    return bindings


def compare_kernel_identities(
    baseline: dict[str, dict[str, Any]],
    accepted: dict[str, dict[str, Any]],
    *,
    frozen_types: set[str],
    frozen_definitions: set[str],
    proof_generated: set[str] = frozenset(),
) -> None:
    """Require exact baseline types and immutable semantic definitions."""
    if (
        not frozen_definitions <= set(baseline)
        or not frozen_definitions <= set(accepted)
        or not frozen_types <= set(accepted)
    ):
        raise contracts.ContractError("kernel declaration identity is incomplete")
    if set(accepted) - set(baseline) - frozen_types - proof_generated:
        raise contracts.ContractError("kernel declaration identity mismatch")
    if any(
        baseline[name].get("type_repr") != accepted[name].get("type_repr")
        for name in (frozen_types & set(baseline)) | frozen_definitions
    ) or any(
        baseline[name] != accepted[name]
        for name in frozen_definitions
    ):
        raise contracts.ContractError("kernel declaration identity mismatch")


def proof_generated_project_dependencies(
    project_identities: dict[str, dict[str, Any]],
    baseline_identities: dict[str, dict[str, Any]],
    observations: dict[str, dict[str, Any]],
    expected: list[dict[str, Any]],
    state: dict[str, Any],
    replayed: set[str],
) -> set[str]:
    """Classify replayed, proof-only native helpers by observed provenance."""
    frozen = set(state.get("frozen_contracts", {}))
    generated = set(project_identities) - set(baseline_identities) - frozen
    if not generated:
        return set()
    semantic_roots = {
        dependency
        for record in expected
        for dependency in record.get("semantic_dependencies", [])
    }
    semantic_closure = {
        dependency
        for root in semantic_roots
        for dependency in observations.get(root, {}).get(
            "project_dependencies", []
        )
    }
    native_roots = {
        candidate
        for use in state.get("native_decide_uses", [])
        if isinstance(use, dict)
        for candidate in (use.get("spec"), use.get("declaration"))
        if candidate in frozen
    }
    native_closure = {
        dependency
        for root in native_roots
        for dependency in observations.get(root, {}).get(
            "project_dependencies", []
        )
    }
    if (
        not generated <= replayed
        or bool(generated & semantic_closure)
        or not generated <= native_closure
    ):
        raise contracts.ContractError("kernel declaration identity mismatch")
    return generated
