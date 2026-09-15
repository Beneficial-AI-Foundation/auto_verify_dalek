"""Public compatibility facade for the split trusted Lean audit subsystem.

Inventory policy, Lean kernel replay, and volume orchestration live in focused
modules. Existing callers may continue importing :mod:`autofv.axiom_audit`.
"""

from . import contracts
from .audit_volume import audit_artifacts, checkout_volume, olean_paths, prepare_auditor
from .axiom_inventory import (
    COMPILER_AXIOMS,
    _RECORD_FIELDS,
    _contract_dependency_nodes,
    _contract_nodes,
    _dependency_closure,
    _native_uses,
    _reference_uses,
    _sha,
    _use_key,
    accepted_declaration_for_target,
    canonical_native_uses,
    expected_inventory,
    inventory_identity_sha256,
    inventory_scope_sha256,
    native_use_provenance,
    parse_inventory,
    validate_inventory,
    validate_report_inventory,
)
from .lean_audit_program import (
    AUDIT_SOURCE,
    BASELINE_SOURCE,
    EXPECTED_OLEAN,
    EXPECTED_SOURCE,
    REFERENCE_OLEAN,
    REFERENCE_SOURCE,
    _audit_prelude,
    _trusted_baseline_prelude,
    audit_program,
    baseline_program,
    counterexample_audit_program,
    expected_program,
    project_modules,
    reference_program,
)
from .lean_kernel_audit import (
    _binding_pairs,
    _lean_name,
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

__all__ = [
    "AUDIT_SOURCE", "BASELINE_SOURCE", "COMPILER_AXIOMS",
    "EXPECTED_OLEAN", "EXPECTED_SOURCE", "REFERENCE_OLEAN",
    "REFERENCE_SOURCE", "accepted_declaration_for_target",
    "audit_artifacts", "audit_program", "baseline_program",
    "canonical_native_uses", "checkout_volume",
    "compare_kernel_identities", "counterexample_audit_program",
    "expected_inventory", "expected_program",
    "inventory_identity_sha256", "inventory_scope_sha256",
    "native_use_provenance", "olean_paths", "parse_inventory",
    "parse_kernel_identities", "parse_kernel_replay",
    "parse_kernel_replay_provenance", "parse_project_kernel_identities",
    "prepare_auditor", "project_modules",
    "proof_generated_project_dependencies", "reference_program",
    "type_bindings", "validate_inventory", "validate_report_inventory",
]
