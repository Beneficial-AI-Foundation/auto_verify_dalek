"""Trusted Lean auditor source templates and program constructors."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from . import contracts
from .axiom_inventory import _sha, expected_inventory
from .lean_kernel_audit import (
    _binding_pairs,
    _lean_name,
    _observation_names,
    _permitted_incomplete_accepted,
)


REFERENCE_SOURCE = "AutoFVReferenceCheck.lean"
REFERENCE_OLEAN = ".lake/build/lib/lean/AutoFVReferenceCheck.olean"
BASELINE_SOURCE = "AutoFVBaselineAudit.lean"
AUDIT_SOURCE = "AutoFVAxiomAudit.lean"
EXPECTED_SOURCE = "AutoFVExpected.lean"
EXPECTED_OLEAN = ".lake/build/lib/lean/AutoFVExpected.olean"


def _trusted_baseline_prelude(
    imports: list[str],
    project_modules: list[str],
    replay_modules: list[str] | None = None,
    *,
    forced_replay: list[str] | None = None,
    permitted_sorry: list[str] | None = None,
    preserved_baseline: bool = False,
    expected_module: bool = False,
) -> str:
    quoted_modules = ", ".join(f"`{name}" for name in project_modules)
    quoted_replay_modules = ", ".join(
        f"`{name}" for name in (replay_modules or [])
    )
    quoted_forced_replay = ", ".join(
        f"`{_lean_name(name)}" for name in (forced_replay or [])
    )
    quoted_permitted_sorry = ", ".join(
        f"`{_lean_name(name)}" for name in (permitted_sorry or [])
    )
    baseline_module_names = [*project_modules]
    if expected_module:
        baseline_module_names.append("AutoFVExpected")
    baseline_imports = ", ".join(
        f"{{module := `{name}}}" for name in baseline_module_names
    )
    baseline_artifacts = ""
    if preserved_baseline:
        for module in project_modules:
            relative = module.replace(".", "/")
            baseline_artifacts += (
                f"  artifacts := artifacts.insert `{module} "
                f"(.ofArray #[\".autofv-baseline/{relative}.olean\"])\n"
            )
    if expected_module:
        baseline_artifacts += (
            "  artifacts := artifacts.insert `AutoFVExpected "
            "(.ofArray #[\".autofv-baseline/AutoFVExpected.olean\"])\n"
        )
    return (
        "import Lean\n"
        "import Lean.Replay\n"
        + "\n".join(f"import {module}" for module in imports)
        + "\n"
        "open Lean Elab Command Meta\n"
        f"def autofvAuditProjectModules : NameSet := "
        f"NameSet.ofList [{quoted_modules}]\n"
        f"def autofvAuditReplayModules : NameSet := "
        f"NameSet.ofList [{quoted_replay_modules}]\n"
        f"def autofvAuditForcedReplay : NameSet := "
        f"NameSet.ofList [{quoted_forced_replay}]\n"
        f"def autofvAuditPermittedSorry : NameSet := "
        f"NameSet.ofList [{quoted_permitted_sorry}]\n"
        f"def autofvAuditBaselineImports : Array Import := "
        f"#[{{module := `Lean}}{', ' if baseline_imports else ''}{baseline_imports}]\n"
        "def autofvAuditBaselineArtifacts : IO (NameMap ImportArtifacts) := do\n"
        "  let mut artifacts : NameMap ImportArtifacts := {}\n"
        + baseline_artifacts
        + "  return artifacts\n"
        "def autofvAuditIsProject (env : Environment) (name : Name) : Bool :=\n"
        "  match env.getModuleIdxFor? name with\n"
        "  | some index => autofvAuditProjectModules.contains "
        "env.header.moduleNames[index.toNat]!\n"
        "  | none => false\n"
        "def autofvAuditIsTransferred (env : Environment) (name : Name) : Bool :=\n"
        "  match env.getModuleIdxFor? name with\n"
        "  | some index => autofvAuditReplayModules.contains "
        "env.header.moduleNames[index.toNat]!\n"
        "  | none => false\n"
        "def autofvAuditSameQuotKind : QuotKind → QuotKind → Bool\n"
        "  | .type, .type | .ctor, .ctor | .lift, .lift | .ind, .ind => true\n"
        "  | _, _ => false\n"
        "def autofvAuditSameInductive (expected actual : InductiveVal) : Bool :=\n"
        "  expected.name == actual.name &&\n"
        "  expected.levelParams == actual.levelParams &&\n"
        "  expected.type == actual.type &&\n"
        "  expected.numParams == actual.numParams &&\n"
        "  expected.numIndices == actual.numIndices &&\n"
        "  expected.all == actual.all && expected.ctors == actual.ctors &&\n"
        "  expected.numNested == actual.numNested &&\n"
        "  expected.isRec == actual.isRec &&\n"
        "  expected.isUnsafe == actual.isUnsafe &&\n"
        "  expected.isReflexive == actual.isReflexive\n"
        "def autofvAuditSameQuotient (expected actual : QuotVal) : Bool :=\n"
        "  expected.name == actual.name &&\n"
        "  expected.levelParams == actual.levelParams &&\n"
        "  expected.type == actual.type &&\n"
        "  autofvAuditSameQuotKind expected.kind actual.kind\n"
        "def autofvAuditSameConstant : ConstantInfo → ConstantInfo → Bool\n"
        "  | .axiomInfo expected, .axiomInfo actual => expected == actual\n"
        "  | .defnInfo expected, .defnInfo actual => expected == actual\n"
        "  | .thmInfo expected, .thmInfo actual => expected == actual\n"
        "  | .opaqueInfo expected, .opaqueInfo actual => expected == actual\n"
        "  | .quotInfo expected, .quotInfo actual => "
        "autofvAuditSameQuotient expected actual\n"
        "  | .inductInfo expected, .inductInfo actual => "
        "autofvAuditSameInductive expected actual\n"
        "  | .ctorInfo expected, .ctorInfo actual => expected == actual\n"
        "  | .recInfo expected, .recInfo actual => expected == actual\n"
        "  | _, _ => false\n"
        "def autofvAuditFreshName (name : Name) : Name := "
        "`AutoFVKernelChecked ++ name\n"
        "def autofvAuditRenameExpr (renamed : NameSet) (expression : Expr) : Expr :=\n"
        "  expression.replace fun subexpression =>\n"
        "    match subexpression with\n"
        "    | .const name levels =>\n"
        "        if renamed.contains name then\n"
        "          some (.const (autofvAuditFreshName name) levels)\n"
        "        else none\n"
        "    | _ => none\n"
        "partial def autofvAuditReplayRenamed "
        "(source : Std.HashMap Name ConstantInfo) (renamed : NameSet) "
        "(name : Name) (visiting : NameSet := {}) : CoreM Unit := do\n"
        "  unless renamed.contains name do\n"
        "    let some actual := (\u2190 getEnv).find? name\n"
        "      | throwError \"missing pristine dependency {name}\"\n"
        "    if let some expected := source[name]? then\n"
        "      unless autofvAuditSameConstant expected actual do\n"
        "        throwError \"pristine dependency mismatch {name}\"\n"
        "    return\n"
        "  let freshName := autofvAuditFreshName name\n"
        "  if (\u2190 getEnv).contains freshName then return\n"
        "  if visiting.contains name then\n"
        "    throwError \"cyclic transferred declaration {name}\"\n"
        "  let some info := source[name]?\n"
        "    | throwError \"missing transferred declaration {name}\"\n"
        "  if info.isUnsafe || info.isPartial then\n"
        "    throwError \"unsafe or partial transferred declaration {name}\"\n"
        "  let visiting := visiting.insert name\n"
        "  for dependency in info.getUsedConstantsAsSet do\n"
        "    autofvAuditReplayRenamed source renamed dependency visiting\n"
        "  let declaration \u2190 match info with\n"
        "    | .defnInfo value => pure <| .defnDecl { value with\n"
        "        name := freshName\n"
        "        type := autofvAuditRenameExpr renamed value.type\n"
        "        value := autofvAuditRenameExpr renamed value.value\n"
        "        all := value.all.map fun name => if renamed.contains name then "
        "autofvAuditFreshName name else name }\n"
        "    | .thmInfo value => pure <| .thmDecl { value with\n"
        "        name := freshName\n"
        "        type := autofvAuditRenameExpr renamed value.type\n"
        "        value := autofvAuditRenameExpr renamed value.value\n"
        "        all := value.all.map fun name => if renamed.contains name then "
        "autofvAuditFreshName name else name }\n"
        "    | .opaqueInfo value => pure <| .opaqueDecl { value with\n"
        "        name := freshName\n"
        "        type := autofvAuditRenameExpr renamed value.type\n"
        "        value := autofvAuditRenameExpr renamed value.value\n"
        "        all := value.all.map fun name => if renamed.contains name then "
        "autofvAuditFreshName name else name }\n"
        "    | .axiomInfo _ => throwError \"unapproved transferred axiom {name}\"\n"
        "    | _ => throwError \"unsupported mutable declaration {name}\"\n"
        "  let checked \u2190 ofExceptKernelException <| "
        "(\u2190 getEnv).addDeclCore 0 declaration none\n"
        "  setEnv checked\n"
        "  compileDecl declaration\n"
        "partial def autofvAuditCheckedClosure (env : Environment) "
        "(pending : List Name) (seen : NameSet := {}) : NameSet :=\n"
        "  match pending with\n"
        "  | [] => seen\n"
        "  | name :: rest =>\n"
        "      if seen.contains name then\n"
        "        autofvAuditCheckedClosure env rest seen\n"
        "      else\n"
        "        let seen := seen.insert name\n"
        "        let dependencies := match env.find? name with\n"
        "          | some info => info.getUsedConstantsAsSet\n"
        "          | none => {}\n"
        "        autofvAuditCheckedClosure env "
        "(dependencies.foldl (fun pending name => name :: pending) rest) seen\n"
        "def autofvAuditReplayConstants "
        "(source : Std.HashMap Name ConstantInfo) (roots : List Name) : "
        "IO (Environment × NameSet) := do\n"
        "  let artifacts \u2190 autofvAuditBaselineArtifacts\n"
        "  let pristine \u2190 importModules autofvAuditBaselineImports {} 0 "
        "(loadExts := true) (arts := artifacts)\n"
        "  let mut renamed := autofvAuditForcedReplay\n"
        "  for name in roots do\n"
        "    let some expected := source[name]?\n"
        "      | throw <| IO.userError s!\"missing transferred declaration {name}\"\n"
        "    match pristine.find? name with\n"
        "    | some actual =>\n"
        "        unless autofvAuditSameConstant expected actual do\n"
        "          renamed := renamed.insert name\n"
        "    | none => renamed := renamed.insert name\n"
        "  unless autofvAuditForcedReplay.toList.all roots.contains do\n"
        "    throw <| IO.userError \"forced kernel replay declaration is absent\"\n"
        "  let mut changed := true\n"
        "  while changed do\n"
        "    changed := false\n"
        "    for name in roots do\n"
        "      if !renamed.contains name then\n"
        "        let some info := source[name]?\n"
        "          | throw <| IO.userError s!\"missing transferred declaration {name}\"\n"
        "        if info.getUsedConstantsAsSet.any renamed.contains then\n"
        "          renamed := renamed.insert name\n"
        "          changed := true\n"
        "  for name in renamed do\n"
        "    if pristine.contains (autofvAuditFreshName name) then\n"
        "      throw <| IO.userError s!\"kernel replay name collision {name}\"\n"
        "  let options := ({} : Options).setBool `Elab.async false\n"
        "  let (_, checked) \u2190 Lean.Core.CoreM.toIO "
        "(roots.forM (autofvAuditReplayRenamed source renamed))\n"
        "    { fileName := \"<autofv-kernel-replay>\", "
        "fileMap := default, options := options }\n"
        "    { env := pristine }\n"
        "  for name in renamed do\n"
        "    let freshName := autofvAuditFreshName name\n"
        "    unless checked.env.contains freshName do\n"
        "      throw <| IO.userError s!\"kernel replay omitted {name}\"\n"
        "    let closure := autofvAuditCheckedClosure checked.env [freshName]\n"
        "    if (closure.contains `sorryAx && "
        "!autofvAuditPermittedSorry.contains name) || "
        "closure.any renamed.contains then\n"
        "      throw <| IO.userError s!\"checked closure retained untrusted dependency {name}\"\n"
        "  return (checked.env, renamed)\n"
        "syntax (name := autofvReplayTransferred) "
        "\"#autofv_replay_transferred\" : command\n"
        "@[command_elab autofvReplayTransferred] "
        "def elabAutofvReplayTransferred : CommandElab\n"
        "  | `(#autofv_replay_transferred) => do\n"
        "      let source \u2190 getEnv\n"
        "      let mut constants : Std.HashMap Name ConstantInfo := {}\n"
        "      let mut roots : List Name := []\n"
        "      for (name, info) in source.constants.toList do\n"
        "        constants := constants.insert name info\n"
        "        if autofvAuditIsTransferred source name then\n"
        "          roots := name :: roots\n"
        "      let (_checked, renamed) \u2190 liftIO <| "
        "autofvAuditReplayConstants constants roots\n"
        "      let replayed := roots.foldl "
        "(fun names name => names ++ [name.toString]) []\n"
        "      let checkedNames := roots.foldl (fun names name =>\n"
        "        if renamed.contains name then names ++ [name.toString]\n"
        "        else names) []\n"
        "      let baselineNames := roots.foldl (fun names name =>\n"
        "        if renamed.contains name then names\n"
        "        else names ++ [name.toString]) []\n"
        "      logInfo m!\"AUTOFV_REPLAYED:"
        "{String.intercalate \",\" replayed}\"\n"
        "      logInfo m!\"AUTOFV_KERNEL_CHECKED:"
        "{String.intercalate \",\" checkedNames}\"\n"
        "      logInfo m!\"AUTOFV_BASELINE_BOUND:"
        "{String.intercalate \",\" baselineNames}\"\n"
        "  | _ => throwUnsupportedSyntax\n"
        "partial def autofvAuditClosure (env : Environment) "
        "(pending : List Name) (seen : NameSet := {}) : NameSet :=\n"
        "  match pending with\n"
        "  | [] => seen\n"
        "  | name :: rest =>\n"
        "      if seen.contains name then\n"
        "        autofvAuditClosure env rest seen\n"
        "      else\n"
        "        let seen := seen.insert name\n"
        "        let dependencies := match env.find? name with\n"
        "          | some info => info.getUsedConstantsAsSet\n"
        "          | none => {}\n"
        "        let pending := dependencies.foldl "
        "(fun pending name => name :: pending) rest\n"
        "        autofvAuditClosure env pending seen\n"
        "def autofvAuditLogIdentity (env : Environment) (name : Name) : "
        "CommandElabM Unit := do\n"
        "  let some info := env.find? name\n"
        "    | throwError \"observed declaration missing\"\n"
        "  logInfo m!\"AUTOFV_TYPE_BEGIN:{name}\"\n"
        "  logInfo m!\"{repr info.type}\"\n"
        "  logInfo m!\"AUTOFV_TYPE_END:{name}\"\n"
        "  logInfo m!\"AUTOFV_VALUE_BEGIN:{name}\"\n"
        "  logInfo m!\"{repr info.value?}\"\n"
        "  logInfo m!\"AUTOFV_VALUE_END:{name}\"\n"
        "syntax (name := autofvSameType) \"#autofv_same_type \" ident ident : command\n"
        "@[command_elab autofvSameType] def elabAutofvSameType : CommandElab\n"
        "  | `(#autofv_same_type $expected $actual) => do\n"
        "      let expectedName ← resolveGlobalConstNoOverload expected\n"
        "      let actualName ← resolveGlobalConstNoOverload actual\n"
        "      let env ← getEnv\n"
        "      let some expectedInfo := env.find? expectedName\n"
        "        | throwError \"expected declaration missing\"\n"
        "      let some actualInfo := env.find? actualName\n"
        "        | throwError \"audited declaration missing\"\n"
        "      unless expectedInfo.type == actualInfo.type do\n"
        "        throwError \"audited declaration type mismatch\"\n"
        "  | _ => throwUnsupportedSyntax\n"
        "syntax (name := autofvDefeqType) \"#autofv_defeq_type \" ident ident : command\n"
        "@[command_elab autofvDefeqType] def elabAutofvDefeqType : CommandElab\n"
        "  | `(#autofv_defeq_type $expected $actual) => do\n"
        "      let expectedName ← resolveGlobalConstNoOverload expected\n"
        "      let actualName ← resolveGlobalConstNoOverload actual\n"
        "      let env ← getEnv\n"
        "      let some expectedInfo := env.find? expectedName\n"
        "        | throwError \"expected declaration missing\"\n"
        "      let some actualInfo := env.find? actualName\n"
        "        | throwError \"audited declaration missing\"\n"
        "      let equivalent ← liftTermElabM do\n"
        "        isDefEq expectedInfo.type actualInfo.type\n"
        "      unless equivalent do\n"
        "        throwError \"audited declaration type mismatch\"\n"
        "  | _ => throwUnsupportedSyntax\n"
        "syntax (name := autofvSameValue) \"#autofv_same_value \" ident ident : command\n"
        "@[command_elab autofvSameValue] def elabAutofvSameValue : CommandElab\n"
        "  | `(#autofv_same_value $expected $actual) => do\n"
        "      let expectedName ← resolveGlobalConstNoOverload expected\n"
        "      let actualName ← resolveGlobalConstNoOverload actual\n"
        "      let env ← getEnv\n"
        "      let some expectedInfo := env.find? expectedName\n"
        "        | throwError \"expected declaration missing\"\n"
        "      let some actualInfo := env.find? actualName\n"
        "        | throwError \"audited declaration missing\"\n"
        "      unless expectedInfo.value? == actualInfo.value? do\n"
        "        throwError \"audited declaration value mismatch\"\n"
        "  | _ => throwUnsupportedSyntax\n"
        "syntax (name := autofvObserve) \"#autofv_observe \" ident : command\n"
        "@[command_elab autofvObserve] def elabAutofvObserve : CommandElab\n"
        "  | `(#autofv_observe $declaration) => do\n"
        "      let name ← resolveGlobalConstNoOverload declaration\n"
        "      let env ← getEnv\n"
        "      let closure := autofvAuditClosure env [name]\n"
        "      let dependencies := closure.foldl "
        "(fun names name => names ++ [name.toString]) []\n"
        "      let projectDependencies := closure.foldl (fun names dependency =>\n"
        "        if autofvAuditIsProject env dependency then\n"
        "          names ++ [dependency.toString]\n"
        "        else names) []\n"
        "      logInfo m!\"AUTOFV_DEPS:{name}:"
        "{String.intercalate \",\" dependencies}\"\n"
        "      logInfo m!\"AUTOFV_PROJECT_DEPS:{name}:"
        "{String.intercalate \",\" projectDependencies}\"\n"
        "      for dependency in closure do\n"
        "        if dependency == name || autofvAuditIsProject env dependency then\n"
        "          autofvAuditLogIdentity env dependency\n"
        "  | _ => throwUnsupportedSyntax\n"
    )


def expected_program(project_modules: list[str], bindings: list[str]) -> bytes:
    """Compile controller-owned expected types against pristine project modules."""
    imports = [f"import {_lean_name(module)}" for module in project_modules]
    declarations = [
        line for line in bindings if line.startswith(("axiom ", "def "))
    ]
    _binding_pairs(bindings)
    if not declarations:
        raise contracts.ContractError("kernel audit binding is invalid")
    return ("\n".join([*imports, *declarations, ""])).encode()


def _audit_prelude(
    imports: list[str],
    project_modules: list[str],
    replay_modules: list[str] | None = None,
    *,
    forced_replay: list[str] | None = None,
    permitted_sorry: list[str] | None = None,
    preserved_baseline: bool = False,
    bindings: list[str] | None = None,
) -> str:
    """Build a trusted-only executable that loads candidate constants inertly."""
    imports = [_lean_name(name) for name in imports]
    replay_modules = [_lean_name(name) for name in (replay_modules or [])]
    bindings = bindings or []
    exact_types, defeq_types, exact_values = _binding_pairs(bindings)

    def lean_names(names: list[str]) -> str:
        return ", ".join(f"`{_lean_name(name)}" for name in names)

    def lean_pairs(items: list[tuple[str, str]]) -> str:
        return ", ".join(f"(`{left}, `{right})" for left, right in items)

    source = _trusted_baseline_prelude(
        [],
        project_modules,
        replay_modules,
        forced_replay=forced_replay,
        permitted_sorry=permitted_sorry,
        preserved_baseline=preserved_baseline,
        expected_module=bool(bindings),
    )
    artifact_lines = []
    for module in replay_modules:
        relative = module.replace(".", "/")
        artifact_lines.append(
            f"  artifacts := artifacts.insert `{module} "
            f"(.ofArray #[\".lake/build/lib/lean/{relative}.olean\"])"
        )
    source += (
        f"def autofvAuditCandidateImports : Array Import := "
        f"#[{', '.join(f'{{module := `{name}}}' for name in imports)}]\n"
        "def autofvAuditCandidateArtifacts : IO (NameMap ImportArtifacts) := do\n"
        "  let mut artifacts : NameMap ImportArtifacts := {}\n"
        + "\n".join(artifact_lines)
        + ("\n" if artifact_lines else "")
        + "  return artifacts\n"
        f"def autofvAuditExactTypeBindings : List (Name × Name) := "
        f"[{lean_pairs(exact_types)}]\n"
        f"def autofvAuditDefeqTypeBindings : List (Name × Name) := "
        f"[{lean_pairs(defeq_types)}]\n"
        f"def autofvAuditExactValueBindings : List (Name × Name) := "
        f"[{lean_pairs(exact_values)}]\n"
        "partial def autofvAuditPublicNameFrom (renamed : List Name) "
        "(name : Name) : Name :=\n"
        "  match renamed with\n"
        "  | [] => name\n"
        "  | original :: rest =>\n"
        "      if autofvAuditFreshName original == name then original\n"
        "      else autofvAuditPublicNameFrom rest name\n"
        "def autofvAuditPublicName (renamed : NameSet) (name : Name) : Name :=\n"
        "  autofvAuditPublicNameFrom renamed.toList name\n"
        "def autofvAuditPublicExpr (renamed : NameSet) (expression : Expr) : Expr :=\n"
        "  expression.replace fun subexpression =>\n"
        "    match subexpression with\n"
        "    | .const name levels =>\n"
        "        let publicName := autofvAuditPublicName renamed name\n"
        "        if publicName == name then none else some (.const publicName levels)\n"
        "    | _ => none\n"
        "def autofvAuditActualName (renamed : NameSet) (name : Name) : Name :=\n"
        "  if renamed.contains name then autofvAuditFreshName name else name\n"
        "def autofvAuditValidateBindings (env : Environment) "
        "(renamed : NameSet) : IO Unit := do\n"
        "  let options := ({} : Options).setBool `Elab.async false\n"
        "  let action : CoreM Unit := do\n"
        "    for (expectedName, originalName) in autofvAuditExactTypeBindings do\n"
        "      let actualName := autofvAuditActualName renamed originalName\n"
        "      let some expected := (← getEnv).find? expectedName\n"
        "        | throwError \"expected declaration missing {expectedName}\"\n"
        "      let some actual := (← getEnv).find? actualName\n"
        "        | throwError \"audited declaration missing {originalName}\"\n"
        "      unless autofvAuditRenameExpr renamed expected.type == actual.type do\n"
        "        throwError \"audited declaration type mismatch {originalName}\"\n"
        "    for (expectedName, originalName) in autofvAuditDefeqTypeBindings do\n"
        "      let actualName := autofvAuditActualName renamed originalName\n"
        "      let some expected := (← getEnv).find? expectedName\n"
        "        | throwError \"expected declaration missing {expectedName}\"\n"
        "      let some actual := (← getEnv).find? actualName\n"
        "        | throwError \"audited declaration missing {originalName}\"\n"
        "      let equivalent ← MetaM.run' <| "
        "isDefEq (autofvAuditRenameExpr renamed expected.type) actual.type\n"
        "      unless equivalent do\n"
        "        throwError \"audited declaration type mismatch {originalName}\"\n"
        "    for (expectedName, originalName) in autofvAuditExactValueBindings do\n"
        "      let actualName := autofvAuditActualName renamed originalName\n"
        "      let some expected := (← getEnv).find? expectedName\n"
        "        | throwError \"expected declaration missing {expectedName}\"\n"
        "      let some actual := (← getEnv).find? actualName\n"
        "        | throwError \"audited declaration missing {originalName}\"\n"
        "      let expectedValue := expected.value?.map "
        "(autofvAuditRenameExpr renamed)\n"
        "      unless expectedValue == actual.value? do\n"
        "        throwError \"audited declaration value mismatch {originalName}\"\n"
        "  discard <| Lean.Core.CoreM.toIO action\n"
        "    { fileName := \"<autofv-bindings>\", fileMap := default, "
        "options := options } { env := env }\n"
        "partial def autofvAuditAxioms (env : Environment) (pending : List Name) "
        "(seen axioms : NameSet := {}) : NameSet :=\n"
        "  match pending with\n"
        "  | [] => axioms\n"
        "  | name :: rest =>\n"
        "      if seen.contains name then autofvAuditAxioms env rest seen axioms\n"
        "      else\n"
        "        let seen := seen.insert name\n"
        "        match env.find? name with\n"
        "        | some (.axiomInfo _) => "
        "autofvAuditAxioms env rest seen (axioms.insert name)\n"
        "        | some info =>\n"
        "            let pending := info.getUsedConstantsAsSet.foldl "
        "(fun pending name => name :: pending) rest\n"
        "            autofvAuditAxioms env pending seen axioms\n"
        "        | none => autofvAuditAxioms env rest seen axioms\n"
        "def autofvAuditLogIdentityIO (env : Environment) (renamed : NameSet) "
        "(publicName : Name) : IO Unit := do\n"
        "  let actualName := autofvAuditActualName renamed publicName\n"
        "  let some info := env.find? actualName\n"
        "    | throw <| IO.userError s!\"observed declaration missing {publicName}\"\n"
        "  IO.println s!\"AUTOFV_TYPE_BEGIN:{publicName}\"\n"
        "  IO.println s!\"{repr (autofvAuditPublicExpr renamed info.type)}\"\n"
        "  IO.println s!\"AUTOFV_TYPE_END:{publicName}\"\n"
        "  IO.println s!\"AUTOFV_VALUE_BEGIN:{publicName}\"\n"
        "  IO.println s!\"{repr (info.value?.map (autofvAuditPublicExpr renamed))}\"\n"
        "  IO.println s!\"AUTOFV_VALUE_END:{publicName}\"\n"
        "def autofvAuditObserveIO (source checked : Environment) "
        "(renamed : NameSet) (publicRoot : Name) : IO Unit := do\n"
        "  let actualRoot := autofvAuditActualName renamed publicRoot\n"
        "  unless checked.contains actualRoot do\n"
        "    throw <| IO.userError s!\"observed declaration missing {publicRoot}\"\n"
        "  let closure := autofvAuditCheckedClosure checked [actualRoot]\n"
        "  let checkedDependencies := closure.foldl "
        "(fun names name => names ++ [name.toString]) []\n"
        "  let dependencies := closure.foldl (fun names name => names ++ "
        "[(autofvAuditPublicName renamed name).toString]) []\n"
        "  let projectDependencies := closure.foldl (fun names dependency =>\n"
        "    let publicName := autofvAuditPublicName renamed dependency\n"
        "    if autofvAuditIsProject source publicName then "
        "names ++ [publicName.toString] else names) []\n"
        "  IO.println s!\"AUTOFV_CHECKED_DEPS:{publicRoot}:"
        "{String.intercalate \",\" checkedDependencies}\"\n"
        "  IO.println s!\"AUTOFV_DEPS:{publicRoot}:"
        "{String.intercalate \",\" dependencies}\"\n"
        "  IO.println s!\"AUTOFV_PROJECT_DEPS:{publicRoot}:"
        "{String.intercalate \",\" projectDependencies}\"\n"
        "  for dependency in closure do\n"
        "    let publicName := autofvAuditPublicName renamed dependency\n"
        "    if publicName == publicRoot || autofvAuditIsProject source publicName then\n"
        "      autofvAuditLogIdentityIO checked renamed publicName\n"
        "def autofvAuditPrintAxiomsIO (checked : Environment) "
        "(renamed : NameSet) (publicRoot : Name) : IO Unit := do\n"
        "  let actualRoot := autofvAuditActualName renamed publicRoot\n"
        "  let options := ({} : Options).setBool `Elab.async false\n"
        "  let (axioms, _) ← Lean.Core.CoreM.toIO (collectAxioms actualRoot)\n"
        "    { fileName := \"<autofv-axioms>\", fileMap := default, "
        "options := options } { env := checked }\n"
        "  let names := axioms.toList.map fun name => "
        "(autofvAuditPublicName renamed name).toString\n"
        "  if names.isEmpty then\n"
        "    IO.println s!\"'{publicRoot}' does not depend on any axioms\"\n"
        "  else\n"
        "    IO.println s!\"'{publicRoot}' depends on axioms: "
        "[{String.intercalate \", \" names}]\"\n"
        "def autofvAuditRunIO (observations declarations : List Name) : IO Unit := do\n"
        "  let artifacts ← autofvAuditCandidateArtifacts\n"
        "  let source ← importModules autofvAuditCandidateImports {} 0 "
        "(plugins := #[]) (loadExts := false) (arts := artifacts)\n"
        "  let mut constants : Std.HashMap Name ConstantInfo := {}\n"
        "  let mut roots : List Name := []\n"
        "  for (name, info) in source.constants.toList do\n"
        "    constants := constants.insert name info\n"
        "    if autofvAuditIsTransferred source name then roots := name :: roots\n"
        "  let (checked, renamed) ← autofvAuditReplayConstants constants roots\n"
        "  autofvAuditValidateBindings checked renamed\n"
        "  let replayed := roots.map Name.toString\n"
        "  let checkedNames := roots.foldl (fun names name => if renamed.contains name "
        "then names ++ [name.toString] else names) []\n"
        "  let baselineNames := roots.foldl (fun names name => if renamed.contains name "
        "then names else names ++ [name.toString]) []\n"
        "  IO.println s!\"AUTOFV_REPLAYED:{String.intercalate \",\" replayed}\"\n"
        "  IO.println s!\"AUTOFV_KERNEL_CHECKED:"
        "{String.intercalate \",\" checkedNames}\"\n"
        "  IO.println s!\"AUTOFV_BASELINE_BOUND:"
        "{String.intercalate \",\" baselineNames}\"\n"
        "  for name in observations do autofvAuditObserveIO source checked renamed name\n"
        "  for name in declarations do autofvAuditPrintAxiomsIO checked renamed name\n"
    )
    return source


def audit_program(
    expected: list[dict[str, Any]],
    *,
    bindings: list[str] | None = None,
    project_modules: list[str] | None = None,
    permitted_incomplete_accepted: list[str] | None = None,
) -> bytes:
    permitted = _permitted_incomplete_accepted(
        expected, permitted_incomplete_accepted
    )
    declarations = [_lean_name(record["declaration"]) for record in expected]
    observations = _observation_names(expected)
    return (
        _audit_prelude(
            ["AutoFVReferenceCheck"],
            project_modules or [],
            [*(project_modules or []), "AutoFVReferenceCheck"],
            forced_replay=declarations,
            permitted_sorry=permitted,
            preserved_baseline=bool(project_modules),
            bindings=bindings,
        )
        + f"def main : IO Unit := autofvAuditRunIO "
        f"[{', '.join(f'`{name}' for name in observations)}] "
        f"[{', '.join(f'`{name}' for name in declarations)}]\n"
    ).encode()


def baseline_program(
    state: dict[str, Any], reference: dict[str, Any]
) -> tuple[bytes, list[str]]:
    """Observe every graph-frozen semantic definition in the pristine tree."""
    expected = expected_inventory(state, reference)
    definitions = sorted(
        {
            _lean_name(name)
            for record in expected
            for name in record["dependencies"]
        }
    )
    modules = sorted(
        {
            ".".join(PurePosixPath(source).with_suffix("").parts)
            for source in state["graph"]["source_paths"].values()
        }
    )
    program = _audit_prelude(modules, modules, modules)
    program += (
        f"def main : IO Unit := autofvAuditRunIO "
        f"[{', '.join(f'`{name}' for name in definitions)}] []\n"
    )
    return program.encode(), definitions


def project_modules(state: dict[str, Any]) -> list[str]:
    """Return the exact source-module set that belongs to the audited project."""
    return sorted(
        {
            ".".join(PurePosixPath(source).with_suffix("").parts)
            for source in state.get("graph", {}).get("source_paths", {}).values()
        }
    )


def reference_program(reference: dict[str, Any]) -> bytes:
    """Generate fixed names for every trusted hidden and meaning theorem."""
    leaves = reference.get("leaves")
    if not isinstance(leaves, list) or not leaves:
        raise contracts.ContractError("verifier_reference_leaves_invalid")
    modules: set[str] = set()
    declarations = []
    required = {
        "declaration",
        "spec",
        "source",
        "statement",
        "statement_sha256",
        "proof",
        "proof_sha256",
    }
    for index, leaf in enumerate(leaves):
        if not isinstance(leaf, dict) or set(leaf) != required:
            raise contracts.ContractError("verifier_reference_leaf_invalid")
        declaration, spec = leaf["declaration"], leaf["spec"]
        source, statement, proof = leaf["source"], leaf["statement"], leaf["proof"]
        path = PurePosixPath(source) if isinstance(source, str) else PurePosixPath()
        safe_path = bool(
            source
            and isinstance(source, str)
            and not path.is_absolute()
            and "\\" not in source
            and path.as_posix() == source
            and all(part not in {"", ".", ".."} for part in path.parts)
        )
        if (
            not all(
                isinstance(item, str) and item
                for item in (declaration, spec, source, statement, proof)
            )
            or _sha(statement.encode()) != leaf["statement_sha256"]
            or _sha(proof.encode()) != leaf["proof_sha256"]
            or declaration not in statement
            or re.fullmatch(r"\s*(?:True|False)\s*", statement)
            or not safe_path
            or path.suffix != ".lean"
        ):
            raise contracts.ContractError("verifier_reference_meaning_invalid")
        modules.add(".".join(path.with_suffix("").parts))
        declarations.extend(
            (
                f"def meaning_{index} : Prop := {statement}",
                f"#check ({spec} : {statement})",
                f"theorem hidden_{index} : {statement} := {proof}",
            )
        )
    imports = [f"import {module}" for module in sorted(modules)]
    return (
        "\n".join(
            (*imports, "namespace AutoFVVerifier", *declarations, "end AutoFVVerifier", "")
        )
    ).encode()


def counterexample_audit_program(
    *,
    module: str,
    theorem: str,
    proposition: str,
    baseline_modules: list[str] | None = None,
) -> bytes:
    """Generate a fresh replay plus axiom audit for one witness theorem."""
    _lean_name(module)
    _lean_name(theorem)
    if not isinstance(proposition, str) or not proposition.strip():
        raise contracts.ContractError("counterexample proposition is invalid")
    bindings = [
        f"axiom AutoFVExpectedCounterexample : {proposition}",
        f"#autofv_same_type AutoFVExpectedCounterexample {theorem}",
    ]
    return (
        _audit_prelude(
            [module],
            sorted({_lean_name(name) for name in baseline_modules or []}),
            [module],
            forced_replay=[theorem],
            bindings=bindings,
        )
        + f"def main : IO Unit := autofvAuditRunIO [] [`{theorem}]\n"
    ).encode()
