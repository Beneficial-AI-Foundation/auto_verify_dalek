/- StmtCanon — G1 v2 statement-identity fingerprint + N1 vocabulary audit.

For each declaration name given on the command line, emit one JSON line:

  { "name":   <fully qualified decl name>,
    "found":  bool,
    "canon":  canonical α-invariant dump of the NORMALIZED statement,
    "pp":     pretty-printed statement (display only, canon is authoritative),
    "consts": [ {"name": .., "module": ..}, .. ]   -- used constants, post-normalization
    "error":  present only on failure }

Normalization (plan.md §6 G1 v2): starting from ConstantInfo.type (fully
elaborated, instances resolved), δ-unfold every constant defined in a
`Curve25519Dalek.Specs.*` module or in no module (script-local) — i.e. any
definition an agent could have introduced — until only frozen vocabulary
(Funs/Types/Math/Aux/Mathlib/Aeneas/core) remains, then β-reduce.  The canon
dump ignores binder names (de Bruijn indices make it α-invariant) and mdata,
so pretty-print-level games cannot make two different propositions collide,
and helper-definition aliasing cannot make equal propositions differ.

Usage (needs the package's LEAN_PATH, so always via `lake env`):

  lake env lean --run harness/gates/StmtCanon.lean [--import M1,M2] decl1 decl2 ..
  lake env lean --run harness/gates/StmtCanon.lean --module M1,M2

`--module` (G1 phase-1 gate, DEC-10 "unchanged supplied statements") audits
every user-facing constant declared in the listed modules (internal/auxiliary
names — `_private` mangling kept, `proof_N`/`match_N`/`eq_N`/instance
auxiliaries dropped) and adds "kind" (theorem/definition/opaque/axiom/...)
and "module" to each record. The driver fingerprints a target module before
the agent runs and after `lake build` passes; any baseline name that is
missing or whose (kind, canon) changed is `rejected_statement_changed`.
Added names are allowed.

Default import root: Curve25519Dalek (which imports all Specs modules).
Extra --import modules are for test fixtures compiled to .olean on LEAN_PATH.
-/
import Lean
open Lean Meta

/-- Modules whose definitions are AGENT territory: unfold them.
    Everything else is frozen vocabulary: keep. -/
def agentTerritory (env : Environment) (n : Name) : Bool :=
  match env.getModuleIdxFor? n with
  | some idx =>
    let mod := env.header.moduleNames[idx.toNat]!
    (`Curve25519Dalek.Specs).isPrefixOf mod || (`G1Test).isPrefixOf mod
  | none => true

def moduleOf (env : Environment) (n : Name) : String :=
  match env.getModuleIdxFor? n with
  | some idx => toString env.header.moduleNames[idx.toNat]!
  | none => "<local>"

/-- δ-unfold agent-territory definitions, then β-reduce. -/
def normalize (e : Expr) : MetaM Expr := do
  let e ← Meta.transform e (pre := fun e => do
    if let .const n _ := e.getAppFn then
      if agentTerritory (← getEnv) n then
        if let some e' ← unfoldDefinition? e then
          return .visit e'
    return .continue)
  Meta.transform e (pre := fun e =>
    if e.isHeadBetaTarget then return .visit e.headBeta
    else return .continue)

/-- Canonical dump: α-invariant (binder names dropped), mdata-transparent. -/
partial def canon : Expr → String
  | .bvar i        => s!"(b{i})"
  | .fvar id       => s!"(fv {id.name})"
  | .mvar id       => s!"(mv {id.name})"
  | .sort u        => s!"(s {u})"
  | .const n us    => s!"(c {n} {us})"
  | .app f a       => s!"(a {canon f} {canon a})"
  | .lam _ t b _   => s!"(l {canon t} {canon b})"
  | .forallE _ t b _ => s!"(p {canon t} {canon b})"
  | .letE _ t v b _  => s!"(z {canon t} {canon v} {canon b})"
  | .lit (.natVal v) => s!"(ln {v})"
  | .lit (.strVal v) => s!"(ls {v})"
  | .mdata _ b     => canon b
  | .proj s i b    => s!"(j {s} {i} {canon b})"

def kindOf : ConstantInfo → String
  | .axiomInfo _  => "axiom"
  | .defnInfo _   => "definition"
  | .thmInfo _    => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _   => "quot"
  | .inductInfo _ => "inductive"
  | .ctorInfo _   => "constructor"
  | .recInfo _    => "recursor"

def auditDecl (declName : Name) : MetaM Json := do
  let env ← getEnv
  match env.find? declName with
  | none => return Json.mkObj [("name", toString declName), ("found", false)]
  | some ci =>
    let ty ← normalize ci.type
    let pp ← ppExpr ci.type
    let consts := ty.getUsedConstants.toList.eraseDups.map fun c =>
      Json.mkObj [("name", toString c), ("module", moduleOf env c)]
    return Json.mkObj [
      ("name", toString declName), ("found", true),
      ("kind", kindOf ci), ("module", moduleOf env declName),
      ("canon", canon ty), ("pp", toString pp),
      ("consts", Json.arr consts.toArray)]

/-- Auxiliary constants whose existence/statement legitimately changes when
    only a PROOF changes: `foo.proof_1`, `foo.match_1`, `foo.eq_1`,
    `foo._cstage`, structural-recursion helpers, etc. Private user
    declarations (`_private.M.0.foo`) are kept: their statements are part of
    the supplied file. -/
def isAuxiliary (n : Name) : Bool :=
  let user := (privateToUserName? n).getD n
  user.isInternalDetail || user.isInaccessibleUserName ||
  user.components.any fun c =>
    let s := c.toString
    s.startsWith "proof_" || s.startsWith "match_" || s.startsWith "eq_" ||
    s.startsWith "_" || s == "below" || s == "brecOn" || s == "binductionOn" ||
    s == "noConfusion" || s == "noConfusionType" || s == "casesOn" ||
    s == "recOn" || s == "rec" || s == "ibelow" || s == "sizeOf_spec" ||
    s.startsWith "injEq" || s.startsWith "inj" || s.startsWith "sizeOf"

/-- All non-auxiliary constants declared in `mod`, in declaration order. -/
def moduleDecls (env : Environment) (mod : Name) : Array Name :=
  match env.getModuleIdx? mod with
  | none => #[]
  | some idx =>
    (env.header.moduleData[idx.toNat]!.constNames.filter fun n => !isAuxiliary n)

unsafe def main (args : List String) : IO Unit := do
  initSearchPath (← findSysroot)
  let mut imports : Array Name := #[`Curve25519Dalek]
  let mut decls : Array Name := #[]
  let mut modules : Array Name := #[]
  let mut i := 0
  let argsArr := args.toArray
  while h : i < argsArr.size do
    let a := argsArr[i]
    if a == "--import" then
      if h2 : i + 1 < argsArr.size then
        imports := imports ++ (argsArr[i+1].splitOn ",").toArray.map String.toName
        i := i + 2
      else
        throw <| IO.userError "--import needs an argument"
    else if a == "--module" then
      if h2 : i + 1 < argsArr.size then
        modules := modules ++ (argsArr[i+1].splitOn ",").toArray.map String.toName
        i := i + 2
      else
        throw <| IO.userError "--module needs an argument"
    else
      decls := decls.push a.toName
      i := i + 1
  let env ← importModules (imports.map fun m => {module := m}) {} (trustLevel := 1024)
  let ctx : Core.Context := { fileName := "<StmtCanon>", fileMap := default,
                              maxHeartbeats := 0 }
  let st : Core.State := { env }
  for m in modules do
    if env.getModuleIdx? m |>.isNone then
      throw <| IO.userError s!"--module {m}: not in the imported environment"
    decls := decls ++ moduleDecls env m
  let act : CoreM Unit := do
    for d in decls do
      let j ← try
        MetaM.run' (auditDecl d)
      catch ex =>
        pure <| Json.mkObj [("name", toString d), ("found", true),
                            ("error", toString (← ex.toMessageData.toString))]
      IO.println j.compress
  let _ ← act.toIO ctx st
  pure ()
