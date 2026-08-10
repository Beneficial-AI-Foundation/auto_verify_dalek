/-
Phase 0 trust-base audit (plan.md §4).

Run: lake env lean harness/phase0_audit.lean

Emits line-oriented records for post-processing:
  EXTAX <name>              axiom declared in FunsExternal/TypesExternal
  PKGAXIOM <module> <name>  axiom declared elsewhere in Curve25519Dalek.* (must be empty)
  SRCSORRY <module> <name>  Math decl whose own body mentions sorryAx (the assumptions)
  SORRYUSER <name>          Math decl whose axiom closure contains sorryAx (inherited ok)
  VIOLATION <name> <axiom>  Math decl depending on an axiom outside the whitelist
  EXTVERIFIED <name>        Math decl tagged @[externally_verified]
  TYPE <name> ⊢ <type>      statement of each SRCSORRY decl (single line)
-/
import Curve25519Dalek

open Lean

def base3 : List Name := [``propext, ``Classical.choice, ``Quot.sound]

def oneLine (s : String) : String :=
  (s.replace "\n" " ").replace "  " " "

#eval show CoreM Unit from do
  let env ← getEnv
  let mods := env.header.moduleNames.zip env.header.moduleData
  -- enumerate external trust-base axioms
  let mut extAx : NameSet := {}
  for (mName, mData) in mods do
    if mName == `Curve25519Dalek.FunsExternal || mName == `Curve25519Dalek.TypesExternal then
      for c in mData.constNames do
        if let some (.axiomInfo _) := env.find? c then
          extAx := extAx.insert c
          IO.println s!"EXTAX {c}"
  -- axioms declared anywhere else in the package
  for (mName, mData) in mods do
    if (`Curve25519Dalek).isPrefixOf mName
        && mName != `Curve25519Dalek.FunsExternal
        && mName != `Curve25519Dalek.TypesExternal then
      for c in mData.constNames do
        if let some (.axiomInfo _) := env.find? c then
          IO.println s!"PKGAXIOM {mName} {c}"
  -- audit every Math declaration
  let whitelist : NameSet := base3.foldl (·.insert ·) (extAx.insert ``sorryAx)
  let mut srcSorry : Array (Name × Name) := #[]
  for (mName, mData) in mods do
    if (`Curve25519Dalek.Math).isPrefixOf mName then
      for c in mData.constNames do
        let some ci := env.find? c | continue
        -- source assumptions: sorryAx appears in the decl's own body
        if let some v := ci.value? then
          if v.getUsedConstants.contains ``sorryAx then
            srcSorry := srcSorry.push (mName, c)
            IO.println s!"SRCSORRY {mName} {c}"
        let axs ← collectAxioms c
        if axs.contains ``sorryAx then
          IO.println s!"SORRYUSER {c}"
        for a in axs do
          if !whitelist.contains a then
            IO.println s!"VIOLATION {c} {a}"
        if externallyVerifiedAttr.hasTag env c then
          IO.println s!"EXTVERIFIED {c}"
  -- statements of the assumptions
  for (_, c) in srcSorry do
    let some ci := env.find? c | continue
    let fmt ← Meta.MetaM.run' (Meta.ppExpr ci.type)
    IO.println s!"TYPE {c} ⊢ {oneLine (toString fmt)}"
  IO.println "AUDIT DONE"
