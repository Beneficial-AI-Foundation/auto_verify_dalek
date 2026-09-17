/-
Exact dependency closure of the bundle's non-Math declarations into Math/.

Run inside a *built* bundle:
    lake env lean ../harness/math_closure.lean > math_closure.tsv

Roots: every constant whose module is `Curve25519Dalek.*` but not
`Curve25519Dalek.Math.*` (Specs statements -- proofs are `sorry` --, Aux,
TypesAux, Funs, ...).  Edges: constants used in type and value (this includes
the `_proof_N` auxiliaries of definitions, which probe-lean does not record).
Output: one `name<TAB>module` line per reached constant living in a Math module.
-/
import Curve25519Dalek
open Lean

def isMath (m : Name) : Bool := (`Curve25519Dalek.Math).isPrefixOf m
def isPkg (m : Name) : Bool := (`Curve25519Dalek).isPrefixOf m

#eval show CoreM Unit from do
  let env ← getEnv
  let modOf (n : Name) : Option Name := env.getModuleIdxFor? n |>.map fun i => env.header.moduleNames[i.toNat]!
  let mut roots : Array Name := #[]
  for (n, _) in env.constants.map₁.toList do
    if let some m := modOf n then
      if isPkg m && !isMath m then roots := roots.push n
  let mut seen : NameSet := {}
  let mut stack := roots.toList
  for r in roots do seen := seen.insert r
  while true do
    match stack with
    | [] => break
    | n :: rest =>
      stack := rest
      if let some ci := env.find? n then
        for d in ci.getUsedConstantsAsSet.toList do
          if !seen.contains d then
            seen := seen.insert d
            stack := d :: stack
  let mut out : Array String := #[]
  for n in seen.toList do
    if let some m := modOf n then
      if isMath m then out := out.push s!"{n}\t{m}"
  IO.println (String.intercalate "\n" (out.qsort (· < ·)).toList)
