# Minimal Math/ subset of the bundle

`dalek-top-spec-only/Curve25519Dalek/Math/` contains only the Math declarations
the bundle needs to compile. Everything else from the repo's `Math/` is cut.
This page explains how that subset is computed.

## Idea

Reachability over the dependency graph.

- **Roots**: every declaration in the bundle outside `Math/` -- the top-level
  spec theorems (proofs are `sorry`, so only their *statements* count), `Aux`,
  `TypesAux`, `Funs`, ...
- **Edges**: "declaration A uses constant B".
- **Keep**: every `Math/` declaration reachable from a root. Nothing is kept
  for its own sake.

## Where the edges come from

Two sources, merged:

1. **Exact kernel closure** -- `harness/math_closure.lean`, run inside a built
   bundle:
   ```
   cd dalek-top-spec-only
   lake env lean ../harness/math_closure.lean > ../.verilib/math_closure.tsv
   ```
   For each constant it takes `getUsedConstantsAsSet` (all constants in type
   and value) and walks to a fixpoint. This sees the `_proof_N` auxiliaries
   of definitions, which source-level tools miss.
2. **probe-lean graph** -- `.verilib/probes/lean_bundle_Curve25519Dalek_0.1.0.json`,
   a source-level extract of a previously built bundle with the same Specs
   selection. Used to map kernel names back to source declarations and as a
   second set of edges.

Kernel names such as `foo._proof_3`, `Point.rec`, `foo.match_1`,
`_private.Mod.0.x` are mapped to the longest prefix the probe knows.

## Cutting

`harness/build_without_internal_spec.py --minimize-math PROBE --math-closure TSV`
(class `MathMin`):

- A `Math/` declaration not in the closure is removed together with its
  docstring, attributes and `... in` prefixes.
- A `Math/` file left with no declarations is dropped; imports of it are
  replaced by its own imports; vanished namespaces are removed from `open`
  lines.
- Sorry-assumptions listed in `harness/frozen/math_assumptions.json` get no
  special treatment: unused ones are cut too (`--keep-math-assumptions`
  keeps them).
- `--math-keep NAME,...` force-keeps declarations the graph cannot see
  (simp sets, notation, `deriving`).

## Checking

`lake build` of the result is the final arbiter. If it fails on a missing
Math name, add it with `--math-keep` and rebuild.

## Current result

447 Math declarations, 128 kept, 319 removed. Modules `BitList`,
`Edwards.EightTorsion`, `PrimeCerts` dropped entirely. Four sorry-assumptions
remain necessary: `Edwards.complete_addition_denominators_ne_zero`,
`curve25519_dalek.math.elligator_ristretto_flavor_pure`,
`curve25519_dalek.math.inv_sqrt_checked_spec`,
`curve25519_dalek.math.sqrt_checked_spec`.

Full per-file table and the list of kept declarations:
`.verilib/math_min_subset.md`. Machine-readable: `.verilib/math_min_subset.json`
and the `math_minimized` section of `dalek-top-spec-only/bundle_manifest.json`.
