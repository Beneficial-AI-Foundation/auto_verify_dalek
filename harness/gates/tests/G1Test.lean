/- G1 v2 / N1 test fixture — statements only, every proof is `sorry`.
Compiled to .olean by test_g1.py and imported by StmtCanon (module `G1Test`
is treated as agent territory: its defs get δ-unfolded).

Expected verdicts (asserted by test_g1.py against the real baselines):
  zero_copy        canon == ZERO_spec      (verbatim restatement)
  invert_renamed   canon == invert_spec    (α-renamed binders)
  zero_alias       canon == ZERO_spec      (helper-def aliasing, unfolded)
  zero_weak        canon != ZERO_spec      (genuinely weaker statement)
  zero_instattack  canon != ZERO_spec      (local OfNat instance swap: the
                                            pretty-printed statement is
                                            byte-identical to the original,
                                            only elaboration differs — the
                                            attack G1 v1 pp-comparison misses)
  zero_vocab_bad   N1 violation            (mentions impl fn `to_bytes`,
                                            target is `ZERO`)
-/
import Curve25519Dalek

open Aeneas Aeneas.Std Aeneas.Std.WP Result

namespace curve25519_dalek.scalar.Scalar

theorem zero_copy : U8x32_as_Nat ZERO.bytes = 0 := sorry

theorem invert_renamed (s : Scalar) (hyp : U8x32_as_Nat s.bytes % L ≠ 0) :
    invert s ⦃ (r : Scalar) =>
      U8x32_as_Nat s.bytes * U8x32_as_Nat r.bytes ≡ 1 [MOD L] ⦄ := sorry

def myNat (s : Scalar) : Nat := U8x32_as_Nat s.bytes

theorem zero_alias : myNat ZERO = 0 := sorry

theorem zero_weak : U8x32_as_Nat ZERO.bytes % L = 0 := sorry

section InstAttack
local instance (priority := high) : OfNat Nat 0 := ⟨1⟩
theorem zero_instattack : U8x32_as_Nat ZERO.bytes = 0 := sorry
end InstAttack

theorem zero_vocab_bad :
    ∀ s : Scalar, to_bytes s ⦃ _r => U8x32_as_Nat ZERO.bytes = 0 ⦄ := sorry

end curve25519_dalek.scalar.Scalar
