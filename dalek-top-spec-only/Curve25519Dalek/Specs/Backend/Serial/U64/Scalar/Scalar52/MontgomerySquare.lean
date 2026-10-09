import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.SquareInternal
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- Montgomery squaring: for an input with 52-bit limbs whose square is below
`2^260 * L` (e.g. when the input is below `L`), the result has 52-bit limbs, is
canonical (`< L`) and satisfies `r * 2^260 ≡ a * a [MOD L]`. -/
@[progress]
theorem montgomery_square_spec (a : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 52)
    (haa : Scalar52_as_Nat a * Scalar52_as_Nat a < 2 ^ 260 * _root_.L) :
    montgomery_square a ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r * 2 ^ 260 ≡ Scalar52_as_Nat a * Scalar52_as_Nat a [MOD _root_.L] ∧
      Scalar52_as_Nat r < _root_.L ⦄ := by
  unfold montgomery_square
  have ha' : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 62 := fun i hi =>
    lt_of_lt_of_le (ha i hi) (by norm_num)
  progress as ⟨t, ht, _, ht107⟩
  have hl : ∀ i, i < 9 → (t.val[i]!).val < 2 ^ 126 := fun i hi =>
    lt_of_lt_of_le (ht107 ha i hi) (by norm_num)
  progress as ⟨r, hr, hmod, hlt⟩
  rw [ht] at hmod
  exact ⟨hr, hmod, hlt⟩

/-- Convenience variant: if `a` is canonical (`< L`), the square bound holds automatically. -/
theorem montgomery_square_spec_lt (a : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 52)
    (haL : Scalar52_as_Nat a < _root_.L) :
    montgomery_square a ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r * 2 ^ 260 ≡ Scalar52_as_Nat a * Scalar52_as_Nat a [MOD _root_.L] ∧
      Scalar52_as_Nat r < _root_.L ⦄ := by
  apply montgomery_square_spec a ha
  have := montgomery_reduce.mr_as_Nat_lt a ha
  calc Scalar52_as_Nat a * Scalar52_as_Nat a ≤ Scalar52_as_Nat a * _root_.L :=
        Nat.mul_le_mul_left _ haL.le
    _ < 2 ^ 260 * _root_.L := Nat.mul_lt_mul_of_pos_right this (by unfold _root_.L; norm_num)

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
