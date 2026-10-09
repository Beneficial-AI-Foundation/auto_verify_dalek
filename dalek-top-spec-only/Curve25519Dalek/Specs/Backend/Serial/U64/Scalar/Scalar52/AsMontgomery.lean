import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryMul
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.RR

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- `L` is odd, hence coprime to the Montgomery radix `R = 2^260`. -/
theorem L_coprime_R : Nat.Coprime _root_.L (2 ^ 260) := by
  unfold _root_.L
  norm_num

/-- Conversion into Montgomery form: for an input with 52-bit limbs, the result has
52-bit limbs, is canonical (`< L`) and satisfies `r ≡ a * 2^260 [MOD L]`. -/
@[progress]
theorem as_montgomery_spec (a : Scalar52)
    (ha : ∀ i, i < 5 → (a.val[i]!).val < 2 ^ 52) :
    as_montgomery a ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r ≡ Scalar52_as_Nat a * 2 ^ 260 [MOD _root_.L] ∧
      Scalar52_as_Nat r < _root_.L ⦄ := by
  unfold as_montgomery
  have hRR : ∀ i, i < 5 → (constants.RR.val[i]!).val < 2 ^ 52 := fun i hi =>
    by simpa [Array.getElem!_Nat_eq] using constants.RR_bounds i hi
  apply WP.spec_mono (montgomery_mul_spec_right_lt a constants.RR ha hRR constants.RR_lt_L)
  rintro r ⟨hr, hmod, hlt⟩
  refine ⟨hr, ?_, hlt⟩
  have h1 : Scalar52_as_Nat r * 2 ^ 260 ≡ (Scalar52_as_Nat a * 2 ^ 260) * 2 ^ 260
      [MOD _root_.L] := by
    refine hmod.trans ?_
    rw [mul_assoc, ← pow_two]
    exact Nat.ModEq.mul_left _ constants.RR_mod
  exact Nat.ModEq.cancel_right_of_coprime L_coprime_R h1

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
