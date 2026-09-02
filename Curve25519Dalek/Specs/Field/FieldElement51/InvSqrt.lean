




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Field.FieldElement51.SqrtRatioi
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ONE
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.SQRT_M1

















open Aeneas Aeneas.Std Aeneas.Std.WP Result
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.backend.serial.u64.constants
namespace curve25519_dalek.field.FieldElement51





































@[progress]
theorem invsqrt_spec
    (v : backend.serial.u64.field.FieldElement51)
    (h_v_bounds : ∀ i, i < 5 → (v[i]!).val ≤ 2 ^ 52 - 1) :
    invsqrt v ⦃ res =>
    let v_nat := Field51_as_Nat v % p
    let r_nat := Field51_as_Nat res.snd % p
    let i_nat := Field51_as_Nat SQRT_M1_val % p

    (∀ i < 5, res.snd[i]!.val ≤ 2 ^ 53 - 1) ∧

    (r_nat % 2 = 0) ∧

    (v_nat = 0 → res.fst.val = 0#u8 ∧ r_nat = 0) ∧

    (v_nat ≠ 0 ∧ (∃ x : Nat, (x ^ 2 * v_nat) % p = 1) →
      res.fst.val = 1#u8 ∧ (r_nat ^ 2 * v_nat) % p = 1) ∧

    (v_nat ≠ 0 ∧ ¬(∃ x : Nat, (x ^ 2 * v_nat) % p = 1) →
      res.fst.val = 0#u8 ∧ (r_nat ^ 2 * v_nat) % p = i_nat) ⦄ := by
  sorry
end curve25519_dalek.field.FieldElement51
