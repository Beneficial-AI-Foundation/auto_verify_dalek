




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryReduce








open Aeneas Aeneas.Std Aeneas.Std.WP Result
namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52















theorem set_getElem!_eq (l : List U128) (a : U128) (i : ℕ) (h : i < l.length) :
    (l.set i (a))[i]! = a := by
  sorry

theorem zero_array (i : ℕ) (hi : i < 9) :
    ((Array.repeat 9#usize 0#u128) : List U128)[i]!.val = 0 := by
  sorry






@[progress]
theorem from_montgomery_loop_spec (self : Scalar52) (limbs : Array U128 9#usize) (i : Usize)
    (hi : i.val ≤ 5) :
    from_montgomery_loop self limbs i ⦃ (result : Std.Array U128 9#usize) =>
      (∀ j < 5, i.val ≤ j → result[j]! = UScalar.cast .U128 self[j]!) ∧
      (∀ j < 9, 5 ≤ j → result[j]! = limbs[j]!) ∧
      (∀ j < i.val, result[j]! = limbs[j]!) ⦄ := by
  sorry


@[progress]
theorem from_montgomery_spec (self : Scalar52) (h_bounds : ∀ i < 5, self[i]!.val < 2 ^ 62) :
    from_montgomery self ⦃ (result : Scalar52) =>
      (Scalar52_as_Nat result * R) % L = Scalar52_as_Nat self % L ∧
      Scalar52_as_Nat result < L ∧ ∀ i < 5, result[i]!.val < 2 ^ 52 ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar.Scalar52
