




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Montgomery.Curve
import Curve25519Dalek.Math.Edwards.Representation
import Curve25519Dalek.Specs.Field.FieldElement51.Invert
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Constants.EDWARDS_D2
import Curve25519Dalek.Aux


























open Aeneas Aeneas.Std Result Aeneas.Std.WP curve25519_dalek.backend.serial.u64.field.FieldElement51
  curve25519_dalek.backend.serial.u64.constants
open curve25519_dalek.backend.serial.curve_models.AffineNielsPoint
open curve25519_dalek.montgomery
namespace curve25519_dalek.edwards.EdwardsPoint



























private lemma field51_modP_ne_zero_of_toField_ne_zero
    (fe : backend.serial.u64.field.FieldElement51)
    (h : fe.toField ≠ 0) :
    Field51_as_Nat fe % p ≠ 0 := by
  intro hmod
  apply h
  unfold curve25519_dalek.backend.serial.u64.field.FieldElement51.toField
  exact Edwards.lift_mod_eq (Field51_as_Nat fe) 0 (by simpa [Nat.zero_mod] using hmod)







private lemma ypx_mod_arith (ypx_nat y_nat x_nat Z_nat X_nat Y_nat : ℕ)
    (h_ypx : ypx_nat = y_nat + x_nat)
    (h_yZ : y_nat * Z_nat ≡ Y_nat [MOD p])
    (h_xZ : x_nat * Z_nat ≡ X_nat [MOD p]) :
    ypx_nat * Z_nat ≡ Y_nat + X_nat [MOD p] := by
  rw [h_ypx, add_mul]
  exact Nat.ModEq.add h_yZ h_xZ



private lemma ymx_mod_arith (ymx_nat x_nat y_nat Z_nat X_nat Y_nat : ℕ)
    (h_ymx : ymx_nat + x_nat ≡ y_nat [MOD p])
    (h_xZ : x_nat * Z_nat ≡ X_nat [MOD p])
    (h_yZ : y_nat * Z_nat ≡ Y_nat [MOD p]) :
    ymx_nat * Z_nat + X_nat ≡ Y_nat [MOD p] := by
  have h_sum_Z := Nat.ModEq.mul_right Z_nat h_ymx
  rw [add_mul] at h_sum_Z
  calc ymx_nat * Z_nat + X_nat
      ≡ ymx_nat * Z_nat + x_nat * Z_nat [MOD p] :=
        Nat.ModEq.add_left _ (Nat.ModEq.symm h_xZ)
    _ ≡ y_nat * Z_nat [MOD p] := h_sum_Z
    _ ≡ Y_nat [MOD p] := h_yZ



private lemma xy2d_mod_arith (xy2d_nat fe_nat d2_nat x_nat y_nat Z_nat X_nat Y_nat : ℕ)
    (h_xy2d : xy2d_nat ≡ fe_nat * d2_nat [MOD p])
    (h_fe : fe_nat ≡ x_nat * y_nat [MOD p])
    (h_d2 : d2_nat ≡ 2 * d [MOD p])
    (h_xZ : x_nat * Z_nat ≡ X_nat [MOD p])
    (h_yZ : y_nat * Z_nat ≡ Y_nat [MOD p]) :
    xy2d_nat * Z_nat * Z_nat ≡ X_nat * Y_nat * (2 * d) [MOD p] := by
  have h_step1 : xy2d_nat ≡ x_nat * y_nat * (2 * d) [MOD p] := by
    calc xy2d_nat
        ≡ fe_nat * d2_nat [MOD p] := h_xy2d
      _ ≡ (x_nat * y_nat) * d2_nat [MOD p] := Nat.ModEq.mul_right _ h_fe
      _ ≡ (x_nat * y_nat) * (2 * d) [MOD p] := Nat.ModEq.mul_left _ h_d2
  calc xy2d_nat * Z_nat * Z_nat
      ≡ x_nat * y_nat * (2 * d) * Z_nat * Z_nat [MOD p] :=
        Nat.ModEq.mul_right _ (Nat.ModEq.mul_right _ h_step1)
    _ = (x_nat * Z_nat) * (y_nat * Z_nat) * (2 * d) := by ring
    _ ≡ X_nat * Y_nat * (2 * d) [MOD p] :=
        Nat.ModEq.mul_right _ (Nat.ModEq.mul h_xZ h_yZ)



























@[progress]
theorem as_affine_niels_spec
  (self : EdwardsPoint)
  (hself : self.IsValid) :
  as_affine_niels self ⦃ an =>
  let X := Field51_as_Nat self.X
  let Y := Field51_as_Nat self.Y
  let Z := Field51_as_Nat self.Z
  let ypx := Field51_as_Nat an.y_plus_x
  let ymx := Field51_as_Nat an.y_minus_x
  let xy2d_val := Field51_as_Nat an.xy2d
  (ypx * Z) % p = (Y + X) % p ∧
  (ymx * Z + X) % p = Y % p ∧
  (xy2d_val * Z * Z) % p = (X * Y * (2 * d)) % p ∧
  (∀ i < 5, an.y_plus_x[i]!.val < 2 ^ 54) ∧
  (∀ i < 5, an.y_minus_x[i]!.val < 2 ^ 52) ∧
  (∀ i < 5, an.xy2d[i]!.val < 2 ^ 52) ⦄
:= by
  sorry
end curve25519_dalek.edwards.EdwardsPoint
