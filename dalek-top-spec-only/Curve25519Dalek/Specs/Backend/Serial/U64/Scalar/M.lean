import Curve25519Dalek.Funs

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek
open backend.serial.u64.scalar

attribute [-simp] Int.reducePow Nat.reducePow

namespace curve25519_dalek.backend.serial.u64.scalar

/-- `m x y` computes the full 128-bit product of two `u64` values; it never overflows. -/
@[progress]
theorem m_spec (x y : U64) :
    m x y ⦃ r => r.val = x.val * y.val ⦄ := by
  unfold m
  have hx := x.hBounds
  have hy := y.hBounds
  progress as ⟨ a, ha ⟩
  progress as ⟨ b, hb ⟩
  progress as ⟨ c, hc ⟩
  simp only [ha, hb, UScalar.cast_val_eq, UScalarTy.numBits] at *
  have : x.val * y.val < 2 ^ 64 * 2 ^ 64 := Nat.mul_lt_mul'' hx hy
  have hx2 : x.val % 2 ^ 128 = x.val := Nat.mod_eq_of_lt (by omega)
  have hy2 : y.val % 2 ^ 128 = y.val := Nat.mod_eq_of_lt (by omega)
  simp only [hx2, hy2] at *
  scalar_tac

end curve25519_dalek.backend.serial.u64.scalar
