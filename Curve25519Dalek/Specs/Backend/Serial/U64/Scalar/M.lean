import Curve25519Dalek.Funs






open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek
open backend.serial.u64.scalar

attribute [-simp] Int.reducePow Nat.reducePow



namespace curve25519_dalek.backend.serial.u64.scalar



@[progress]
theorem m_spec (x y : U64) :
    m x y ⦃ (result : U128) => result.val = x.val * y.val ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.scalar
