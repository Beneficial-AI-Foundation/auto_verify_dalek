




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux

open Aeneas Aeneas.Std Result Aeneas.Std.WP













namespace curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU8























@[progress]
theorem from_spec (x : Std.U8) :
    «from» x ⦃ result =>
    U8x32_as_Nat result.bytes = x.val ⦄ := by
  sorry
end curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU8
