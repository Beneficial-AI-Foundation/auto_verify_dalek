




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic










open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants















def SQRT_AD_MINUS_ONE_raw : backend.serial.u64.field.FieldElement51 :=
  Array.make 5#usize [2241493124984347#u64, 425987919032274#u64, 2207028919301688#u64,
    1220490630685848#u64, 974799131293748#u64]





@[progress]
theorem SQRT_AD_MINUS_ONE_spec :
    SQRT_AD_MINUS_ONE ⦃ result =>
    (Field51_as_Nat result)^2 % p = (a * d - 1) % p ∧
    (∀ i < 5, result[i]!.val < 2^51) ∧
    result = SQRT_AD_MINUS_ONE_raw ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
