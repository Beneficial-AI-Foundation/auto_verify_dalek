




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic









open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.backend.serial.u64.constants














def SQRT_M1_raw : backend.serial.u64.field.FieldElement51 :=
  Array.make 5#usize [1718705420411056#u64, 234908883556509#u64, 2233514472574048#u64,
    2117202627021982#u64, 765476049583133#u64]





@[progress]
theorem SQRT_M1_spec :
    SQRT_M1 ⦃ result =>
    result = SQRT_M1_raw ∧
    (Field51_as_Nat result)^2 % p = p - 1 ∧
    (∀ i < 5, result[i]!.val < 2^51) ⦄ := by
  sorry
end curve25519_dalek.backend.serial.u64.constants
