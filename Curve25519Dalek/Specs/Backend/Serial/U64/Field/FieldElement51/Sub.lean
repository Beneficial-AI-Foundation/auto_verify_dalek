




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Mathlib.Data.Nat.ModEq












open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51
open backend.serial.u64.field

















set_option maxRecDepth 4096 in


















@[progress]
theorem sub_spec (a b : Array U64 5#usize)
    (ha : ∀ i < 5, a[i]!.val < 2 ^ 63) (hb : ∀ i < 5, b[i]!.val < 2 ^ 54) :
    sub a b ⦃ (d : FieldElement51) =>
      (∀ i < 5, d[i]!.val < 2 ^ 52) ∧
      (Field51_as_Nat d + Field51_as_Nat b) % p = Field51_as_Nat a % p ⦄ := by
  sorry
end curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51
