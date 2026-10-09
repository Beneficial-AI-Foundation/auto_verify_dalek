import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.ToBytes

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.scalar.Scalar52

/-- `pack` serialises a `Scalar52` with 52-bit limbs into a `Scalar`; the byte value is the
limb value modulo `2^256` (exactly the limb value when that is below `2^256`, e.g. `< L`). -/
@[progress]
theorem pack_spec (self : backend.serial.u64.scalar.Scalar52)
    (h : ∀ i < 5, self[i]!.val < 2 ^ 52) :
    scalar.Scalar52.pack self ⦃ r =>
      U8x32_as_Nat r.bytes = Scalar52_as_Nat self % 2 ^ 256 ∧
      (Scalar52_as_Nat self < 2 ^ 256 → U8x32_as_Nat r.bytes = Scalar52_as_Nat self) ⦄ := by
  unfold scalar.Scalar52.pack
  progress as ⟨a, ha⟩
  refine ⟨ha, fun hlt => ?_⟩
  rw [ha, Nat.mod_eq_of_lt hlt]

end curve25519_dalek.scalar.Scalar52
