import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52.Insts.CoreOpsIndexIndexUsizeU64

/-- `index` on a `Scalar52` returns the limb at index `i` (for `i < 5`). -/
@[progress]
theorem index_spec (self : backend.serial.u64.scalar.Scalar52) (i : Std.Usize)
    (hi : i.val < 5) :
    index self i ⦃ x => x = self.val[i.val]! ∧ x.val = self.val[i.val]!.val ⦄ := by
  unfold index
  have hlen : self.val.length = 5 := by simp
  progress as ⟨ x, hx ⟩
  exact ⟨hx, by rw [hx]⟩

end curve25519_dalek.backend.serial.u64.scalar.Scalar52.Insts.CoreOpsIndexIndexUsizeU64
