import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52.Insts.CoreOpsIndexIndexMutUsizeU64

/-- `index_mut` on a `Scalar52` returns the limb at index `i` and a back-function that
writes a new value at index `i` (all other limbs are unchanged). -/
@[progress]
theorem index_mut_spec (self : backend.serial.u64.scalar.Scalar52) (i : Std.Usize)
    (hi : i.val < 5) :
    index_mut self i ⦃ x back =>
      x = self.val[i.val]! ∧
      back = Aeneas.Std.Array.set self i ∧
      (∀ v : Std.U64, (back v).val = self.val.set i.val v) ∧
      (∀ v : Std.U64, (back v).val[i.val]! = v) ∧
      (∀ v : Std.U64, ∀ j : Nat, j ≠ i.val → (back v).val[j]! = self.val[j]!) ⦄ := by
  unfold index_mut
  have hlen : self.val.length = 5 := by simp
  progress as ⟨ x, back, hback, hx ⟩
  refine ⟨hx, hback, ?_, ?_, ?_⟩
  · intro v; simp [hback]
  · intro v; simp [hback, hlen, hi]
  · intro v j hj; simp [hback]
    rw [List.getElem?_set_ne (by omega)]

end curve25519_dalek.backend.serial.u64.scalar.Scalar52.Insts.CoreOpsIndexIndexMutUsizeU64
