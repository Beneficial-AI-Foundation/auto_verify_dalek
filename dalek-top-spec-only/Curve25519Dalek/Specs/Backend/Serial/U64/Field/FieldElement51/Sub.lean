import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51

attribute [-simp] Int.reducePow Nat.reducePow

/-- Unrolls `Field51_as_Nat` into its five limb terms, expressed with `Array.val`-level
(list) indexing so that it lines up with the equations produced by `Array.index_usize_spec`. -/
theorem Field51_as_Nat_eq (X : Array Std.U64 5#usize) :
    Field51_as_Nat X =
      X.val[0]!.val + 2 ^ 51 * X.val[1]!.val + 2 ^ 102 * X.val[2]!.val +
        2 ^ 153 * X.val[3]!.val + 2 ^ 204 * X.val[4]!.val := by
  unfold Field51_as_Nat
  simp only [Array.getElem!_Nat_eq, Finset.sum_range_succ, Finset.sum_range_zero]
  ring

@[progress]
theorem sub_spec (self _rhs : backend.serial.u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 63)
    (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 54) :
    sub self _rhs ⦃ (result : backend.serial.u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      (Field51_as_Nat result + Field51_as_Nat _rhs) % p = Field51_as_Nat self % p ⦄ := by
  unfold sub
  simp only [Array.getElem!_Nat_eq] at ha hb
  have ha0 := ha 0 (by omega)
  have ha1 := ha 1 (by omega)
  have ha2 := ha 2 (by omega)
  have ha3 := ha 3 (by omega)
  have ha4 := ha 4 (by omega)
  have hb0 := hb 0 (by omega)
  have hb1 := hb 1 (by omega)
  have hb2 := hb 2 (by omega)
  have hb3 := hb 3 (by omega)
  have hb4 := hb 4 (by omega)
  progress as ⟨i, hi⟩
  progress as ⟨i1, hi1⟩
  progress as ⟨i2, hi2⟩
  progress as ⟨i3, hi3, hi3b⟩
  progress as ⟨i4, hi4⟩
  progress as ⟨i5, hi5⟩
  progress as ⟨i6, hi6⟩
  progress as ⟨i7, hi7, hi7b⟩
  progress as ⟨i8, hi8⟩
  progress as ⟨i9, hi9⟩
  progress as ⟨i10, hi10⟩
  progress as ⟨i11, hi11, hi11b⟩
  progress as ⟨i12, hi12⟩
  progress as ⟨i13, hi13⟩
  progress as ⟨i14, hi14⟩
  progress as ⟨i15, hi15, hi15b⟩
  progress as ⟨i16, hi16⟩
  progress as ⟨i17, hi17⟩
  progress as ⟨i18, hi18⟩
  progress as ⟨i19, hi19, hi19b⟩
  progress as ⟨result, hresult_bd, hresult_eq⟩
  have hL0 : (Array.make 5#usize [i3, i7, i11, i15, i19] : Array Std.U64 5#usize).val[0]! = i3 := by
    simp [Array.make]
  have hL1 : (Array.make 5#usize [i3, i7, i11, i15, i19] : Array Std.U64 5#usize).val[1]! = i7 := by
    simp [Array.make]
  have hL2 : (Array.make 5#usize [i3, i7, i11, i15, i19] : Array Std.U64 5#usize).val[2]! = i11 := by
    simp [Array.make]
  have hL3 : (Array.make 5#usize [i3, i7, i11, i15, i19] : Array Std.U64 5#usize).val[3]! = i15 := by
    simp [Array.make]
  have hL4 : (Array.make 5#usize [i3, i7, i11, i15, i19] : Array Std.U64 5#usize).val[4]! = i19 := by
    simp [Array.make]
  rw [Array.getElem!_Nat_eq, hL4] at hresult_eq
  rw [Field51_as_Nat_eq (Array.make 5#usize [i3, i7, i11, i15, i19]), hL0, hL1, hL2, hL3, hL4]
    at hresult_eq
  have hi' : i.val = self.val[0]!.val := by rw [hi]
  have hi4' : i4.val = self.val[1]!.val := by rw [hi4]
  have hi8' : i8.val = self.val[2]!.val := by rw [hi8]
  have hi12' : i12.val = self.val[3]!.val := by rw [hi12]
  have hi16' : i16.val = self.val[4]!.val := by rw [hi16]
  have hi2' : i2.val = _rhs.val[0]!.val := by rw [hi2]
  have hi6' : i6.val = _rhs.val[1]!.val := by rw [hi6]
  have hi10' : i10.val = _rhs.val[2]!.val := by rw [hi10]
  have hi14' : i14.val = _rhs.val[3]!.val := by rw [hi14]
  have hi18' : i18.val = _rhs.val[4]!.val := by rw [hi18]
  refine ⟨fun j hj => by have := hresult_bd j hj; omega, ?_⟩
  rw [Field51_as_Nat_eq self, Field51_as_Nat_eq _rhs]
  unfold p
  unfold p at hresult_eq
  clear hi hi2 hi4 hi6 hi8 hi10 hi12 hi14 hi16 hi18 ha hb hL0 hL1 hL2 hL3 hL4
  omega

end curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51
