import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Sub
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square2

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.curve_models.ProjectivePoint

attribute [-simp] Int.reducePow Nat.reducePow

/-! Local, sorry-free versions of the `reduce`/`sub` field lemmas used by `double`. -/

theorem double_shr51_spec (x : Std.U64) :
    (x >>> 51#i32 : Result Std.U64) ⦃ z => z.val = x.val / 2 ^ 51 ∧ z.val ≤ 2 ^ 13 - 1 ⦄ := by
  progress with UScalar.ShiftRight_IScalar_spec as ⟨z, hz, _⟩
  have hx : x.val < 2 ^ 64 := by scalar_tac
  rw [Nat.shiftRight_eq_div_pow] at hz
  refine ⟨hz, ?_⟩
  rw [hz]
  omega

theorem double_mask51_spec (x mask : Std.U64) (hmask : mask.val = 2 ^ 51 - 1) :
    (lift (x &&& mask) : Result Std.U64) ⦃ z => z.val = x.val % 2 ^ 51 ∧ z.val < 2 ^ 51 ⦄ := by
  simp only [lift, WP.spec_ok]
  have h : (x &&& mask).val = x.val % 2 ^ 51 := by
    simp only [Aeneas.Std.UScalar.val_and, hmask, Nat.and_two_pow_sub_one_eq_mod]
  refine ⟨h, ?_⟩
  rw [h]
  exact Nat.mod_lt _ (by positivity)

theorem double_reduce_spec (limbs : Array Std.U64 5#usize) :
    u64.field.FieldElement51.reduce limbs ⦃ result =>
      (∀ i < 5, result[i]!.val < 2 ^ 51 + 2 ^ 18) ∧
      Field51_as_Nat result + (limbs[4]!.val / 2 ^ 51) * p = Field51_as_Nat limbs ⦄ := by
  unfold u64.field.FieldElement51.reduce
  progress as ⟨i, hi⟩
  progress with double_shr51_spec as ⟨c0, hc0, hc0b⟩
  progress as ⟨i1, hi1⟩
  progress with double_shr51_spec as ⟨c1, hc1, hc1b⟩
  progress as ⟨i2, hi2⟩
  progress with double_shr51_spec as ⟨c2, hc2, hc2b⟩
  progress as ⟨i3, hi3⟩
  progress with double_shr51_spec as ⟨c3, hc3, hc3b⟩
  progress as ⟨i4, hi4⟩
  progress with double_shr51_spec as ⟨c4, hc4, hc4b⟩
  progress as ⟨i5, hi5⟩
  progress with double_mask51_spec as ⟨i6, hi6, hi6b⟩
  progress as ⟨limbs1, hlimbs1⟩
  progress as ⟨i7, hi7⟩
  progress with double_mask51_spec as ⟨i8, hi8, hi8b⟩
  progress as ⟨limbs2, hlimbs2⟩
  progress as ⟨i9, hi9⟩
  progress with double_mask51_spec as ⟨i10, hi10, hi10b⟩
  progress as ⟨limbs3, hlimbs3⟩
  progress as ⟨i11, hi11⟩
  progress with double_mask51_spec as ⟨i12, hi12, hi12b⟩
  progress as ⟨limbs4, hlimbs4⟩
  progress as ⟨i13, hi13⟩
  progress with double_mask51_spec as ⟨i14, hi14, hi14b⟩
  progress as ⟨limbs5, hlimbs5⟩
  progress as ⟨i15, hi15⟩
  progress as ⟨i16, hi16⟩
  progress as ⟨i17, hi17⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5] at hi16
  subst hi16
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs6, hlimbs6⟩
  progress as ⟨i18, hi18⟩
  progress as ⟨i19, hi19⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6] at hi18
  subst hi18
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs7, hlimbs7⟩
  progress as ⟨i20, hi20⟩
  progress as ⟨i21, hi21⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7] at hi20
  subst hi20
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs8, hlimbs8⟩
  progress as ⟨i22, hi22⟩
  progress as ⟨i23, hi23⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8] at hi22
  subst hi22
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs9, hlimbs9⟩
  progress as ⟨i24, hi24⟩
  progress as ⟨i25, hi25⟩
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8, hlimbs9] at hi24
  subst hi24
  simp only [U64.max_eq]
  omega
  progress as ⟨limbs10, hlimbs10⟩
  simp at hi hi1 hi2 hi3 hi4
  subst hi; subst hi1; subst hi2; subst hi3; subst hi4
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4] at hi7 hi9 hi11 hi13
  subst hi7; subst hi9; subst hi11; subst hi13
  simp [hlimbs1, hlimbs2, hlimbs3, hlimbs4, hlimbs5, hlimbs6, hlimbs7, hlimbs8, hlimbs9]
    at hi16 hi18 hi20 hi22 hi24
  subst hi16; subst hi18; subst hi20; subst hi22; subst hi24
  constructor
  · intro j hj
    interval_cases j <;>
      simp [hlimbs10, hlimbs9, hlimbs8, hlimbs7, hlimbs6] <;> omega
  · unfold Field51_as_Nat p
    simp only [Finset.sum_range_succ, Finset.sum_range_zero]
    norm_num
    simp [hlimbs10, hlimbs9, hlimbs8, hlimbs7, hlimbs6, hlimbs5, hlimbs4, hlimbs3, hlimbs2, hlimbs1]
    have e0 := Nat.div_add_mod limbs[0]!.val (2 ^ 51)
    have e1 := Nat.div_add_mod limbs[1]!.val (2 ^ 51)
    have e2 := Nat.div_add_mod limbs[2]!.val (2 ^ 51)
    have e3 := Nat.div_add_mod limbs[3]!.val (2 ^ 51)
    have e4 := Nat.div_add_mod limbs[4]!.val (2 ^ 51)
    omega

theorem double_sub_spec (self _rhs : u64.field.FieldElement51)
    (ha : ∀ i < 5, self[i]!.val < 2 ^ 63)
    (hb : ∀ i < 5, _rhs[i]!.val < 2 ^ 54) :
    Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.sub self _rhs
      ⦃ (result : u64.field.FieldElement51) =>
      (∀ i < 5, result[i]!.val < 2 ^ 52) ∧
      (Field51_as_Nat result + Field51_as_Nat _rhs) % p = Field51_as_Nat self % p ⦄ := by
  unfold Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.sub
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
  progress with double_reduce_spec as ⟨result, hresult_bd, hresult_eq⟩
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
  rw [Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.Field51_as_Nat_eq
      (Array.make 5#usize [i3, i7, i11, i15, i19]), hL0, hL1, hL2, hL3, hL4] at hresult_eq
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
  rw [Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.Field51_as_Nat_eq
      self,
    Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.Field51_as_Nat_eq
      _rhs]
  unfold p
  unfold p at hresult_eq
  clear hi hi2 hi4 hi6 hi8 hi10 hi12 hi14 hi16 hi18 ha hb hL0 hL1 hL2 hL3 hL4
  omega


/-- Projective doubling produces a completed point with
`X' = (X+Y)^2 - (Y^2 + X^2)`, `Y' = Y^2 + X^2`, `Z' = Y^2 - X^2`, `T' = 2Z^2 - Z'`
(all modulo `p`). -/
@[progress]
theorem double_spec (q : ProjectivePoint)
    (h_qX_bounds : ∀ i < 5, (q.X[i]!).val < 2 ^ 53)
    (h_qY_bounds : ∀ i < 5, (q.Y[i]!).val < 2 ^ 53)
    (h_qZ_bounds : ∀ i < 5, (q.Z[i]!).val < 2 ^ 54) :
    double q ⦃ c =>
      (∀ i < 5, (c.X[i]!).val < 2 ^ 52) ∧
      (∀ i < 5, (c.Y[i]!).val < 2 ^ 53) ∧
      (∀ i < 5, (c.Z[i]!).val < 2 ^ 52) ∧
      (∀ i < 5, (c.T[i]!).val < 2 ^ 52) ∧
      (Field51_as_Nat c.X + Field51_as_Nat q.Y ^ 2 + Field51_as_Nat q.X ^ 2) % p =
        (Field51_as_Nat q.X + Field51_as_Nat q.Y) ^ 2 % p ∧
      Field51_as_Nat c.Y % p = (Field51_as_Nat q.Y ^ 2 + Field51_as_Nat q.X ^ 2) % p ∧
      (Field51_as_Nat c.Z + Field51_as_Nat q.X ^ 2) % p = Field51_as_Nat q.Y ^ 2 % p ∧
      (Field51_as_Nat c.T + Field51_as_Nat c.Z) % p = (2 * Field51_as_Nat q.Z ^ 2) % p ⦄ := by
  unfold double
  have hX54 : ∀ i < 5, (q.X[i]!).val < 2 ^ 54 := fun i hi => by
    have := h_qX_bounds i hi; omega
  have hY54 : ∀ i < 5, (q.Y[i]!).val < 2 ^ 54 := fun i hi => by
    have := h_qY_bounds i hi; omega
  have hX63 : ∀ i < 5, (q.X[i]!).val < 2 ^ 63 := fun i hi => by
    have := h_qX_bounds i hi; omega
  have hY63 : ∀ i < 5, (q.Y[i]!).val < 2 ^ 63 := fun i hi => by
    have := h_qY_bounds i hi; omega
  progress as ⟨XX, hXX1, hXX2⟩
  progress as ⟨YY, hYY1, hYY2⟩
  progress as ⟨ZZ2, hZZ1, hZZ2⟩
  progress as ⟨XpY, hXpY1, hXpY2⟩
  have hXpY54 : ∀ i < 5, (XpY[i]!).val < 2 ^ 54 := fun i hi => by
    have := hXpY1 i hi; have := h_qX_bounds i hi; have := h_qY_bounds i hi; omega
  progress as ⟨XpYsq, hS1, hS2⟩
  have hXX63 : ∀ i < 5, (XX[i]!).val < 2 ^ 63 := fun i hi => by
    have := hXX1 i hi; omega
  have hYY63 : ∀ i < 5, (YY[i]!).val < 2 ^ 63 := fun i hi => by
    have := hYY1 i hi; omega
  progress as ⟨YpX, hYpX1, hYpX2⟩
  have hXX54 : ∀ i < 5, (XX[i]!).val < 2 ^ 54 := fun i hi => by
    have := hXX1 i hi; omega
  progress with double_sub_spec as ⟨YmX, hYmX1, hYmX2⟩
  have hS63 : ∀ i < 5, (XpYsq[i]!).val < 2 ^ 63 := fun i hi => by
    have := hS1 i hi; omega
  have hYpX53 : ∀ i < 5, (YpX[i]!).val < 2 ^ 53 := fun i hi => by
    have := hYpX1 i hi; have := hXX1 i hi; have := hYY1 i hi; omega
  have hYpX54 : ∀ i < 5, (YpX[i]!).val < 2 ^ 54 := fun i hi => by
    have := hYpX53 i hi; omega
  progress with double_sub_spec as ⟨fe, hfe1, hfe2⟩
  have hZZ63 : ∀ i < 5, (ZZ2[i]!).val < 2 ^ 63 := fun i hi => by
    have := hZZ1 i hi; omega
  have hYmX54 : ∀ i < 5, (YmX[i]!).val < 2 ^ 54 := fun i hi => by
    have := hYmX1 i hi; omega
  progress with double_sub_spec as ⟨fe1, hfe11, hfe12⟩
  refine ⟨hfe1, hYpX53, hYmX1, hfe11, ?_, ?_, ?_, ?_⟩
  · have h1 : Field51_as_Nat fe + Field51_as_Nat q.Y ^ 2 + Field51_as_Nat q.X ^ 2 ≡
        Field51_as_Nat fe + Field51_as_Nat YpX [MOD p] := by
      rw [hYpX2, ← add_assoc]
      exact Nat.ModEq.add (Nat.ModEq.add rfl hYY2.symm) hXX2.symm
    have h2 : (Field51_as_Nat q.X + Field51_as_Nat q.Y) ^ 2 ≡ Field51_as_Nat XpYsq [MOD p] := by
      rw [← hXpY2]; exact hS2.symm
    exact h1.trans (hfe2.trans h2.symm)
  · have : Field51_as_Nat YpX ≡ Field51_as_Nat q.Y ^ 2 + Field51_as_Nat q.X ^ 2 [MOD p] := by
      rw [hYpX2]; exact Nat.ModEq.add hYY2 hXX2
    exact this
  · have : Field51_as_Nat YmX + Field51_as_Nat q.X ^ 2 ≡
        Field51_as_Nat YmX + Field51_as_Nat XX [MOD p] :=
      Nat.ModEq.add rfl hXX2.symm
    exact this.trans (hYmX2.trans hYY2)
  · exact hfe12.trans hZZ2


end curve25519_dalek.backend.serial.curve_models.ProjectivePoint
