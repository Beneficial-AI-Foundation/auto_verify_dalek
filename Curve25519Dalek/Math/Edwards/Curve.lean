




import Curve25519Dalek.Math.Basic

import Mathlib.Algebra.Field.ZMod
import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic.NormNum.LegendreSymbol
import Mathlib.Tactic.LinearCombination
import PrimeCert.PrimeList

























namespace Edwards

open ZMod



instance : NeZero (2 : CurveField) := ⟨by decide⟩



structure EdwardsCurve (F : Type) where
  a : F
  d : F


def Ed25519 : EdwardsCurve CurveField := {
  a := -1,
  d := (d : CurveField)
}


lemma d_not_square : ¬IsSquare Ed25519.d := by
  apply (legendreSym.eq_neg_one_iff' p).mp
  norm_num [d, p]


@[ext]
structure Point {F : Type} [Mul F] [Add F] [Pow F ℕ] [One F] (C : EdwardsCurve F) where
  x : F
  y : F
  on_curve : C.a * x^2 + y^2 = 1 + C.d * x^2 * y^2 := by grind
  deriving Repr

instance : DecidableEq (Point Ed25519) := fun p1 p2 =>
  if hx : p1.x = p2.x then
    if hy : p1.y = p2.y then isTrue (Point.ext hx hy)
    else isFalse (fun h => hy (congrArg Point.y h))
  else isFalse (fun h => hx (congrArg Point.x h))

instance : Inhabited (Point Ed25519) := ⟨{ x := 0, y := 1}⟩


lemma neg_one_is_square : IsSquare (-1 : CurveField) := by
  apply ZMod.exists_sq_eq_neg_one_iff.mpr; decide



variable {F : Type} [Field F]

section Completeness
variable [NeZero (2 : F)]







theorem complete_addition_denominators_ne_zero
    (C : EdwardsCurve F) (ha : IsSquare C.a) (hd : ¬IsSquare C.d) (p1 p2 : Point C) :
    let lam := C.d * p1.x * p2.x * p1.y * p2.y
    (1 + lam ≠ 0) ∧ (1 - lam ≠ 0) := by





  sorry




theorem Ed25519.denomsNeZero (p1 p2 : Point Ed25519) :
    let lam := Ed25519.d * p1.x * p2.x * p1.y * p2.y
    (1 + lam ≠ 0) ∧ (1 - lam ≠ 0) :=
  complete_addition_denominators_ne_zero Ed25519 neg_one_is_square d_not_square p1 p2




def add_coords (C : EdwardsCurve F) (p1 p2 : F × F) : F × F :=
  let (x₁, y₁) := p1
  let (x₂, y₂) := p2
  let lambda_val := C.d * x₁ * x₂ * y₁ * y₂
  ( (x₁ * y₂ + y₁ * x₂) / (1 + lambda_val), (y₁ * y₂ - C.a * x₁ * x₂) / (1 - lambda_val) )

omit [NeZero (2 : F)] in



theorem add_closure (C : EdwardsCurve F) (p1 p2 : Point C)
    (h : let lam := C.d * p1.x * p2.x * p1.y * p2.y; (1 + lam ≠ 0) ∧ (1 - lam ≠ 0)) :
    let (x, y) := add_coords C (p1.x, p1.y) (p2.x, p2.y)
    C.a * x^2 + y^2 = 1 + C.d * x^2 * y^2 := by
  set x₁ := p1.x; set y₁ := p1.y
  set x₂ := p2.x; set y₂ := p2.y
  suffices C.a * (x₁ * y₂ + y₁ * x₂)^2 * (1 - x₁ * y₂ * y₁ * x₂ * C.d)^2 +
      (1 + x₁ * y₂ * y₁ * x₂ * C.d)^2 * (y₂ * y₁ - C.a * x₁ * x₂)^2 =
      (1 + x₁ * y₂ * y₁ * x₂ * C.d)^2 * (1 - x₁ * y₂ * y₁ * x₂ * C.d)^2 +
      (x₁ * y₂ + y₁ * x₂)^2 * C.d * (y₂ * y₁ - C.a * x₁ * x₂)^2 by
    have : 1 + x₁ * y₂ * y₁ * x₂ * C.d ≠ 0 := by grind
    have : 1 - x₁ * y₂ * y₁ * x₂ * C.d ≠ 0 := by grind
    unfold add_coords
    field_simp; assumption
  rw [← sub_eq_zero]



  let A := C.a * x₁^2 + y₁^2 - (1 + C.d * x₁^2 * y₁^2)
  let B := C.a * x₂^2 + y₂^2 - (1 + C.d * x₂^2 * y₂^2)
  have hA : A = 0 := by linear_combination p1.on_curve
  have hB : B = 0 := by linear_combination p2.on_curve
  let P := (C.a * x₂^2 + y₂^2) + (-C.d * x₂^2 * y₂^2) + (-C.d * x₂^2 * y₁^2 * y₂^2) +
    (-C.a * x₁^2 * x₂^2 * y₂^2 * C.d) + (x₁^2 * y₁^2 * x₂^2 * y₂^4 * C.d^2) +
    (-x₁^2 * y₁^2 * x₂^2 * y₂^2 * C.d^2) + (C.a * x₁^2 * x₂^4 * y₁^2 * y₂^2 * C.d^2)
  let Q := 1 + (-x₁^2 * y₁^2 * y₂^2 * C.d) + (-C.a * x₁^2 * x₂^2 * y₁^2 * C.d) +
    (x₁^4 * x₂^2 * y₁^4 * y₂^2 * C.d^3)
  calc _ = P * A + Q * B := by grind
    _ = P * 0 + Q * 0 := by rw [hA, hB]
    _ = 0 := by ring

end Completeness



theorem add_closure_Ed25519 (p1 p2 : Point Ed25519) :
    let (x, y) := add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)
    Ed25519.a * x^2 + y^2 = 1 + Ed25519.d * x^2 * y^2 :=
  add_closure Ed25519 p1 p2 (Ed25519.denomsNeZero p1 p2)



instance : Add (Point Ed25519) where
  add p1 p2 :=
  let coords := add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)
  { x := coords.1
    y := coords.2
    on_curve := add_closure_Ed25519 p1 p2 }

instance : Zero (Point Ed25519) where
  zero := { x := 0, y := 1 }

@[simp] theorem zero_x : (0 : Point Ed25519).x = 0 := rfl
@[simp] theorem zero_y : (0 : Point Ed25519).y = 1 := rfl

instance : Neg (Point Ed25519) where
  neg p := {
    x := -p.x
    y := p.y
    on_curve := by simpa [neg_pow_two] using p.on_curve
  }

@[simp] theorem neg_x (p : Point Ed25519) : (-p).x = -p.x := rfl
@[simp] theorem neg_y (p : Point Ed25519) : (-p).y = p.y := rfl

instance : Sub (Point Ed25519) where
  sub p1 p2 := p1 + (-p2)

def nsmul_Ed25519 (n : ℕ) (p : Point Ed25519) : Point Ed25519 :=
  match n with
  | 0 => 0
  | n + 1 => p + (nsmul_Ed25519 n p)



def binary_nsmul_Ed25519 (n : ℕ) (p : Point Ed25519) : Point Ed25519 :=
  if n = 0 then 0
  else
    let half := binary_nsmul_Ed25519 (n / 2) p
    let doubled := half + half
    if n % 2 = 1 then doubled + p else doubled
decreasing_by omega

def zsmul_Ed25519 (z : ℤ) (p : Point Ed25519) : Point Ed25519 :=
  match z with
  | (n : ℕ) => nsmul_Ed25519 n p
  | (Int.negSucc n) => -(nsmul_Ed25519 (n + 1) p)

instance : SMul ℕ (Point Ed25519) := ⟨nsmul_Ed25519⟩
instance : SMul ℤ (Point Ed25519) := ⟨zsmul_Ed25519⟩




theorem add_coords_mk (C : EdwardsCurve F) (x₁ y₁ x₂ y₂ : F) :
    let lam := C.d * x₁ * x₂ * y₁ * y₂;
    add_coords C (x₁, y₁) (x₂, y₂) =
      ((x₁ * y₂ + y₁ * x₂) / (1 + lam), (y₁ * y₂ - C.a * x₁ * x₂) / (1 - lam)) := rfl


theorem add_x (p q : Point Ed25519) :
    (p + q).x = (p.x * q.y + p.y * q.x) / (1 + Ed25519.d * p.x * q.x * p.y * q.y) := rfl


theorem add_y (p q : Point Ed25519) :
    (p + q).y = (p.y * q.y - Ed25519.a * p.x * q.x) / (1 - Ed25519.d * p.x * q.x * p.y * q.y) := rfl


theorem zero_add_Ed25519 (p : Point Ed25519) : (0 : Point Ed25519) + p = p := by
  ext
  · rw [add_x]; simp only [Ed25519, zero_x, zero_mul, zero_y, one_mul, zero_add, mul_zero, mul_one,
    add_zero, div_one]
  · rw [add_y]; simp only [Ed25519, zero_y, one_mul, zero_x, mul_zero, zero_mul, sub_zero, mul_one,
    div_one]


theorem add_zero_Ed25519 (p : Point Ed25519) : p + (0 : Point Ed25519) = p := by
  ext
  · rw [add_x]; simp only [Ed25519, zero_y, mul_one, zero_x, mul_zero, add_zero, zero_mul, div_one]
  · rw [add_y]; simp only [Ed25519, zero_y, mul_one, neg_mul, one_mul, zero_x, mul_zero, sub_zero,
    zero_mul, div_one]


theorem neg_add_cancel_Ed25519 (p : Point Ed25519) : -p + p = (0 : Point Ed25519) := by
  have h : p.y^2 - p.x^2 = 1 + (d : CurveField) * p.x^2 * p.y^2 := by
    have := p.on_curve; simp only [Ed25519, neg_mul, one_mul] at this; grind
  have : 1 + (d : CurveField) * p.x^2 * p.y^2 ≠ 0 := calc
    1 + d * p.x^2 * p.y^2 = 1 - d * (-p.x) * p.x * p.y * p.y := by ring
    _ ≠ 0 := (Ed25519.denomsNeZero (-p) p).2
  ext
  · rw [add_x, neg_x, neg_y]; ring_nf; rfl
  · have := calc (p.y * p.y - -1 * (-p.x) * p.x) / (1 - d * (-p.x) * p.x * p.y * p.y)
      _ = (p.y^2 - p.x^2) / (1 + d * p.x^2 * p.y^2) := by ring_nf
      _ = 1 := by rw [h]; grind
    rw [add_y]; simp only [Ed25519, zero_y]
    omega


theorem add_comm_Ed25519 (p q : Point Ed25519) : p + q = q + p := by
  ext <;> simp only [add_x, add_y] <;> ring


theorem nsmul_succ_Ed25519 (n : ℕ) (p : Point Ed25519) :
    nsmul_Ed25519 (n + 1) p = nsmul_Ed25519 n p + p := by
  rw [add_comm_Ed25519]; rfl


theorem zsmul_succ_Ed25519 (n : ℕ) (p : Point Ed25519) :
    zsmul_Ed25519 (Int.ofNat n.succ) p = zsmul_Ed25519 (Int.ofNat n) p + p := by
  simp only [zsmul_Ed25519]
  induction n with
  | zero =>
    simp only [nsmul_Ed25519]

    rw [add_zero_Ed25519, zero_add_Ed25519]
  | succ k _ih =>
    simp only [nsmul_Ed25519]
    rw [add_comm_Ed25519]


theorem add_assoc_Ed25519 (p q r : Point Ed25519) : p + q + r = p + (q + r) := by




  sorry


instance : AddCommGroup (Point Ed25519) where
  add := Add.add
  add_assoc := add_assoc_Ed25519
  zero := 0
  zero_add := zero_add_Ed25519
  add_zero := add_zero_Ed25519
  nsmul := nsmul_Ed25519
  neg := Neg.neg
  zsmul := zsmul_Ed25519
  neg_add_cancel := neg_add_cancel_Ed25519
  add_comm := add_comm_Ed25519
  nsmul_succ := nsmul_succ_Ed25519
  zsmul_succ' := zsmul_succ_Ed25519


theorem add_def (p1 p2 : Point Ed25519) :
  (p1 + p2).x = (add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)).1 ∧
  (p1 + p2).y = (add_coords Ed25519 (p1.x, p1.y) (p2.x, p2.y)).2 := by
  exact Prod.mk_inj.mp rfl


theorem binary_nsmul_Ed25519_eq (n : ℕ) (q : Point Ed25519) :
    binary_nsmul_Ed25519 n q = n • q := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    unfold binary_nsmul_Ed25519
    split_ifs
    · simp_all
    · have : n / 2 < n := by omega
      conv_rhs => rw [show n = n / 2 + n / 2 + 1 from by omega]
      simp [ih _ this, add_nsmul]
    · have : n / 2 < n := by omega
      conv_rhs => rw [show n = n / 2 + n / 2 from by omega]
      simp [ih _ this, add_nsmul]

end Edwards
