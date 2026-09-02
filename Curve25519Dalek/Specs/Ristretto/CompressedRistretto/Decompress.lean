




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Math.Ristretto.Representation
import Curve25519Dalek.Specs.Ristretto.CompressedRistretto.Step1
import Curve25519Dalek.Specs.Ristretto.CompressedRistretto.Step2
















open Aeneas Aeneas.Std Result Edwards Aeneas.Std.WP
open curve25519_dalek.ristretto
namespace curve25519_dalek.ristretto.CompressedRistretto



private lemma decompress_step1_val_eq (c : CompressedRistretto)
    (s : backend.serial.u64.field.FieldElement51)
    (hs : s.toField = ((U8x32_as_Nat c % 2 ^ 255 : ℕ) : ZMod p))
    {val : ZMod p} (h : decompress_step1 c = some val) :
    val = s.toField := by
  simp only [decompress_step1] at h
  split_ifs at h with h_cond
  simp only [Bool.or_eq_true, decide_eq_true_eq, ge_iff_le, not_or, not_le] at h_cond
  have h_lt_p : U8x32_as_Nat c < p := h_cond.1
  have h_lt_255 : U8x32_as_Nat c < 2 ^ 255 := lt_trans h_lt_p (by decide)
  rw [Option.some.injEq] at h
  rw [← h, hs, Nat.mod_eq_of_lt h_lt_255]







@[progress]
theorem decompress_spec (comp : CompressedRistretto) :
    decompress comp ⦃ result =>
    (¬comp.IsValid → result = none) ∧
    (comp.IsValid →
        ∃ rist,
        result = some rist ∧
        RistrettoPoint.IsValid rist ∧
        decompress_pure comp = some rist.toPoint) ⦄ := by
  sorry
end curve25519_dalek.ristretto.CompressedRistretto
