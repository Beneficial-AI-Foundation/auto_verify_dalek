import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.AsMontgomery
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromMontgomery
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.MontgomeryInvert

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.scalar.Scalar52

/-- Fermat's little theorem for `L`: `a * a^(L-2) ≡ 1 [MOD L]` when `a` is not divisible by `L`. -/
theorem mul_pow_L_sub_two_modEq_one (a : ℕ) (h : a % _root_.L ≠ 0) :
    a * a ^ (_root_.L - 2) ≡ 1 [MOD _root_.L] := by
  rw [← ZMod.natCast_eq_natCast_iff]
  have ha : (a : ZMod _root_.L) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff]
    exact fun hd => h (Nat.mod_eq_zero_of_dvd hd)
  have hL : 2 ≤ _root_.L := by unfold _root_.L; norm_num
  have hexp : _root_.L - 1 = 1 + (_root_.L - 2) := by omega
  push_cast
  rw [← pow_one (a : ZMod _root_.L), ← pow_mul, one_mul, ← pow_add, ← hexp]
  simpa using ZMod.pow_card_sub_one_eq_one ha

/-- Montgomery round trip for exponentiation: entering Montgomery form (`s ≡ a R`), computing
`m R^(n-3) ≡ s^(n-2)` and leaving it (`r R ≡ m`) yields `r ≡ a^(n-2) [MOD n]`. -/
theorem mont_roundtrip_pow {n R a s m r : ℕ} (hn : 3 ≤ n) (hR : Nat.Coprime n R)
    (hs : s ≡ a * R [MOD n]) (hm : m * R ^ (n - 3) ≡ s ^ (n - 2) [MOD n])
    (hr : r * R ≡ m [MOD n]) : r ≡ a ^ (n - 2) [MOD n] := by
  apply Nat.ModEq.cancel_right_of_coprime (Nat.Coprime.pow_right (n - 2) hR)
  have he : n - 2 = 1 + (n - 3) := by omega
  calc r * R ^ (n - 2) = (r * R) * R ^ (n - 3) := by rw [he, pow_add, pow_one]; ring
    _ ≡ m * R ^ (n - 3) [MOD n] := Nat.ModEq.mul_right _ hr
    _ ≡ s ^ (n - 2) [MOD n] := hm
    _ ≡ (a * R) ^ (n - 2) [MOD n] := Nat.ModEq.pow _ hs
    _ = a ^ (n - 2) * R ^ (n - 2) := mul_pow _ _ _

/-- `invert` computes `self^(L-2) mod L` (the inverse of `self` modulo `L` when it is
non-zero mod `L`), with limbs bounded by `2^52` and fully reduced value. -/
@[progress]
theorem invert_spec (self : backend.serial.u64.scalar.Scalar52)
    (h : ∀ i, i < 5 → (self.val[i]!).val < 2 ^ 52) :
    scalar.Scalar52.invert self ⦃ r =>
      (∀ i, i < 5 → (r.val[i]!).val < 2 ^ 52) ∧
      Scalar52_as_Nat r < _root_.L ∧
      Scalar52_as_Nat r ≡ Scalar52_as_Nat self ^ (_root_.L - 2) [MOD _root_.L] ∧
      (Scalar52_as_Nat self % _root_.L ≠ 0 →
        Scalar52_as_Nat self * Scalar52_as_Nat r ≡ 1 [MOD _root_.L]) ⦄ := by
  unfold scalar.Scalar52.invert
  progress as ⟨s, hs, hsm, hsL⟩
  progress as ⟨m, hm, hmL, hmm⟩
  progress as ⟨r, hr, hrm, hrL⟩
  have hL : 3 ≤ _root_.L := by unfold _root_.L; norm_num
  have key : Scalar52_as_Nat r ≡ Scalar52_as_Nat self ^ (_root_.L - 2) [MOD _root_.L] :=
    mont_roundtrip_pow hL backend.serial.u64.scalar.Scalar52.L_coprime_R hsm hmm hrm
  refine ⟨hr, hrL, key, fun hne => ?_⟩
  exact (Nat.ModEq.mul_left _ key).trans (mul_pow_L_sub_two_modEq_one _ hne)

end curve25519_dalek.scalar.Scalar52
