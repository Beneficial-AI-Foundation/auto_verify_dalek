




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Field.FieldElement51.Pow22501
import Curve25519Dalek.Math.Edwards.Curve













open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
  (mul_spec)
namespace curve25519_dalek.field.FieldElement51


















theorem prime_25519 : Nat.Prime p := by
  sorry
lemma coprime_of_prime_not_dvd {a p : ℕ}
(hp : p.Prime) (hpa : ¬ p ∣ a) : Nat.Coprime a p := by
  sorry
set_option exponentiation.threshold 100000






@[progress]
theorem invert_spec (r : backend.serial.u64.field.FieldElement51)
    (h_bounds : ∀ i, i < 5 → (r[i]!).val < 2 ^ 54) :
    invert r ⦃ (r' : backend.serial.u64.field.FieldElement51) =>
      let r_nat := Field51_as_Nat r % p
      let r'_nat := Field51_as_Nat r' % p
      (r_nat ≠ 0 → (r'_nat * r_nat) % p = 1) ∧
      (r_nat = 0 → r'_nat = 0) ∧
      (∀ i, i < 5 → (r'[i]!).val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.field.FieldElement51
