




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Pow2K
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Square
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Mul









open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek.backend.serial.u64.field.FieldElement51
open curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51
  (mul_spec)
namespace curve25519_dalek.field.FieldElement51

set_option exponentiation.threshold 100000






lemma chain_sq {a r b e m : ℕ}
    (ha : a ≡ r ^ e [MOD m]) (hb : b ≡ a ^ 2 [MOD m]) :
    b ≡ r ^ (2 * e) [MOD m] := sorry
lemma chain_mul {r a b c ea eb m : ℕ}
    (ha : a ≡ r ^ ea [MOD m]) (hb : b ≡ r ^ eb [MOD m]) (hc : c ≡ a * b [MOD m]) :
    c ≡ r ^ (ea + eb) [MOD m] := sorry
lemma chain_pow2k {r a b e k m : ℕ}
    (ha : a ≡ r ^ e [MOD m]) (hb : b ≡ a ^ (2 ^ k) [MOD m]) :
    b ≡ r ^ (e * 2 ^ k) [MOD m] := sorry





@[progress]
theorem pow22501_spec (r : backend.serial.u64.field.FieldElement51)
    (h_bounds : ∀ i, i < 5 → (r[i]!).val < 2 ^ 54) :
    pow22501 r ⦃ result =>
    let r1 := result.1
    let r2 := result.2
    Field51_as_Nat r1 % p = (Field51_as_Nat r ^ (2 ^ 250 - 1)) % p ∧
    Field51_as_Nat r2 % p = (Field51_as_Nat r ^ 11) % p ∧
    (∀ i, i < 5 → (r1[i]!).val < 2 ^ 52) ∧
    (∀ i, i < 5 → (r2[i]!).val < 2 ^ 52) ⦄ := by
  sorry
end curve25519_dalek.field.FieldElement51
