




import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.FromBytes
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Add
import Curve25519Dalek.Specs.Backend.Serial.U64.Scalar.Scalar52.Pack






















open Aeneas Aeneas.Std Result Aeneas.Std.WP
namespace curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithAddSharedAScalarScalar






























@[progress]
theorem add_spec (self _rhs : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L)
    (h_rhs : U8x32_as_Nat _rhs.bytes < L) :
    add self _rhs ⦃ (result : scalar.Scalar) =>
      U8x32_as_Nat result.bytes ≡ U8x32_as_Nat self.bytes + U8x32_as_Nat _rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  unfold add scalar.Scalar.unpack
  progress as ⟨s, hs, hs_bound⟩
  progress as ⟨s1, hs1, hs1_bound⟩
  have has : ∀ i < 5, s[i]!.val < 2 ^ 52 := hs_bound
  have hbs : ∀ i < 5, s1[i]!.val < 2 ^ 52 := hs1_bound
  have has' : Scalar52_as_Nat s < L := by rw [hs]; exact h_self
  have hbs' : Scalar52_as_Nat s1 ≤ L := by rw [hs1]; exact h_rhs.le
  progress as ⟨s2, hs2, hs2_lt, hs2_bound⟩
  progress as ⟨result, hresult, hresult_lt⟩
  refine ⟨?_, hresult_lt⟩
  rw [hs, hs1] at hs2
  exact hresult.trans hs2
end curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithAddSharedAScalarScalar







namespace curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddSharedBScalarScalar

















@[progress]
theorem add_spec (self rhs : scalar.Scalar)
    (h_self : U8x32_as_Nat self.bytes < L)
    (h_rhs : U8x32_as_Nat rhs.bytes < L) :
    add self rhs ⦃ result =>
      U8x32_as_Nat result.bytes ≡
        U8x32_as_Nat self.bytes + U8x32_as_Nat rhs.bytes [MOD L] ∧
      U8x32_as_Nat result.bytes < L ⦄ := by
  unfold add
  progress*
end curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddSharedBScalarScalar
