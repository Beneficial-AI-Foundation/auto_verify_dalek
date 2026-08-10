# Curve25519Dalek 顶层 specification 清单

来源: `.verilib/probes/lean_Curve25519Dalek_0.1.0.json`（263 条 spec，其中 94 条顶层）

判定: spec 目标函数不被任何其他带 spec 的函数（直接或经无 spec helper 传递）调用。

## 公开 API 顶层 spec

| Spec | 状态 | 位置 |
|---|---|---|
| `curve25519_dalek.IdentityCurveModelsProjectivePoint.identity_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/ProjectivePoint/Identity.lean:40-50 |
| `curve25519_dalek.backend.serial.curve_models.ProjectivePoint.as_extended_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/ProjectivePoint/AsExtended.lean:46-76 |
| `curve25519_dalek.backend.serial.u64.constants.EIGHT_TORSION_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/U64/Constants/EIGHT_TORSION.lean:49-61 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.as_bytes_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/AsBytes.lean:31-39 |
| `curve25519_dalek.backend.serial.u64.scalar.Scalar52.square_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/U64/Scalar/Scalar52/Square.lean:63-75 |
| `curve25519_dalek.edwards.CompressedEdwardsY.from_slice_spec` | unverified | Curve25519Dalek/Specs/Edwards/CompressedEdwardsY/FromSlice.lean:48-59 |
| `curve25519_dalek.edwards.EdwardsPoint.as_affine_niels_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/AsAffineNiels.lean:138-177 |
| `curve25519_dalek.edwards.EdwardsPoint.compress_spec` | trusted | Curve25519Dalek/Specs/Edwards/EdwardsPoint/Compress.lean:49-61 |
| `curve25519_dalek.edwards.EdwardsPoint.double_spec` | trusted | Curve25519Dalek/Specs/Edwards/EdwardsPoint/Double.lean:40-48 |
| `curve25519_dalek.edwards.EdwardsPoint.is_small_order_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/IsSmallOrder.lean:39-47 |
| `curve25519_dalek.edwards.EdwardsPoint.is_torsion_free_spec` | trusted | Curve25519Dalek/Specs/Edwards/EdwardsPoint/IsTorsionFree.lean:57-65 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_base_clamped_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/MulBaseClamped.lean:47-62 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_clamped_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/MulClamped.lean:59-75 |
| `curve25519_dalek.edwards.affine.AffinePoint.to_edwards_spec` | unverified | Curve25519Dalek/Specs/Edwards/Affine/AffinePoint/ToEdwards.lean:55-73 |
| `curve25519_dalek.field.FieldElement51.SQRT_M1_val_spec` | unverified | Curve25519Dalek/Specs/Field/FieldElement51/SqrtRatioi.lean:42-43 |
| `curve25519_dalek.math.inv_sqrt_checked_spec` | unverified | Curve25519Dalek/Math/Basic.lean:353-361 |
| `curve25519_dalek.montgomery.MontgomeryPoint.as_bytes_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/AsBytes.lean:35-48 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_base_clamped_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/MulBaseClamped.lean:41-56 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_clamped_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/MulClamped.lean:40-55 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_bytes_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/ToBytes.lean:35-48 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_edwards_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/ToEdwards.lean:63-73 |
| `curve25519_dalek.montgomery.differential_add_and_double_spec` | unverified | Curve25519Dalek/Specs/Montgomery/ProjectivePoint/DifferentialAddAndDouble.lean:119-139 |
| `curve25519_dalek.montgomery.elligator_encode_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/ElligatorEncode.lean:462-489 |
| `curve25519_dalek.ristretto.CompressedRistretto.decompress_spec` | unverified | Curve25519Dalek/Specs/Ristretto/CompressedRistretto/Decompress.lean:46-61 |
| `curve25519_dalek.ristretto.CompressedRistretto.from_slice_spec` | unverified | Curve25519Dalek/Specs/Ristretto/CompressedRistretto/FromSlice.lean:51-62 |
| `curve25519_dalek.ristretto.CompressedRistretto.to_bytes_spec` | unverified | Curve25519Dalek/Specs/Ristretto/CompressedRistretto/ToBytes.lean:33-41 |
| `curve25519_dalek.ristretto.RistrettoPoint.compress_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Compress.lean:195-205 |
| `curve25519_dalek.ristretto.RistrettoPoint.from_uniform_bytes_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/FromUniformBytes.lean:68-81 |
| `curve25519_dalek.ristretto.RistrettoPoint.mul_base_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Mul_Base.lean:46-56 |
| `curve25519_dalek.scalar.Scalar.ONE_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/One.lean:24-30 |
| `curve25519_dalek.scalar.Scalar.ZERO_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Zero.lean:24-30 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromBytesModOrder.lean:35-43 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order_wide_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromBytesModOrderWide.lean:33-41 |
| `curve25519_dalek.scalar.Scalar.from_canonical_bytes_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromCanonicalBytes.lean:41-53 |
| `curve25519_dalek.scalar.Scalar.invert_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Invert.lean:38-47 |
| `curve25519_dalek.scalar.Scalar.to_bytes_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/ToBytes.lean:35-44 |
| `curve25519_dalek.subtle.ConditionallySelectable.conditional_assign.default_spec` | unverified | Curve25519Dalek/FunsExternal.lean:300-311 |
| `curve25519_dalek.subtle.ConditionallySelectable.conditional_swap.default_spec` | unverified | Curve25519Dalek/FunsExternal.lean:326-343 |

## Trait 实例顶层 spec

| Spec | 状态 | 位置 |
|---|---|---|
| `curve25519_dalek.Shared0AffineNielsPoint.Insts.CoreOpsArithNegAffineNielsPoint.neg_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/Neg.lean:65-73 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAAffineNielsPointCompletedPoint.add_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/Add.lean:63-91 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint.neg_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/Neg.lean:40-52 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithSubSharedAAffineNielsPointCompletedPoint.sub_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/Sub.lean:67-95 |
| `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithMulSharedAScalarRistrettoPoint.mul_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Mul.lean:44-55 |
| `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithSubSharedARistrettoPointRistrettoPoint.sub_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Sub.lean:39-52 |
| `curve25519_dalek.SharedAScalar.Insts.CoreOpsArithMulScalarScalar.mul_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Mul.lean:133-142 |
| `curve25519_dalek.U16.Insts.SubtleConstantTimeEq.ct_eq_spec` | unverified | Curve25519Dalek/FunsExternal.lean:227-235 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/AssertReceiverIsTotalEq.lean:36-45 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpPartialEqAffineNielsPoint.eq_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/Eq.lean:50-63 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/Identity.lean:46-57 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/ConditionalAssign.lean:52-72 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/CurveModels/AffineNielsPoint/ConditionalSelect.lean:30-52 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:700-714 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithSubAssignSharedAFieldElement51.sub_assign_spec` | unverified | Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/SubAssign.lean:41-48 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Edwards/CompressedEdwardsY/Identity.lean:42-50 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.SubtleConstantTimeEq.ct_eq_spec` | unverified | Curve25519Dalek/Specs/Edwards/CompressedEdwardsY/CtEq.lean:37-46 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCmpPartialEqEdwardsPoint.eq_spec` | unverified | Curve25519Dalek/Specs/Edwards/EdwardsPoint/Eq.lean:50-58 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:928-940 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:902-916 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint.eq_spec` | unverified | Curve25519Dalek/Specs/Edwards/Affine/AffinePoint/Eq.lean:49-57 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Edwards/Affine/AffinePoint/Identity.lean:37-46 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1136-1148 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select_spec` | unverified | Curve25519Dalek/Specs/Edwards/Affine/AffinePoint/ConditionalSelect.lean:38-49 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1110-1124 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1065-1074 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint.eq_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/Eq.lean:40-50 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulAssignShared0Scalar.mul_assign_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/MulAssign.lean:46-57 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint.mul_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/Mul.lean:280-301 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/Identity.lean:35-45 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1038-1050 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select_spec` | unverified | Curve25519Dalek/Specs/Montgomery/MontgomeryPoint/ConditionalSelect.lean:23-41 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1015-1026 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1086-1098 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select_spec` | unverified | Curve25519Dalek/Specs/Montgomery/ProjectivePoint/ConditionalSelect.lean:24-43 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Ristretto/CompressedRistretto/Identity.lean:32-40 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq.ct_eq_spec` | unverified | Curve25519Dalek/Specs/Ristretto/CompressedRistretto/CtEq.lean:37-46 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.eq_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Eq.lean:45-59 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/Identity.lean:35-46 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1245-1257 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select_spec` | unverified | Curve25519Dalek/Specs/Ristretto/RistrettoPoint/ConditionalSelect.lean:39-50 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:1219-1233 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar.eq_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Eq.lean:37-45 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU128.from_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromU128.lean:151-161 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU16.from_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromU16.lean:88-98 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU32.from_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromU32.lean:87-97 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64.from_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromU64.lean:90-100 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU8.from_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/FromU8.lean:42-52 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddSharedBScalarScalar.add_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Add.lean:96-107 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar.mul_assign_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/MulAssign.lean:97-104 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulScalarScalar.mul_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Mul.lean:167-176 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBScalarScalar.mul_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Mul.lean:99-108 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithNegScalar.neg_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Neg.lean:123-132 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubSharedBScalarScalar.sub_spec` | unverified | Curve25519Dalek/Specs/Scalar/Scalar/Sub.lean:100-111 |
| `curve25519_dalek.scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_assign_spec` | unverified | Curve25519Dalek/FunsExternal.lean:854-866 |
| `curve25519_dalek.scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_swap_spec` | unverified | Curve25519Dalek/FunsExternal.lean:828-842 |

## 排除的无目标函数 spec（辅助引理）

- `Montgomery.Aux_u_affine_toPoint_spec`
- `Montgomery.addX_spec`
- `Montgomery.non_u_affine_toPoint_spec`
- `curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51.LOW_51_BIT_MASK_spec`
- `curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51.m_spec`
- `curve25519_dalek.backend.serial.u64.constants.L_limbs_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.from_bytes_bitList_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.load8_at_bitList_progress_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.load8_at_bitList_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.load8_at_val_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.u64_and_mask51_bitList_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.u64_and_mask_bitList_spec`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.u64_shr_bitList_spec`
- `curve25519_dalek.backend.serial.u64.scalar.Scalar52.U64.ShiftLeft_IScalar_bitList_spec`
- `curve25519_dalek.backend.serial.u64.scalar.Scalar52.U64.ShiftRight_IScalar_bitList_spec`
- `curve25519_dalek.backend.serial.u64.scalar.Scalar52.part1_spec`
- `curve25519_dalek.backend.serial.u64.scalar.Scalar52.part2_spec`
- `curve25519_dalek.edwards.CompressedEdwardsY.step_1_spec`
- `curve25519_dalek.edwards.CompressedEdwardsY.step_2_spec`
- `curve25519_dalek.edwards.affine.AffinePoint.ONE_bounds_spec`
- `curve25519_dalek.montgomery.MontgomeryPoint.ONE_bounds_spec`
- `curve25519_dalek.ristretto.CompressedRistretto.core.array.TryFromArrayCopySlice.try_from_spec`
- `curve25519_dalek.scalar.Scalar52.square_multiply_loop_spec`
- `curve25519_dalek.scalar.Scalar52.square_multiply_spec`
