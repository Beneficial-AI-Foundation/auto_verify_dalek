# api-top：面向用户的 pub API 面 ∩ 已抽取已 spec 集合

来源: `functions.json` + Rust 源码可见性 + probe 调用图；共 **87** 条。
`caller_anchored = yes` 表示存在其他带 spec 的函数（经无 spec helper 传递）调用它——
删除这类 spec 时全绿不等于合格，必须靠 `synth_eq_human` 评分。

## 公开 API 函数（36 条）

| Lean 名 | spec | caller_anchored | 位置 |
|---|---|---|---|
| `curve25519_dalek.edwards.CompressedEdwardsY.as_bytes` | ✓ | yes | curve25519-dalek/src/edwards.rs:L188-L190 |
| `curve25519_dalek.edwards.CompressedEdwardsY.decompress` | ✓ | yes | curve25519-dalek/src/edwards.rs:L201-L209 |
| `curve25519_dalek.edwards.CompressedEdwardsY.from_slice` | ✓ | no | curve25519-dalek/src/edwards.rs:L414-L417 |
| `curve25519_dalek.edwards.EdwardsPoint.compress` | ✓ | no | curve25519-dalek/src/edwards.rs:L607-L609 |
| `curve25519_dalek.edwards.EdwardsPoint.is_small_order` | ✓ | no | curve25519-dalek/src/edwards.rs:L1367-L1369 |
| `curve25519_dalek.edwards.EdwardsPoint.is_torsion_free` | ✓ | no | curve25519-dalek/src/edwards.rs:L1397-L1399 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_base` | ✓ | yes | curve25519-dalek/src/edwards.rs:L877-L887 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_base_clamped` | ✓ | no | curve25519-dalek/src/edwards.rs:L907-L915 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_by_cofactor` | ✓ | yes | curve25519-dalek/src/edwards.rs:L1325-L1327 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_clamped` | ✓ | no | curve25519-dalek/src/edwards.rs:L891-L903 |
| `curve25519_dalek.edwards.EdwardsPoint.to_montgomery` | ✓ | yes | curve25519-dalek/src/edwards.rs:L572-L582 |
| `curve25519_dalek.edwards.affine.AffinePoint.compress` | ✓ | yes | curve25519-dalek/src/edwards/affine.rs:L71-L75 |
| `curve25519_dalek.edwards.affine.AffinePoint.to_edwards` | ✓ | no | curve25519-dalek/src/edwards/affine.rs:L60-L67 |
| `curve25519_dalek.montgomery.MontgomeryPoint.as_bytes` | ✓ | no | curve25519-dalek/src/montgomery.rs:L199-L201 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_base` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L128-L130 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_base_clamped` | ✓ | no | curve25519-dalek/src/montgomery.rs:L150-L158 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_clamped` | ✓ | no | curve25519-dalek/src/montgomery.rs:L134-L146 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_bytes` | ✓ | no | curve25519-dalek/src/montgomery.rs:L204-L206 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_edwards` | ✓ | no | curve25519-dalek/src/montgomery.rs:L224-L253 |
| `curve25519_dalek.montgomery.ProjectivePoint.as_affine` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L331-L334 |
| `curve25519_dalek.ristretto.CompressedRistretto.as_bytes` | ✓ | yes | curve25519-dalek/src/ristretto.rs:L235-L237 |
| `curve25519_dalek.ristretto.CompressedRistretto.decompress` | ✓ | no | curve25519-dalek/src/ristretto.rs:L257-L271 |
| `curve25519_dalek.ristretto.CompressedRistretto.from_slice` | ✓ | no | curve25519-dalek/src/ristretto.rs:L245-L248 |
| `curve25519_dalek.ristretto.CompressedRistretto.to_bytes` | ✓ | no | curve25519-dalek/src/ristretto.rs:L230-L232 |
| `curve25519_dalek.ristretto.RistrettoPoint.compress` | ✓ | no | curve25519-dalek/src/ristretto.rs:L498-L542 |
| `curve25519_dalek.ristretto.RistrettoPoint.from_uniform_bytes` | ✓ | no | curve25519-dalek/src/ristretto.rs:L823-L839 |
| `curve25519_dalek.ristretto.RistrettoPoint.mul_base` | ✓ | no | curve25519-dalek/src/ristretto.rs:L988-L998 |
| `curve25519_dalek.scalar.Scalar.as_bytes` | ✓ | yes | curve25519-dalek/src/scalar.rs:L706-L708 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order` | ✓ | no | curve25519-dalek/src/scalar.rs:L237-L246 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order_wide` | ✓ | no | curve25519-dalek/src/scalar.rs:L250-L252 |
| `curve25519_dalek.scalar.Scalar.from_canonical_bytes` | ✓ | no | curve25519-dalek/src/scalar.rs:L261-L265 |
| `curve25519_dalek.scalar.Scalar.invert` | ✓ | no | curve25519-dalek/src/scalar.rs:L747-L749 |
| `curve25519_dalek.scalar.Scalar.to_bytes` | ✓ | no | curve25519-dalek/src/scalar.rs:L691-L693 |
| `curve25519_dalek.scalar.Scalar52.invert` | ✓ | yes | curve25519-dalek/src/scalar.rs:L1232-L1234 |
| `curve25519_dalek.scalar.Scalar52.montgomery_invert` | ✓ | yes | curve25519-dalek/src/scalar.rs:L1174-L1229 |
| `curve25519_dalek.scalar.clamp_integer` | ✓ | yes | curve25519-dalek/src/scalar.rs:L1415-L1420 |

## 公开常量（4 条）

| Lean 名 | spec | caller_anchored | 位置 |
|---|---|---|---|
| `curve25519_dalek.constants.BASEPOINT_ORDER_PRIVATE` | ✓ | yes | curve25519-dalek/src/constants.rs:L75-L81 |
| `curve25519_dalek.constants.RISTRETTO_BASEPOINT_POINT` | ✓ | yes | curve25519-dalek/src/constants.rs:L66-L66 |
| `curve25519_dalek.scalar.Scalar.ONE` | ✓ | no | curve25519-dalek/src/scalar.rs:L567-L572 |
| `curve25519_dalek.scalar.Scalar.ZERO` | ✓ | no | curve25519-dalek/src/scalar.rs:L564-L564 |

## Trait 实例（47 条）

| Lean 名 | spec | caller_anchored | 位置 |
|---|---|---|---|
| `curve25519_dalek.IdentityMontgomeryProjectivePoint.identity` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L297-L302 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAEdwardsPointEdwardsPoint.add` | ✓ | yes | curve25519-dalek/src/edwards.rs:L756-L758 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithMulSharedAScalarEdwardsPoint.mul` | ✓ | yes | curve25519-dalek/src/edwards.rs:L855-L857 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint.neg` | ✓ | no | curve25519-dalek/src/edwards.rs:L815-L822 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithSubSharedAEdwardsPointEdwardsPoint.sub` | ✓ | yes | curve25519-dalek/src/edwards.rs:L777-L779 |
| `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithAddSharedARistrettoPointRistrettoPoint.add` | ✓ | yes | curve25519-dalek/src/ristretto.rs:L890-L892 |
| `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithMulSharedAScalarRistrettoPoint.mul` | ✓ | no | curve25519-dalek/src/ristretto.rs:L969-L971 |
| `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithSubSharedARistrettoPointRistrettoPoint.sub` | ✓ | no | curve25519-dalek/src/ristretto.rs:L912-L914 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithAddSharedAScalarScalar.add` | ✓ | yes | curve25519-dalek/src/scalar.rs:L343-L347 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAEdwardsPointEdwardsPoint.mul` | ✓ | yes | curve25519-dalek/src/edwards.rs:L867-L869 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedARistrettoPointRistrettoPoint.mul` | ✓ | yes | curve25519-dalek/src/ristretto.rs:L978-L980 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithMulSharedAScalarScalar.mul` | ✓ | yes | curve25519-dalek/src/scalar.rs:L325-L327 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithNegScalar.neg` | ✓ | yes | curve25519-dalek/src/scalar.rs:L375-L379 |
| `curve25519_dalek.Shared0Scalar.Insts.CoreOpsArithSubSharedAScalarScalar.sub` | ✓ | yes | curve25519-dalek/src/scalar.rs:L363-L367 |
| `curve25519_dalek.Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint.mul` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L414-L451 |
| `curve25519_dalek.Shared1Scalar.Insts.CoreOpsArithMulShared0MontgomeryPointMontgomeryPoint.mul` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L463-L465 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | no | curve25519-dalek/src/edwards.rs:L393-L398 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | no | curve25519-dalek/src/edwards.rs:L175-L177 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCmpPartialEqEdwardsPoint.eq` | ✓ | no | curve25519-dalek/src/edwards.rs:L507-L509 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | yes | curve25519-dalek/src/edwards.rs:L421-L428 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ | yes | curve25519-dalek/src/edwards.rs:L479-L486 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | yes | curve25519-dalek/src/edwards.rs:L494-L503 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint.eq` | ✓ | no | curve25519-dalek/src/edwards/affine.rs:L48-L50 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | no | curve25519-dalek/src/edwards/affine.rs:L39-L44 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ | no | curve25519-dalek/src/edwards/affine.rs:L24-L29 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | yes | curve25519-dalek/src/edwards/affine.rs:L18-L20 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint.eq` | ✓ | no | curve25519-dalek/src/montgomery.rs:L94-L96 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulAssignShared0Scalar.mul_assign` | ✓ | no | curve25519-dalek/src/montgomery.rs:L455-L457 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | no | curve25519-dalek/src/montgomery.rs:L114-L116 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ | no | curve25519-dalek/src/montgomery.rs:L88-L90 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | yes | curve25519-dalek/src/montgomery.rs:L79-L84 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ | no | curve25519-dalek/src/montgomery.rs:L312-L321 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | no | curve25519-dalek/src/ristretto.rs:L346-L348 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | no | curve25519-dalek/src/ristretto.rs:L223-L225 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.eq` | ✓ | no | curve25519-dalek/src/ristretto.rs:L859-L861 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ | no | curve25519-dalek/src/ristretto.rs:L843-L845 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ | no | curve25519-dalek/src/ristretto.rs:L1192-L1198 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | yes | curve25519-dalek/src/ristretto.rs:L871-L878 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar.eq` | ✓ | no | curve25519-dalek/src/scalar.rs:L295-L297 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU128.from` | ✓ | no | curve25519-dalek/src/scalar.rs:L547-L552 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU16.from` | ✓ | no | curve25519-dalek/src/scalar.rs:L499-L504 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU32.from` | ✓ | no | curve25519-dalek/src/scalar.rs:L508-L513 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64.from` | ✓ | no | curve25519-dalek/src/scalar.rs:L538-L543 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU8.from` | ✓ | no | curve25519-dalek/src/scalar.rs:L491-L495 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignSharedAScalar.mul_assign` | ✓ | yes | curve25519-dalek/src/scalar.rs:L316-L318 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithNegScalar.neg` | ✓ | no | curve25519-dalek/src/scalar.rs:L384-L386 |
| `curve25519_dalek.scalar.Scalar.Insts.SubtleConstantTimeEq.ct_eq` | ✓ | yes | curve25519-dalek/src/scalar.rs:L301-L303 |

## 已抽取但无 spec 的公开函数（94 条）

- `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithNegRistrettoPoint` (curve25519-dalek/src/ristretto.rs:L943-L949)
- `curve25519_dalek.Shared0RistrettoPoint.Insts.CoreOpsArithNegRistrettoPoint.neg` (curve25519-dalek/src/ristretto.rs:L946-L948)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCloneClone` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCloneClone.clone` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpEq` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpEq.assert_receiver_is_total_eq` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpPartialEqCompressedEdwardsY` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpPartialEqCompressedEdwardsY.eq` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreDefaultDefault` (curve25519-dalek/src/edwards.rs:L401-L405)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/edwards.rs:L402-L404)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreMarkerCopy` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreMarkerStructuralPartialEq` (curve25519-dalek/src/edwards.rs:L171-L171)
- `curve25519_dalek.edwards.CompressedEdwardsY.to_bytes` (curve25519-dalek/src/edwards.rs:L193-L195)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCloneClone` (curve25519-dalek/src/edwards.rs:L379-L379)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCloneClone.clone` (curve25519-dalek/src/edwards.rs:L379-L379)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCmpEq` (curve25519-dalek/src/edwards.rs:L512-L512)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreDefaultDefault` (curve25519-dalek/src/edwards.rs:L431-L435)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/edwards.rs:L432-L434)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreMarkerCopy` (curve25519-dalek/src/edwards.rs:L379-L379)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddAssignSharedAEdwardsPoint` (curve25519-dalek/src/edwards.rs:L767-L771)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddAssignSharedAEdwardsPoint.add_assign` (curve25519-dalek/src/edwards.rs:L768-L770)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithMulAssignSharedAScalar` (curve25519-dalek/src/edwards.rs:L837-L842)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithMulAssignSharedAScalar.mul_assign` (curve25519-dalek/src/edwards.rs:L838-L841)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint` (curve25519-dalek/src/edwards.rs:L825-L831)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint.neg` (curve25519-dalek/src/edwards.rs:L828-L830)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithSubAssignSharedAEdwardsPoint` (curve25519-dalek/src/edwards.rs:L788-L792)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithSubAssignSharedAEdwardsPoint.sub_assign` (curve25519-dalek/src/edwards.rs:L789-L791)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.Curve25519_dalekTraitsValidityCheck` (curve25519-dalek/src/edwards.rs:L465-L472)
- `curve25519_dalek.edwards.EdwardsPoint.Insts.Curve25519_dalekTraitsValidityCheck.is_valid` (curve25519-dalek/src/edwards.rs:L466-L471)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCloneClone` (curve25519-dalek/src/edwards/affine.rs:L11-L11)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCloneClone.clone` (curve25519-dalek/src/edwards/affine.rs:L11-L11)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpEq` (curve25519-dalek/src/edwards/affine.rs:L53-L53)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreDefaultDefault` (curve25519-dalek/src/edwards/affine.rs:L32-L36)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/edwards/affine.rs:L33-L35)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreMarkerCopy` (curve25519-dalek/src/edwards/affine.rs:L11-L11)
- `curve25519_dalek.edwards.affine.AffinePoint.Insts.ZeroizeDefaultIsZeroes` (curve25519-dalek/src/edwards/affine.rs:L56-L56)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCloneClone` (curve25519-dalek/src/montgomery.rs:L73-L73)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCloneClone.clone` (curve25519-dalek/src/montgomery.rs:L73-L73)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpEq` (curve25519-dalek/src/montgomery.rs:L99-L99)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreDefaultDefault` (curve25519-dalek/src/montgomery.rs:L73-L73)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/montgomery.rs:L73-L73)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreMarkerCopy` (curve25519-dalek/src/montgomery.rs:L73-L73)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.ZeroizeZeroize` (curve25519-dalek/src/montgomery.rs:L120-L124)
- `curve25519_dalek.montgomery.MontgomeryPoint.Insts.ZeroizeZeroize.zeroize` (curve25519-dalek/src/montgomery.rs:L121-L123)
- `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreCloneClone` (curve25519-dalek/src/montgomery.rs:L289-L289)
- `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreCloneClone.clone` (curve25519-dalek/src/montgomery.rs:L289-L289)
- `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreDefaultDefault` (curve25519-dalek/src/montgomery.rs:L305-L309)
- `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/montgomery.rs:L306-L308)
- `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreMarkerCopy` (curve25519-dalek/src/montgomery.rs:L289-L289)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCloneClone` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCloneClone.clone` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpEq` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpEq.assert_receiver_is_total_eq` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpPartialEqCompressedRistretto` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpPartialEqCompressedRistretto.eq` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreDefaultDefault` (curve25519-dalek/src/ristretto.rs:L351-L355)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/ristretto.rs:L352-L354)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreMarkerCopy` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreMarkerStructuralPartialEq` (curve25519-dalek/src/ristretto.rs:L219-L219)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCloneClone` (curve25519-dalek/src/ristretto.rs:L493-L493)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCloneClone.clone` (curve25519-dalek/src/ristretto.rs:L493-L493)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCmpEq` (curve25519-dalek/src/ristretto.rs:L881-L881)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreDefaultDefault` (curve25519-dalek/src/ristretto.rs:L848-L852)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/ristretto.rs:L849-L851)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreMarkerCopy` (curve25519-dalek/src/ristretto.rs:L493-L493)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithAddAssignShared0RistrettoPoint` (curve25519-dalek/src/ristretto.rs:L901-L905)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithAddAssignShared0RistrettoPoint.add_assign` (curve25519-dalek/src/ristretto.rs:L902-L904)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithMulAssignSharedAScalar` (curve25519-dalek/src/ristretto.rs:L959-L964)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithMulAssignSharedAScalar.mul_assign` (curve25519-dalek/src/ristretto.rs:L960-L963)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithNegRistrettoPoint` (curve25519-dalek/src/ristretto.rs:L951-L957)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithNegRistrettoPoint.neg` (curve25519-dalek/src/ristretto.rs:L954-L956)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithSubAssignShared0RistrettoPoint` (curve25519-dalek/src/ristretto.rs:L923-L927)
- `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithSubAssignShared0RistrettoPoint.sub_assign` (curve25519-dalek/src/ristretto.rs:L924-L926)
- `curve25519_dalek.scalar.Scalar.Insts.CoreCloneClone` (curve25519-dalek/src/scalar.rs:L194-L194)
- `curve25519_dalek.scalar.Scalar.Insts.CoreCloneClone.clone` (curve25519-dalek/src/scalar.rs:L194-L194)
- `curve25519_dalek.scalar.Scalar.Insts.CoreCmpEq` (curve25519-dalek/src/scalar.rs:L293-L293)
- `curve25519_dalek.scalar.Scalar.Insts.CoreDefaultDefault` (curve25519-dalek/src/scalar.rs:L484-L488)
- `curve25519_dalek.scalar.Scalar.Insts.CoreDefaultDefault.default` (curve25519-dalek/src/scalar.rs:L485-L487)
- `curve25519_dalek.scalar.Scalar.Insts.CoreMarkerCopy` (curve25519-dalek/src/scalar.rs:L194-L194)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddAssignSharedAScalar` (curve25519-dalek/src/scalar.rs:L332-L336)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddAssignSharedAScalar.add_assign` (curve25519-dalek/src/scalar.rs:L333-L335)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAffinePointEdwardsPoint` (curve25519-dalek/src/edwards/affine.rs:L78-L85)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAffinePointEdwardsPoint.mul` (curve25519-dalek/src/edwards/affine.rs:L82-L84)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulShared0AffinePointEdwardsPoint` (curve25519-dalek/src/edwards/affine.rs:L87-L94)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulShared0AffinePointEdwardsPoint.mul` (curve25519-dalek/src/edwards/affine.rs:L91-L93)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubAssignSharedAScalar` (curve25519-dalek/src/scalar.rs:L352-L356)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubAssignSharedAScalar.sub_assign` (curve25519-dalek/src/scalar.rs:L353-L355)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsIndexIndexUsizeU8` (curve25519-dalek/src/scalar.rs:L306-L313)
- `curve25519_dalek.scalar.Scalar.Insts.CoreOpsIndexIndexUsizeU8.index` (curve25519-dalek/src/scalar.rs:L310-L312)
- `curve25519_dalek.scalar.Scalar.Insts.SubtleConditionallySelectable` (curve25519-dalek/src/scalar.rs:L389-L398)
- `curve25519_dalek.scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select` (curve25519-dalek/src/scalar.rs:L390-L397)
- `curve25519_dalek.scalar.Scalar.Insts.ZeroizeZeroize` (curve25519-dalek/src/scalar.rs:L556-L560)
- `curve25519_dalek.scalar.Scalar.Insts.ZeroizeZeroize.zeroize` (curve25519-dalek/src/scalar.rs:L557-L559)
- `curve25519_dalek.scalar.Scalar.batch_invert` (curve25519-dalek/src/scalar.rs:L788-L845)

## CryptoProver 清单交叉核对

| 模块 | 函数 | 状态 |
|---|---|---|
| edwards | `decompress` | in api-top |
| edwards | `compress` | in api-top |
| edwards | `to_montgomery` | in api-top |
| edwards | `mul_base` | in api-top |
| edwards | `mul_clamped` | in api-top |
| edwards | `mul_by_cofactor` | in api-top |
| edwards | `is_small_order` | in api-top |
| edwards | `is_torsion_free` | in api-top |
| edwards | `vartime_double_scalar_mul_basepoint` | not extracted |
| ristretto | `decompress` | in api-top |
| ristretto | `compress` | in api-top |
| ristretto | `from_uniform_bytes` | in api-top |
| ristretto | `hash_from_bytes` | not extracted |
| ristretto | `from_hash` | not extracted |
| ristretto | `double_and_compress_batch` | not extracted |
| ristretto | `random` | not extracted |
| ristretto | `mul_base` | in api-top |
| ristretto | `basepoint` | not extracted |
| montgomery | `to_edwards` | in api-top |
| montgomery | `as_affine` | in api-top |
| montgomery | `mul_base` | in api-top |
| montgomery | `mul_clamped` | in api-top |
| montgomery | `mul_bits_be` | not extracted |
| scalar | `from_bytes_mod_order` | in api-top |
| scalar | `from_bytes_mod_order_wide` | in api-top |
| scalar | `from_canonical_bytes` | in api-top |
| scalar | `invert` | in api-top |
| scalar | `batch_invert` | extracted, NO SPEC |
| scalar | `random` | not extracted |
| scalar | `hash_from_bytes` | not extracted |
| scalar | `from_hash` | not extracted |
