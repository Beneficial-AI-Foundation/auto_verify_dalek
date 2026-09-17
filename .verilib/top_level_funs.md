# graph-top：Funs.lean 中不被其他抽取函数依赖的函数

来源: `functions.json`（557 行；剔除 200 个 trait 实例记录、19 个 `_loop` 体后 338 个候选）；共 **134** 条。
判定: 候选函数不被任何其他候选函数依赖。实例记录透传（含 supertrait 链），`P_loop` 的依赖记为 `P` 的依赖。
分类只按 Rust 源里 `fn` 行的可见性关键字，不判断是否为 API 入口；`模块` 列 = 所属模块是否由 lib.rs 导出（`pub` 但模块未导出 = backend 内部函数）。`external_lean_refs` = 手写 Lean（`Curve25519Dalek/FunsExternal.lean`, `Curve25519Dalek/Aux.lean`）中提到该函数或其实例记录的文件；本次 0 条非空（手写默认方法模型以实例记录为参数，抽取代码从未传入这些记录）。`rust_grep_hits` = crate 非测试源码中 `name(` 的出现次数（定义行除外），仅作交叉核对提示；按方法名匹配，同名方法（如 `CompletedPoint::as_extended` 与 `ProjectivePoint::as_extended`）会互相污染，高计数不等于有调用者。

## 固有方法，`pub`（25 条）

| Lean 名 | spec | 模块 | grep | 位置 |
|---|---|---|---|---|
| `curve25519_dalek.backend.serial.curve_models.ProjectivePoint.as_extended` | ✓ | backend | 33 | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L339-L346 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.as_bytes` | ✓ | backend | 20 | curve25519-dalek/src/backend/serial/u64/field.rs:L369-L371 |
| `curve25519_dalek.backend.serial.u64.scalar.Scalar52.square` | ✓ | backend | 38 | curve25519-dalek/src/backend/serial/u64/scalar.rs:L319-L322 |
| `curve25519_dalek.edwards.CompressedEdwardsY.to_bytes` |  | 导出 | 29 | curve25519-dalek/src/edwards.rs:L193-L195 |
| `curve25519_dalek.edwards.EdwardsPoint.compress` | ✓ | 导出 | 15 | curve25519-dalek/src/edwards.rs:L607-L609 |
| `curve25519_dalek.edwards.EdwardsPoint.is_small_order` | ✓ | 导出 | 2 | curve25519-dalek/src/edwards.rs:L1367-L1369 |
| `curve25519_dalek.edwards.EdwardsPoint.is_torsion_free` | ✓ | 导出 | 3 | curve25519-dalek/src/edwards.rs:L1397-L1399 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_base_clamped` | ✓ | 导出 | 0 | curve25519-dalek/src/edwards.rs:L907-L915 |
| `curve25519_dalek.edwards.EdwardsPoint.mul_clamped` | ✓ | 导出 | 0 | curve25519-dalek/src/edwards.rs:L891-L903 |
| `curve25519_dalek.montgomery.MontgomeryPoint.as_bytes` | ✓ | 导出 | 20 | curve25519-dalek/src/montgomery.rs:L199-L201 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_base_clamped` | ✓ | 导出 | 0 | curve25519-dalek/src/montgomery.rs:L150-L158 |
| `curve25519_dalek.montgomery.MontgomeryPoint.mul_clamped` | ✓ | 导出 | 0 | curve25519-dalek/src/montgomery.rs:L134-L146 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_bytes` | ✓ | 导出 | 29 | curve25519-dalek/src/montgomery.rs:L204-L206 |
| `curve25519_dalek.montgomery.MontgomeryPoint.to_edwards` | ✓ | 导出 | 4 | curve25519-dalek/src/montgomery.rs:L224-L253 |
| `curve25519_dalek.ristretto.CompressedRistretto.decompress` | ✓ | 导出 | 6 | curve25519-dalek/src/ristretto.rs:L257-L271 |
| `curve25519_dalek.ristretto.CompressedRistretto.to_bytes` | ✓ | 导出 | 29 | curve25519-dalek/src/ristretto.rs:L230-L232 |
| `curve25519_dalek.ristretto.RistrettoPoint.compress` | ✓ | 导出 | 15 | curve25519-dalek/src/ristretto.rs:L498-L542 |
| `curve25519_dalek.ristretto.RistrettoPoint.from_uniform_bytes` | ✓ | 导出 | 3 | curve25519-dalek/src/ristretto.rs:L823-L839 |
| `curve25519_dalek.ristretto.RistrettoPoint.mul_base` | ✓ | 导出 | 5 | curve25519-dalek/src/ristretto.rs:L988-L998 |
| `curve25519_dalek.scalar.Scalar.batch_invert` |  | 导出 | 4 | curve25519-dalek/src/scalar.rs:L788-L845 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order` | ✓ | 导出 | 3 | curve25519-dalek/src/scalar.rs:L237-L246 |
| `curve25519_dalek.scalar.Scalar.from_bytes_mod_order_wide` | ✓ | 导出 | 4 | curve25519-dalek/src/scalar.rs:L250-L252 |
| `curve25519_dalek.scalar.Scalar.from_canonical_bytes` | ✓ | 导出 | 5 | curve25519-dalek/src/scalar.rs:L261-L265 |
| `curve25519_dalek.scalar.Scalar.invert` | ✓ | 导出 | 18 | curve25519-dalek/src/scalar.rs:L747-L749 |
| `curve25519_dalek.scalar.Scalar.to_bytes` | ✓ | 导出 | 29 | curve25519-dalek/src/scalar.rs:L691-L693 |

## 固有方法，`pub(crate)`（6 条）

| Lean 名 | spec | 模块 | grep | 位置 |
|---|---|---|---|---|
| `curve25519_dalek.edwards.EdwardsPoint.as_affine_niels` | ✓ | 导出 | 6 | curve25519-dalek/src/edwards.rs:L543-L553 |
| `curve25519_dalek.edwards.EdwardsPoint.double` | ✓ | 导出 | 25 | curve25519-dalek/src/edwards.rs:L745-L747 |
| `curve25519_dalek.montgomery.elligator_encode` | ✓ | 导出 | 2 | curve25519-dalek/src/montgomery.rs:L263-L284 |
| `curve25519_dalek.scalar.Scalar.as_radix_2w` |  | 导出 | 3 | curve25519-dalek/src/scalar.rs:L1080-L1140 |
| `curve25519_dalek.scalar.Scalar.non_adjacent_form` |  | 导出 | 12 | curve25519-dalek/src/scalar.rs:L931-L983 |
| `curve25519_dalek.scalar.Scalar.to_radix_2w_size_hint` |  | 导出 | 2 | curve25519-dalek/src/scalar.rs:L1036-L1056 |

## 固有方法，私有（1 条）

| Lean 名 | spec | 模块 | grep | 位置 |
|---|---|---|---|---|
| `curve25519_dalek.ristretto.RistrettoPoint.coset4` |  | 导出 | 1 | curve25519-dalek/src/ristretto.rs:L659-L666 |

## trait 实现方法（65 条）

| Lean 名 | spec | 手写 Lean 引用 | 位置 |
|---|---|---|---|
| `curve25519_dalek.IdentityCurveModelsProjectivePoint.identity` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L231-L237 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithAddSharedAAffineNielsPointCompletedPoint.add` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L459-L473 |
| `curve25519_dalek.Shared0EdwardsPoint.Insts.CoreOpsArithSubSharedAAffineNielsPointCompletedPoint.sub` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L480-L494 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L182-L182 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L182-L182 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpPartialEqAffineNielsPoint.eq` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L182-L182 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L268-L270 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.CoreOpsArithNegAffineNielsPoint.neg` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L537-L539 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_assign` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L323-L327 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L315-L321 |
| `curve25519_dalek.backend.serial.curve_models.AffineNielsPoint.Insts.ZeroizeZeroize.zeroize` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L192-L196 |
| `curve25519_dalek.backend.serial.curve_models.CompletedPoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L167-L167 |
| `curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L252-L254 |
| `curve25519_dalek.backend.serial.curve_models.ProjectiveNielsPoint.Insts.ZeroizeZeroize.zeroize` |  |  | curve25519-dalek/src/backend/serial/curve_models/mod.rs:L215-L220 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/backend/serial/u64/field.rs:L42-L42 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithMulAssignSharedAFieldElement51.mul_assign` |  |  | curve25519-dalek/src/backend/serial/u64/field.rs:L107-L110 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithSubAssignSharedAFieldElement51.sub_assign` | ✓ |  | curve25519-dalek/src/backend/serial/u64/field.rs:L78-L81 |
| `curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.SubtleConditionallySelectable.conditional_swap` |  |  | curve25519-dalek/src/backend/serial/u64/field.rs:L242-L248 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/edwards.rs:L171-L171 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpEq.assert_receiver_is_total_eq` |  |  | curve25519-dalek/src/edwards.rs:L171-L171 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreCmpPartialEqCompressedEdwardsY.eq` |  |  | curve25519-dalek/src/edwards.rs:L171-L171 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreConvertTryFromShared0SliceU8TryFromSliceError.try_from` |  |  | curve25519-dalek/src/edwards.rs:L254-L256 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/edwards.rs:L402-L404 |
| `curve25519_dalek.edwards.CompressedEdwardsY.Insts.SubtleConstantTimeEq.ct_eq` | ✓ |  | curve25519-dalek/src/edwards.rs:L175-L177 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/edwards.rs:L379-L379 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreCmpPartialEqEdwardsPoint.eq` | ✓ |  | curve25519-dalek/src/edwards.rs:L507-L509 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/edwards.rs:L432-L434 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithNegEdwardsPoint.neg` |  |  | curve25519-dalek/src/edwards.rs:L828-L830 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.Curve25519_dalekTraitsValidityCheck.is_valid` |  |  | curve25519-dalek/src/edwards.rs:L466-L471 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/edwards/affine.rs:L11-L11 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint.eq` | ✓ |  | curve25519-dalek/src/edwards/affine.rs:L48-L50 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/edwards/affine.rs:L33-L35 |
| `curve25519_dalek.edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ |  | curve25519-dalek/src/edwards/affine.rs:L24-L29 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/montgomery.rs:L73-L73 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint.eq` | ✓ |  | curve25519-dalek/src/montgomery.rs:L94-L96 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/montgomery.rs:L73-L73 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.Curve25519_dalekTraitsIdentity.identity` | ✓ |  | curve25519-dalek/src/montgomery.rs:L114-L116 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ |  | curve25519-dalek/src/montgomery.rs:L88-L90 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.ZeroizeZeroize.zeroize` |  |  | curve25519-dalek/src/montgomery.rs:L121-L123 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/montgomery.rs:L289-L289 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/montgomery.rs:L306-L308 |
| `curve25519_dalek.montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ |  | curve25519-dalek/src/montgomery.rs:L312-L321 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/ristretto.rs:L219-L219 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpEq.assert_receiver_is_total_eq` |  |  | curve25519-dalek/src/ristretto.rs:L219-L219 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreCmpPartialEqCompressedRistretto.eq` |  |  | curve25519-dalek/src/ristretto.rs:L219-L219 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreConvertTryFromShared0SliceU8TryFromSliceError.try_from` |  |  | curve25519-dalek/src/ristretto.rs:L360-L362 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/ristretto.rs:L352-L354 |
| `curve25519_dalek.ristretto.CompressedRistretto.Insts.SubtleConstantTimeEq.ct_eq` | ✓ |  | curve25519-dalek/src/ristretto.rs:L223-L225 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/ristretto.rs:L493-L493 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.eq` | ✓ |  | curve25519-dalek/src/ristretto.rs:L859-L861 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/ristretto.rs:L849-L851 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithNegRistrettoPoint.neg` |  |  | curve25519-dalek/src/ristretto.rs:L954-L956 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select` | ✓ |  | curve25519-dalek/src/ristretto.rs:L1192-L1198 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreCloneClone.clone` |  |  | curve25519-dalek/src/scalar.rs:L194-L194 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreCmpPartialEqScalar.eq` | ✓ |  | curve25519-dalek/src/scalar.rs:L295-L297 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU128.from` | ✓ |  | curve25519-dalek/src/scalar.rs:L547-L552 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU16.from` | ✓ |  | curve25519-dalek/src/scalar.rs:L499-L504 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU32.from` | ✓ |  | curve25519-dalek/src/scalar.rs:L508-L513 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64.from` | ✓ |  | curve25519-dalek/src/scalar.rs:L538-L543 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU8.from` | ✓ |  | curve25519-dalek/src/scalar.rs:L491-L495 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreDefaultDefault.default` |  |  | curve25519-dalek/src/scalar.rs:L485-L487 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAffinePointEdwardsPoint.mul` |  |  | curve25519-dalek/src/edwards/affine.rs:L82-L84 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithNegScalar.neg` | ✓ |  | curve25519-dalek/src/scalar.rs:L384-L386 |
| `curve25519_dalek.scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select` |  |  | curve25519-dalek/src/scalar.rs:L390-L397 |
| `curve25519_dalek.scalar.Scalar.Insts.ZeroizeZeroize.zeroize` |  |  | curve25519-dalek/src/scalar.rs:L557-L559 |

## 运算符转发壳（macros.rs 生成）（37 条）

| Lean 名 | spec | 手写 Lean 引用 | 位置 |
|---|---|---|---|
| `curve25519_dalek.SharedAEdwardsPoint.Insts.CoreOpsArithAddEdwardsPointEdwardsPoint.add` |  |  | curve25519-dalek/src/macros.rs:L26-L28 |
| `curve25519_dalek.SharedAEdwardsPoint.Insts.CoreOpsArithSubEdwardsPointEdwardsPoint.sub` |  |  | curve25519-dalek/src/macros.rs:L63-L65 |
| `curve25519_dalek.SharedAMontgomeryPoint.Insts.CoreOpsArithMulScalarMontgomeryPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L100-L102 |
| `curve25519_dalek.SharedARistrettoPoint.Insts.CoreOpsArithAddRistrettoPointRistrettoPoint.add` |  |  | curve25519-dalek/src/macros.rs:L26-L28 |
| `curve25519_dalek.SharedARistrettoPoint.Insts.CoreOpsArithMulScalarRistrettoPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L100-L102 |
| `curve25519_dalek.SharedARistrettoPoint.Insts.CoreOpsArithSubRistrettoPointRistrettoPoint.sub` |  |  | curve25519-dalek/src/macros.rs:L63-L65 |
| `curve25519_dalek.SharedAScalar.Insts.CoreOpsArithAddScalarScalar.add` |  |  | curve25519-dalek/src/macros.rs:L26-L28 |
| `curve25519_dalek.SharedAScalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L100-L102 |
| `curve25519_dalek.SharedAScalar.Insts.CoreOpsArithMulScalarScalar.mul` | ✓ |  | curve25519-dalek/src/macros.rs:L100-L102 |
| `curve25519_dalek.SharedAScalar.Insts.CoreOpsArithSubScalarScalar.sub` |  |  | curve25519-dalek/src/macros.rs:L63-L65 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddAssignEdwardsPoint.add_assign` |  |  | curve25519-dalek/src/macros.rs:L44-L46 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithAddSharedBEdwardsPointEdwardsPoint.add` |  |  | curve25519-dalek/src/macros.rs:L19-L21 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithMulAssignScalar.mul_assign` |  |  | curve25519-dalek/src/macros.rs:L118-L120 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithSubAssignEdwardsPoint.sub_assign` |  |  | curve25519-dalek/src/macros.rs:L81-L83 |
| `curve25519_dalek.edwards.EdwardsPoint.Insts.CoreOpsArithSubSharedBEdwardsPointEdwardsPoint.sub` |  |  | curve25519-dalek/src/macros.rs:L56-L58 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulAssignScalar.mul_assign` |  |  | curve25519-dalek/src/macros.rs:L118-L120 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulScalarMontgomeryPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L107-L109 |
| `curve25519_dalek.montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint.mul` | ✓ |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithAddAssignRistrettoPoint.add_assign` |  |  | curve25519-dalek/src/macros.rs:L44-L46 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithAddSharedBRistrettoPointRistrettoPoint.add` |  |  | curve25519-dalek/src/macros.rs:L19-L21 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithMulAssignScalar.mul_assign` |  |  | curve25519-dalek/src/macros.rs:L118-L120 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithMulScalarRistrettoPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L107-L109 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithMulSharedBScalarRistrettoPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithSubAssignRistrettoPoint.sub_assign` |  |  | curve25519-dalek/src/macros.rs:L81-L83 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithSubRistrettoPointRistrettoPoint.sub` |  |  | curve25519-dalek/src/macros.rs:L70-L72 |
| `curve25519_dalek.ristretto.RistrettoPoint.Insts.CoreOpsArithSubSharedBRistrettoPointRistrettoPoint.sub` |  |  | curve25519-dalek/src/macros.rs:L56-L58 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddAssignScalar.add_assign` |  |  | curve25519-dalek/src/macros.rs:L44-L46 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithAddScalarScalar.add` |  |  | curve25519-dalek/src/macros.rs:L33-L35 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulAssignScalar.mul_assign` | ✓ |  | curve25519-dalek/src/macros.rs:L118-L120 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulRistrettoPointRistrettoPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L107-L109 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulScalarScalar.mul` | ✓ |  | curve25519-dalek/src/macros.rs:L107-L109 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBEdwardsPointEdwardsPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBMontgomeryPointMontgomeryPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBRistrettoPointRistrettoPoint.mul` |  |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulSharedBScalarScalar.mul` | ✓ |  | curve25519-dalek/src/macros.rs:L93-L95 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubAssignScalar.sub_assign` |  |  | curve25519-dalek/src/macros.rs:L81-L83 |
| `curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithSubScalarScalar.sub` |  |  | curve25519-dalek/src/macros.rs:L70-L72 |
