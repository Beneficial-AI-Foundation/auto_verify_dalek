# dalek-top-spec-only 核对报告

- 日期：2026-09-15
- 对象：`dalek-top-spec-only/`（由 `harness/build_without_internal_spec.py --theorem-level --top-source .verilib/top_level_funs_probe.json` 生成）
- 目标：确认 bundle 实现正确，且 Specs 中只含 Funs.lean 里 top-level 函数的规格定理。
- probe 基线：`.verilib/top_level_funs_probe.json`，commit `99dfe74`，top-level 函数 134 个。

## 结论

**实现正确。** bundle 中 Specs 只剩 57 个定理，恰好对应 134 个 top-level 函数中已有规格的 57 个；证明全部替换为 `sorry`；语句与仓库原文逐字相同；`lake build` 通过。存在三处不影响正确性的小瑕疵，见文末。

## 核对项

| 项目 | 方法 | 结果 |
|---|---|---|
| 冻结代码 | `cmp` / `diff -rq` 逐文件比对 | Funs.lean、Types*.lean、Aux、FunsExternal、ExternallyVerified、Tactics、Math/、Utils/、lakefile、lake-manifest、lean-toolchain 全部与仓库相同；Curve25519Dalek.lean 只删除了 import 行 |
| Specs 文件集合 | 遍历 bundle Specs/ 与 manifest 比对 | 73 个文件 = 55 kept + 18 stub，与 `bundle_manifest.json` 一致；仓库其余 116 个 Specs 文件被丢弃 |
| 定理集合 | 任意缩进扫描 theorem/lemma/example，按 namespace 求全名 | 共 57 个，与白名单（probe lean_name 的命名空间 + functions.json `spec_statement` 定理名）完全相等，无多无少；stub 中 0 个定理；无 `mutual`、无缩进定理漏网 |
| 证明 | 深度感知解析顶层 `:=` | 57 个全部 `:= by sorry`；语句中 `let x := ...` 均位于 `⦃ ⦄` 内，未被误截 |
| 语句原文 | 仓库 vs bundle 逐定理比对（规范化空白） | 57/57 相同。Mul.lean 仓库有 4 个同名 `mul_spec`，保留的是 `montgomery.MontgomeryPoint.Insts.CoreOpsArithMulSharedBScalarMontgomeryPoint` 命名空间那个，正确 |
| top-level 函数存在性 | probe 134 个 lean_name 与 bundle Funs.lean 的 `def` 比对 | 134/134 均为 Funs.lean 中的定义，无一来自 FunsExternal |
| top-level 判定独立复核 | 用 Funs.lean 引用图重算"无调用者"集合 | 与 probe 差异仅两类：(a) 无方法的 marker 实例记录（`CoreMarkerCopy`、`CoreCmpEq` 等），probe 视为透明记录，正确；(b) `scalar.Scalar.as_bytes`，实际被 `Shared1MontgomeryPoint.Insts.CoreOpsArithMulShared0ScalarMontgomeryPoint.mul` 以点记法 `scalar.as_bytes` 调用（Funs.lean:5481），probe 正确 |
| 完整性 | 77 个"未 spec"top-level 函数在仓库 Specs 中搜 `*_spec` 定理 | 0 个命中，无被误删的 top-level 规格；probe `specified` 标志与 functions.json `spec_file` 完全一致 |
| 构建 | 在 bundle 目录 `lake build` | `Build completed successfully (3387 jobs)`；仅 `declaration uses sorry` 警告（含 TypesAux.lean 原有 2 个 sorry，仓库自带） |

## 保留的 57 个定理对应的函数

按文件见 `dalek-top-spec-only/bundle_manifest.json` 的 `kept_theorems`。分布：Scalar 15、MontgomeryPoint 10、EdwardsPoint 8、RistrettoPoint / CompressedRistretto 8、AffineNielsPoint 6、AffinePoint 2、其余（FieldElement51、Scalar52、ProjectivePoint、CompressedEdwardsY、elligator_encode）8。

## 小瑕疵（不影响正确性）

1. **9 个 stub 仅因 `attribute [-simp] ...` 行被保留。**
   `declares_vocab` 把 `attribute` 计为词汇。`attribute [-simp]` 是文件局部效果，对下游无意义。涉及：
   `Backend/Serial/U64/Scalar/M.lean`、`Scalar52/MulInternal.lean`、`Scalar52/SquareInternal.lean`、`Scalar52/ConditionalAddL.lean`、`Scalar52/ToBytes.lean`、`FieldElement51/Reduce.lean`、`FieldElement51/FromBytes.lean`、`Scalar/ClampInteger.lean` 等。

2. **stub 中大部分定义无人引用。**
   kept 语句真正用到的 stub 词汇只有 `SQRT_M1_raw`、`SQRT_M1_val`、`montgomery.ProjectivePoint.IsValid`。
   未被引用但仍出现在 bundle 中的有：`IsMont`（MontgomeryInvert）、`valid_ladder_state`（DifferentialAddAndDouble）、`bytes_match_limbs`（FieldElement51/ToBytes）、`Scalar52_partial_as_Nat`（Scalar52/Sub）、`Hold`（IsZero）、`sqrt_ratio_i_cases`（SqrtRatioi）、`SQRT_AD_MINUS_ONE_raw`、`pow2`（SquareMultiply），以及 `ElligatorRistrettoFlavor.lean` 中 8 个 `private structure Elligator*Posts / ElligatorLiftFacts`。
   这些是内部函数后置条件的描述性定义，虽非定理，但若要求严格"只含 top-level 内容"，应按引用裁剪。

3. **两个空 namespace 残留（纯美观）。**
   - `Specs/Backend/Serial/CurveModels/AffineNielsPoint/Eq.lean`：`curve25519_dalek.backend.serial.u64.field.FieldElement51.Insts.CoreCmpPartialEqFieldElement51`
   - `Specs/Montgomery/MontgomeryPoint/Mul.lean`：`curve25519_dalek.scalar.Scalar.Insts.CoreOpsArithMulMontgomeryPointMontgomeryPoint`

## 建议修改（`harness/build_without_internal_spec.py`）

- `declares_vocab`：忽略 `attribute [...]` 行（尤其 `attribute [-...]`），只把 def/abbrev/structure/instance/notation 等算作词汇。
- `filter_theorems` 之后：删除只剩 `namespace X ... end X` 且中间无声明的块。
- stub 生成：从 kept 文件语句出发做引用闭包，只保留被引用的定义；无引用的 stub 整体降级为 dropped（其 import 递归展开即可）。
