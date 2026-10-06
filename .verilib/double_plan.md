# EdwardsPoint.double 依赖计划

目标：`curve25519_dalek.edwards.EdwardsPoint.double_spec`

待证明内部函数：**16**；可编辑文件：**10**（包括顶层规格）。

Math 已同步修复后的裁剪结果，保留 139/447 个 probe 声明。保留现有证明；此计划并不代表证明已经完成。

使用现有 probe 的函数调用图重新规划，未重新提取 probe。输入文件哈希保存在 `double_plan.json` 中。

## 按依赖顺序的待证明函数

1. `backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul.LOW_51_BIT_MASK` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Mul.lean`
2. `backend.serial.u64.field.MulShared0FieldElement51SharedAFieldElement51FieldElement51.mul.m` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Mul.lean`
3. `Shared0FieldElement51.Insts.CoreOpsArithMulSharedAFieldElement51FieldElement51.mul` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Mul.lean`
4. `backend.serial.curve_models.CompletedPoint.as_extended` — `Curve25519Dalek/Specs/Backend/Serial/CurveModels/CompletedPoint/AsExtended.lean`
5. `backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign_loop` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/AddAssign.lean`
6. `backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithAddAssignSharedAFieldElement51.add_assign` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/AddAssign.lean`
7. `Shared0FieldElement51.Insts.CoreOpsArithAddSharedAFieldElement51FieldElement51.add` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Add.lean`
8. `backend.serial.u64.field.FieldElement51.pow2k.LOW_51_BIT_MASK` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Pow2K.lean`
9. `backend.serial.u64.field.FieldElement51.pow2k.m` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Pow2K.lean`
10. `backend.serial.u64.field.FieldElement51.pow2k_loop` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Pow2K.lean`
11. `backend.serial.u64.field.FieldElement51.pow2k` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Pow2K.lean`
12. `backend.serial.u64.field.FieldElement51.square` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Square.lean`
13. `backend.serial.u64.field.FieldElement51.square2_loop` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Square2.lean`
14. `backend.serial.u64.field.FieldElement51.square2` — `Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/Square2.lean`
15. `backend.serial.curve_models.ProjectivePoint.double` — `Curve25519Dalek/Specs/Backend/Serial/CurveModels/ProjectivePoint/Double.lean`
16. `edwards.EdwardsPoint.as_projective` — `Curve25519Dalek/Specs/Edwards/EdwardsPoint/AsProjective.lean`

## 复用的已接受内部规格

- `curve25519_dalek.Shared0FieldElement51.Insts.CoreOpsArithSubSharedAFieldElement51FieldElement51.sub`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.reduce`
- `curve25519_dalek.backend.serial.u64.field.FieldElement51.reduce.LOW_51_BIT_MASK`

## 可用的顶层规格

无；此计划不跳过任何依赖来复用尚未证明的顶层规格。


## 重新生成预览

```bash
python harness/prove_top_spec.py --bottom-up --target curve25519_dalek.edwards.EdwardsPoint.double_spec --dry-run
```

## 验证

- 实际 bundle 的 `lake build` 通过（3385 jobs）。
- 79 个 Specs、证明登记表及根模块文件逐字节保持不变；6 个已接受内部证明全部保留。
- Math 代码与重新生成的裁剪结果一致（忽略注释和空行）。
