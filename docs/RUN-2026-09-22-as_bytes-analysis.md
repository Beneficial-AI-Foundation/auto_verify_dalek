# 2026-09-22 `FieldElement51.as_bytes_spec` 联合批次:失败分析

run: `ledger/runs/topspec_2026-09-22T083111+0000`,分支 `exp/top-spec-20260922-1631`
模型 claude-sonnet-5,joint 模式,3 轮 × 3600s,gate build_timeout 1200s。
最终判定 `rejected_kernel_budget`,0 commit。

## 目标与闭包

| 步骤 | 函数 | 文件 | 上游人工证明规模 |
|---|---|---|---|
| 1 | `reduce.LOW_51_BIT_MASK` | Reduce.lean | (含在下行) |
| 2 | `reduce` | Reduce.lean | 105 行,`maxHeartbeats 500000` |
| 3 | `to_bytes` | ToBytes.lean | 711 行,`maxHeartbeats 1600000`,10 个辅助 lemma |
| top | `as_bytes_spec` | AsBytes.lean | 33 行,`unfold as_bytes; step*` |

`to_bytes` 占闭包人工证明量约 85%。harness 只按依赖序排步骤(callee 先),
无难度估计;`docs/TOP-SPEC-RESULTS.md` 只评价了 `reduce`,未提 `to_bytes`。
结果是最难的一块排最后,只拿到剩余预算。

## 三轮做了什么

三轮共用同一 work 目录和同一 Claude session(`--resume`),不是独立尝试。
每轮结束(deadline kill)后 gate 跑一次,FEEDBACK 类拒绝则续下一轮。

| 轮 | 时间 (UTC) | 产出 | gate 结果 |
|---|---|---|---|
| r1 | 08:31–09:31 | Reduce.lean 完成(`LOW_51_BIT_MASK_spec`、`shiftRight51_spec`、`mask51_spec`、`reduce_spec`,0 sorry);ToBytes.lean 加 `cast_U8_spec`、5 个 `chunk*_eq`、桥接 lemma `bytes_match_limbs_as_Nat` | `rejected_sorry_remains`(build 28s) |
| r2 | 09:32–10:30 | `to_bytes_spec` 写完约 170 步 `progress as`,到 `massert` 前;结尾 `progress; sorry` | `rejected_build`(build 164s,末尾 omega 报 could not prove) |
| r3 | 10:34–11:33 | 补字节重组、删 `sorry`;遇 heartbeat 超时后把 `maxHeartbeats` 4000000 → 20000000 | `rejected_kernel_budget`(build 1200s 超时) |

r1 时间分配:探索 7 min,`reduce` 34 min(约 50 次 edit → build 循环),
桥接 lemma 16 min(32 变量一次 `omega` 超时,拆成 5 个 chunk lemma 后通过),
剩 3 min 未及写 `to_bytes_spec`。71 次 `lake build`,累计编译 11 min。

`as_bytes_spec` 三轮都没碰。

## 为什么 r3 的证明过不了

partials 里的 ToBytes.lean(458 行)文本上 0 sorry,但有三处从未被 Lean 验证通过,
前一处挡住后一处:

1. **`hUeqLimbs` 的 `omega` 超时。**
   直接原因:`omega` 使用整个上下文,此时约 400 条假设,其中大量含 `/`、`%`,
   每条都引入新变量。间接原因:`simp only [hs1..hs32]` 只把 `s32` 展开成 32 层嵌套
   `Array.set`,没有把 `((…).set k b)[j]!` 化简成 `b`,目标里剩 32 个不透明原子;
   即便不超时也证不出(r2 末尾的 counterexample 里
   `o_1 := ↑↑(↑((((Array.repeat 32 0).set 0 i40).set 1 i42)…` 就是这个症状)。
   Lean 的 `maxHeartbeats` 按整个 declaration 计,这一个 `omega` 把 170 步主定理
   的预算全部耗尽。
2. **最终 `≡ [MOD p]` 和 `< p` 两个目标从未被检查。**
   数学上需要从 10 个 `/ 2^51`、`% 2^51` 的进位链推出 `i34 / 2^51 = q4`
   (q4 ∈ {0,1}),再对 p 取模。线性可判定,但在满上下文里同样会炸,
   需要 `clear * -` 或拆成独立 lemma。
3. **`as_bytes_spec` 未写。** 上游只需 `unfold as_bytes; step*`,几分钟量级。

手工探测(已回滚,不计入 run):对 partials 的 `hUeqLimbs` 加
`clear * - chunk0 … hi38b` 后 `omega` 在 54s 内返回,不再超时,但报
could not prove,确认第 1 点的两个原因都成立;单独证
「32 次 `set` 的数组的 `U8x32_as_Nat` = 32 项和」作为独立 lemma 只需 4.5s,
说明拆 lemma 路线可行。

## 再加一轮能否做完

**按现状不会自动发生,且成功概率偏低(估计 3 成以内)。**

- `rejected_kernel_budget` 不在 driver 的 FEEDBACK 集合里,`run_rounds` 直接 break,
  注释写明「resuming would just make the agent try another blow-up」。
  `--rounds 5` 因此只跑了 3 轮。要续,得改策略或手动从 partials 重启。
- 剩余差距是「3 个未验证点 + 需要结构性拆分」,不是「差一行」。
- agent 行为不利:r3 对 heartbeat 超时的反应是调大 `maxHeartbeats`,没有复用 r1
  拆 chunk lemma 的经验;每次迭代 build 3–6 min,一轮只够 8–10 次;
  session 已续三轮,上下文很长;prompt 无「omega 用全部假设」类提示。
- 上游人工方案是 10 个辅助 lemma + 主定理,agent 现在是单个 300 行定理加末尾
  一次性 `omega`,结构差距大。

## 建议

1. 实现 PLAN-REVISE-LOOP 的 diagnose/recovery:把 gate 的错误行(文件:行号、
   超时类型)喂回下一轮 prompt,并提示「缩上下文 / 拆独立 lemma」。
2. `rejected_kernel_budget` 允许 resume 一次,附带诊断;仍超时再终止。
3. PROOF_SKETCH 补两条:`omega`/`scalar_tac` 会读取全部假设,大定理末尾先
   `clear * - …`;`maxHeartbeats` 按整条定理计,不要靠调大它解决单点超时。
4. 联合批次预算按人工证明规模加权(可用上游文件行数作代理),
   或让 harness 在 prompt 里标出「大函数」。
5. 每轮 gate 通过的中间成果(如 r1 的 Reduce.lean)单独 publish/commit,
   避免只靠 work 目录残留传递。
