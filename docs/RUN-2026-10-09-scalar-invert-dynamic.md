# Scalar.invert 动态证明实验总结

实验 ID：`scalar_invert_dynamic_01`。实验日期：2026-10-09；总结日期：2026-10-10。

本次实验完成了 `Scalar.invert_spec` 的证明：动态证明图的 31 个节点全部 accepted，最终检查记录为 `verified: true`。顶层命题保持不变，其最终证明依赖中没有 `sorry`。实验包含多次局部修改和构建重试，但没有重新打开已经 accepted 的 internal spec。

## 目标与实验设置

固定的顶层目标是：

```text
curve25519_dalek.scalar.Scalar.invert_spec
```

令 `x` 为输入的 32 字节按小端解释的自然数，`y` 为返回值的字节对应的自然数，标量模数为：

```text
L = 2^252 + 27742317777372353535851937790883648493
```

顶层规格要求：当 `x % L ≠ 0` 时，调用 `invert` 成功，且 `x * y ≡ 1 (mod L)`。

实验在 `dalek-top-spec-only` 工作副本上运行。harness 识别出 30 个内部函数节点，由 worker 编写内部规格和证明，再完成固定的顶层目标。因此这里的“31 个 theorem”更准确地说是 **31 个证明图节点（30 个内部节点 + 1 个顶层节点）**；节点内还可以引入辅助引理，31 不是全部 Lean theorem 声明的数量。

主要证明链为：

```text
Scalar.unpack / Scalar52.from_bytes
  → Scalar52.invert
      → Montgomery 表示转换
      → Montgomery 乘法、平方、约减
      → square_multiply 与 montgomery_invert
      → 从 Montgomery 表示转换回来
  → Scalar.pack / Scalar52.to_bytes
  → Scalar.invert_spec
```

顶层证明利用内部规格组合出结论：`unpack` 保留输入数值并给出 limb 范围；`Scalar52.invert` 给出模逆关系和规范化范围；`pack` 将结果转回字节并保留所需的模关系。

## 结果与轮次口径

| 指标 | 结果 | 口径 |
| --- | ---: | --- |
| 证明图节点 | 31 | 全部 accepted |
| Worker attempt | 32 | `graph.json` 的 `attempts` |
| 执行 round | 35 | 所有事件的 `rounds` 数量之和，对应 35 个 JSONL trace |
| Harness turn | 592 | 所有 round 的 `assistant_turns` 之和，与日志统计一致 |
| 单个 round 最大 turn 数 | 65 | `from_bytes_loop` |
| 已接受规格的 revision | 0 | 所有节点的 `revisions` 均为 0 |
| Refinement | 0 | 所有节点的 `refinements` 均为 0 |
| 最终检查 | accepted | `final_gate.verified = true` |

**不是整次实验只跑了 2 round。** `r1`、`r2` 是每个 attempt 内的编号；本次单个 attempt 最多运行到 `r2`。每个 round 内仍有多次模型交互、文件编辑和 Lean 检查。

具体分布是：29 个节点各用 1 个 round；`from_bytes` 使用 2 个 round；`montgomery_reduce` 使用 2 个 attempt、共 4 个 round。合计为 `29 + 2 + 4 = 35` 个 round。

| 节点 | 执行结果 |
| --- | --- |
| `n4: from_bytes` | 第一次 attempt：`r1 rejected_build`，`r2 accepted` |
| `n17: montgomery_reduce` | 第一次 attempt：`r1 rejected_build`，`r2 rejected_build` |
| `n17: montgomery_reduce` | 第二次 attempt：`r1 rejected_no_spec`，`r2 accepted` |

失败记录包含 kernel/whnf 超时、语法和证明项问题。这些属于证明构造与执行重试，不能据此认定为 internal spec revision。

SDK 的 `result.num_turns` 与 harness 的 turn 不是同一口径，且部分 trace 缺少 result，因此本总结统一使用 harness 的 592 turn；不把 JSONL 中 assistant 消息片段数当成轮数。

## 证明检查的证据与边界

`graph.json` 中最终顶层声明的 `canon` 与初始声明一致，说明检查记录中的顶层命题没有被改弱。最终顶层声明记录为：

```text
axioms = [propext, Classical.choice, Quot.sound]
sorry_sources = []
```

这支持“该顶层证明没有依赖 sorry 或额外的自定义公理”的结论。末尾执行日志也记录了目标模块和全项目 `lake build` 成功。

这里没有声称整个仓库所有定理都已证明：其他无关模块仍可含有 `sorry`。另外，accepted 事件中的 `g2` 字段为 `skipped`，不应把本次结果描述为所有命名检查阶段都执行过。

## Internal spec 有没有被修复

需要区分两个层次：

1. **Worker 内部修改尚未接受的辅助命题：发生过。**
2. **调用者发现已接受的 internal spec 不够强，触发 harness 重新打开、加强规格并重证：没有发生。**

明确的局部修改出现在 `dag_scalar_invert_dynamic_01_15.r1.jsonl` 第 94–95 行。worker 为 `sub_loop_step_arith` 最初写了前提：

```lean
hy : y < 2 ^ 52 + 2
```

随后指出 `y = 2^52 + 1` 会使辅助引理不成立，并改成：

```lean
hy : y ≤ 2 ^ 52
```

trace 原文为：

> The helper's hypothesis was too weak (y = 2^52+1 breaks it); tightening it to `y ≤ 2^52`.

这是修正一个前提过弱、原本不成立的辅助引理。它发生在同一 worker 的局部证明过程中，不是将一个已证明但后置条件不足的 internal spec 加强后交给调用者。因此它不能作为跨节点 `needs_stronger_spec` / revision 流程成功运行的证据。

“没有 spec revision”也不意味着 AI 一次写对了全部规格和证明：35 个 round 内有 592 个 turn，以及多次修改和失败反馈。

## 网络访问与自动压缩

35 个 trace 中记录的工具调用如下：

| 工具 | 次数 |
| --- | ---: |
| Bash | 476 |
| Grep | 116 |
| Read | 44 |
| Edit | 57 |
| Glob | 3 |
| Write | 1 |

没有发现 `WebSearch`、`WebFetch`，此前对显式命令的检查也没有发现联网搜索或下载数据的尝试。这个结论限于可见 trace，不等同于底层网络流量审计。

没有发现实际发生自动压缩的 `compact_boundary` / `compact_metadata` 事件。运行元数据包含 compact recovery 的配置，这只表示配置了恢复机制，不能证明压缩发生过。592 个 turn 分布在多个 worker 执行中，并非一个连续上下文中的 592 轮对话。

## 实验意义与后续判断

本次结果支持：在固定顶层规格下，系统能够为这条标量求逆调用链生成可组合的内部规格和证明，并完成最终证明。

它尚未验证“已接受 internal spec 不足时自动修复”的跨节点流程，也不足以说明这种修复永远不需要。一个合理解释是：worker 能看到调用者需求，内部规格按当前证明目标设计，许多问题在 accepted 之前就被局部解决了。这是对实验现象的解释，不是经过对照实验确认的因果结论。

当前不必为了触发 revision 专门寻找更复杂的顶层定理。保留修复机制作为后备能力，继续评估真实目标的完成率、成本和证明可靠性更有价值；以后若在复用内部规格或多个调用者之间自然出现需求缺口，再分析该机制。

此前讨论的 `Scalar52.to_bytes` 任意字节 round-trip 只是一个新目标候选，不能算本次实验实际遇到的规格不足。它也不同于过去 `FieldElement51.as_bytes` 所调用的 `FieldElement51.to_bytes`；本次总结不将两者混为一谈。

## 产物与复核位置

- 实验状态：[graph.json](../ledger/runs/scalar_invert_dynamic_01/graph.json)。包含节点、attempt、round、声明检查快照与 final gate。
- 执行日志：[scalar_invert_dynamic_01.log](../ledger/runs/scalar_invert_dynamic_01.log)。
- Worker traces：`ledger/transcripts/dag_scalar_invert_dynamic_01_*.jsonl`，共 35 个。
- 局部辅助引理修改：[第 15 次 attempt 的 r1 trace](../ledger/transcripts/dag_scalar_invert_dynamic_01_15.r1.jsonl)。
- 证明保存分支：`exp/scalar_invert-dynamic-20261009T072112Z`。
- 保存提交：`835c44e` — `feat(proofs): preserve scalar inversion dynamic proof and internal specs`，包含 28 个文件的变更。

证明内容保存在上述提交中；查看 main 上的原始文件不能代替查看实验提交。ledger 链接指向本地实验记录，分享本总结时需要另外保留这些记录。
