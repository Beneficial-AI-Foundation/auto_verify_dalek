# 借鉴 LeanMarathon 改进 Lean 证明 harness

分析日期：2026-10-01。

本文基于本地 `/home/zhang-liao/LeanMarathon`、当前项目的 harness 实现，以及 `to_bytes` 实验记录。本文是设计分析，没有启动新的证明实验，也没有重新编译或审计已有成功证明。

## 结论

可以借鉴 LeanMarathon 的 prompt 和流程，但更适合当前项目的方案是：**保留现有隔离与验收机制，引入证明拆分、局部反馈和持久化状态，再逐步增加证明引理的依赖图。**

当前 harness 已有不少正确设计，包括 `--resume`、结构化构建反馈、失败 partial 保存、joint 多文件证明，以及小引理和缩小上下文的提示。主要缺口是把这些提示落实为可执行、可恢复的工作流程，而不只是继续增加 prompt 文本。

现有记录支持“harness 的反馈和过程管理有改进空间”，但不足以证明“证明困难主要由 harness 导致”。模型能力、提示词、代码版本和预算也影响结果。

## 1. `to_bytes` 实验提供的证据

| 实验 | 模型与提示 | 结果 | 关键现象 |
| --- | --- | --- | --- |
| 2026-09-29 | `claude-sonnet-5`，B prompt | `rejected_kernel_budget` | agent 跑满 3600 秒，验收构建再超时 1200 秒；记录到 heartbeat 提高到 100 万 |
| 2026-09-30 | `claude-opus-5-5`，interactive prompt | `accepted` | 74 turns，agent 用时 2217.9 秒，约 37 分钟 |

证据：

- [失败结果](../ledger/runs/to_bytes_b_20260929T105951Z_STVOfG/attempt/results.jsonl)
- [成功结果](../ledger/runs/to_bytes_b_20260930T061436Z_FvUNwN/attempt/results.jsonl)
- [成功证明](../ledger/runs/to_bytes_b_20260930T061436Z_FvUNwN/attempt/bundle/Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/ToBytes.lean)

失败会话中可以看到反复执行长时间构建、等待后台任务、轮询构建状态。部分预算消耗在编译过程管理和低效反馈上。

成功版本把证明拆成了以下部分：

- 进位算术，如 `to_bytes_div_chain`、`to_bytes_chain_eq`、`to_bytes_carry_arith`。
- 移位与掩码接口，如 `to_bytes_shr51_spec`、`to_bytes_mask51_spec`。
- 进位执行证明 `to_bytes_carry_spec`。
- 字节数值重建，如 `to_bytes_bytes_sum`、`to_bytes_U8x32_as_Nat_set`。
- 四段打包执行证明 `to_bytes_pack0_spec` 至 `to_bytes_pack3_spec`。
- 顶层 `to_bytes_spec` 组合上述结果，得到模同余和规范范围。

这说明执行推导、算术事实和表示转换之间存在有效的拆分边界。

但两次实验的模型、prompt 和代码版本不同，不能从这组结果单独推断 prompt 或 harness 的因果效果。另有实验结果为 `agent_error`，也不应混同于数学证明失败。

成功记录中 `g2` 为 `skipped`。因此本文所说的成功是“通过当时 harness 验收”，不代表已经重新完成传递依赖的信任审计。

## 2. 两套流程的主要差异

| 方面 | 当前项目 | 可借鉴的改变 |
| --- | --- | --- |
| 任务拆分 | bottom-up plan 主要根据函数调用关系生成 | 在函数层内部增加证明引理依赖图 |
| 证明规划 | 提示小步证明，由一个 session 自行维护结构 | 先形成可编译的引理接口与组合骨架 |
| 局部反馈 | 主要通过 shell 构建，round 结束后获得 gate 反馈 | 提供当前位置的 goal、诊断和慢声明定位 |
| 过程记忆 | transcript、round history、失败快照 | 增加当前节点、已验证事实、失败路线和下一步 |
| 失败处理 | 重试、reset、最终 rollback；也支持 joint 模式 | 区分证明搜索、接口、statement 与工具故障 |

当前项目的相关实现：

- [`build_plan()`、`PROOF_SKETCH` 与 joint 模式](../harness/prove_top_spec.py)
- [反馈、session 恢复与 gate](../harness/driver.py)
- [agent 工具与启动配置](../harness/agentproc.py)
- [interactive prompt](../experiments/to_bytes_b/interactive_harness_prompt.txt)
- [B 实验入口](../harness/prove_to_bytes_b.py)

## 3. 第一项结构性改进：区分函数调用图与证明依赖图

**函数调用图记录“代码调用了谁”；证明依赖图记录“证明需要哪些引理”。**

例如，`to_bytes` 调用了 `reduce`。当前 `build_plan()` 能据此安排先证明 `reduce_spec`，再证明 `to_bytes_spec`。这是按函数调用关系安排任务。

但有了 `reduce_spec`，`to_bytes` 的证明仍然很长：还要证明进位计算正确、移位和掩码得到正确的字节、这些字节组合出的数值满足最终要求。这些步骤可以写成辅助引理，**即使 Rust 代码没有把它们拆成单独的函数**。

证明依赖图就是把这些引理，以及“哪个引理用到哪个引理”的关系记录下来。例如，下面是一个简化的拆分示意：

```text
进位算术引理 ───────→ 进位执行正确 ──┐
移位、掩码引理 ─────→ 字节打包正确 ──┤
字节数值重建引理 ───────────────────┼→ to_bytes_spec
已有的 reduce_spec ────────────────┘
```

箭头表示右边的证明使用左边的结果。harness 可以先安排基础引理，再安排使用它们的证明；失败时也能知道卡在哪个小步骤。

**建议保留现有函数级计划，再把每个困难证明拆成可单独检查的引理任务：**

1. 让模型提出需要哪些辅助引理，并写清每条引理的假设和结论。
2. 检查这些引理是否能组合出原来的目标。
3. 按依赖顺序逐条证明，保存已检查的进展。
4. 组合成完整证明，再做最终验收。

第 2 步可以在隔离草稿中暂用 `sorry` 检查组合是否成立，但这不算证明完成；最终必须补齐所有证明。只拆分有帮助的步骤，不必把每一行推导都变成引理。

这借鉴了 LeanMarathon 的[拆分指南](/home/zhang-liao/LeanMarathon/agents/Blueprinter/docs/references/decomposition.md)：按照证明本身的结构选择辅助引理，而不是只按照程序中的函数边界划分任务。

## 4. 固定 Worker 目标，同时允许自主拆分

LeanMarathon 并不要求 Worker 永远遵守初始拆分。它允许在目标之前增加局部引理，但要求目标 statement 不变、新引理全部完成，并最终用于目标证明。

参考：[局部 refinement 合约](/home/zhang-liao/LeanMarathon/agents/Worker/docs/contracts/local-refinement.md)、[formalization 阶段](/home/zhang-liao/LeanMarathon/agents/Worker/docs/exec-phases/formalization/TASK.md)。

建议当前项目采用以下边界：

- 顶层 spec、生成代码和已有定义固定。
- 未接受的草稿辅助引理接口可以修订。
- 已接受的辅助引理优先保留，通过新增桥接引理或更强版本解决问题。
- Worker 遇到缺少方便的 helper 时先自行构造，不能直接认定目标不可证明。
- 发布前，目标和本次新增 helper 都必须完成。

需要特别注意，LeanMarathon 当前明确反对把普通困难转交为上游问题。[Worker 合约](/home/zhang-liao/LeanMarathon/agents/Worker/AGENTS.md)要求：不能仅因为 helper 缺失、不方便或不够强就提出上游修复；必须提供固定目标错误、缺失必要假设、输入无效或不可恢复工具故障等具体证据。

因此，当前项目的 spec-revision 机制需要区分：

| 情况 | 建议处理 |
| --- | --- |
| 当前 tactic 或拆分不合适 | 局部调整证明、缩小上下文 |
| 草稿 helper 的接口不适合组合 | 修订草稿接口并重新检查调用方 |
| 已接受 spec 缺少所需性质 | 优先新增性质或桥接引理，验证实际调用效果 |
| 固定目标疑似错误 | 保存具体证据，不擅自修改目标 |
| 构建、进程或环境故障 | 基础设施恢复，不消耗数学接口修订预算 |

已有 [PLAN-REVISE-LOOP-REVIEW.md](PLAN-REVISE-LOOP-REVIEW.md) 中关于 additive revision、证据传递和事务语义的讨论仍然有用。不过判断现状应以代码为准：例如当前 driver 已有构建错误尾部和结构化诊断，不能把旧评审中的全部缺口视为仍未实现。

## 5. 把小步反馈落实为工具能力

我们与 LeanMarathon 都通过 prompt 指导模型何时检查。可以借鉴的是：给模型方便、可靠的反馈工具，减少它自己管理编译进程的工作。不能把 LeanMarathon 使用 LSP 工具理解为“每次编辑后自动强制检查”。

第一步现已实现：[小步检查工具](LEAN-CHECK.md)，入口为 `harness/lean_check.py`。它仍然执行 `lake build`，但统一负责超时、日志和子进程清理，返回明确的成功、失败、超时、繁忙或中断状态，以及耗时、首个错误和日志路径。agent 启动及恢复时会自动获得工具命令；检查器在 bwrap 沙箱中只读可见。

写证明时，用它检查当前修改的模块，及时发现错误。全部完成后，运行完整构建，再由 harness 独立验收。局部编译通过不能代替最终验收：带 `sorry` 的文件也可能编译通过，完整构建本身也不检查固定目标是否被改动。

每次检查必须根据实际退出状态判断。没有错误输出可能是成功的缓存构建，也可能是进程还在运行或已超时。工具明确区分这些结果，不能把“没有看到错误”当作“已经通过”。

这一版只提供模块级编译反馈。`goal_text` 只来自编译器实际打印的未解决目标；超时返回最后一条日志，不能可靠定位声明时明确返回空值，不猜测。完整日志保留，便于继续排查。

LeanMarathon 使用 Lean LSP 的 diagnostics、goal、multi-attempt 和 profiling 能力。我们当前仍没有接入这些服务；统一编译包装是本项目的实现选择，不是对 LeanMarathon 已有超时和日志接口的复刻。

后续可接入受控 Lean LSP，增加实时 goal 和声明级诊断，再按需要增加 tactic 尝试和性能定位。

库检索可以继续使用本地固定版本的 Aeneas 与 Mathlib 源码，不必复制 LeanMarathon 的专用检索服务约束。接入工具时需要同时检查 sandbox 可见性和依赖版本一致性。

## 6. 保存证明状态，而不只保存会话

当前 reset 保留文件，并附上 round outcome 与诊断历史，这是已有优势。但新 session 仍可能不知道哪些 helper 已独立检查、当前具体义务是什么、哪些路线失败过，以及最后一个可编译版本在哪里。

LeanMarathon 用 `inputs.yml` 和 `state.md` 处理恢复，并明确规定状态文档不能推翻 Lean 实际诊断。

建议增加小型结构化状态，至少记录：

```text
固定目标与 statement 指纹
当前证明节点
已验证节点及对应文件哈希
剩余 goal
已失败的方法及证据
下一项具体检查
最后一个可恢复 checkpoint
```

恢复时先检查文件版本与诊断是否匹配，再使用状态摘要。若文件已经改变，不能直接继承先前的“已验证”标签。

这需要同步修改 allowlist 与 sandbox：当前单文件任务通常禁止创建其他文件，无法直接承载可写状态文档。可以为状态文件单独授权，或由 harness 根据结构化结果写入；它不能获得修改验收输入的权限。

失败 partial 应继续保存，并增加可恢复 checkpoint。必须区分：

- **草稿快照**：保留探索，不表示证明正确。
- **已检查节点**：记录声明、检查环境和依赖条件。
- **正式接受成果**：通过完整约束后才能进入 accepted registry。

尤其不能把依赖未证明草稿的 helper 标记为无条件完成。

## 7. 将验收粒度推进到声明及其依赖

若开始按引理节点调度，就不能只依靠整个文件的 `sorry` warning 数量。

建议为每个节点记录准确 Lean 名称，并检查：

1. 指定目标确实完成。
2. 本次新增 helper 不含未允许的未证明依赖。
3. 原有目标 statement 未变。
4. 最终证明的传递依赖中，哪些已验证，哪些属于预先允许的信任基础。

当前 benchmark 包含大量既有 `sorry`。一段没有直接写 `sorry` 的 proof，仍可能引用带 `sorry` 的其他定理。应接入已有 G2 思路，并明确区分“相对于给定依赖完成”和“依赖闭包完整证明”。

节点状态应由机器检查结果驱动。模型报告 COMPLETE、文件编译通过、以及目标依赖闭包完成，是三个不同层次的证据。

## 8. 不宜直接照搬的部分

### 自然语言证明源

LeanMarathon 的输入包含自然语言证明源，而本项目主要输入是固定 spec、Rust/Aeneas 实现和已有库。这里的规划阶段应从代码和目标生成候选证明结构，不能假设已有完整数学证明。

### 重型编排与交付

Slurm、GitHub issue/PR 循环、LaTeX blueprint 格式和论文级文字润色都不是当前主要瓶颈。可以先由同一个 agent 分阶段执行，验证收益后再考虑更多调度机制。

### 信任策略

LeanMarathon 禁止 `native_decide`，当前 harness 允许。这是独立的信任策略选择，不应为了模仿流程而未经评估地改变。实验比较时必须固定并报告这类验收规则。

## 9. 推荐的最小 Worker 提示契约

以下是建议的新契约，不是已经实现的工具接口。启用前必须先配置相应状态文件权限、检查工具和节点验收。

```text
你的任务是证明指定的固定 Lean 声明。

先读取目标 statement、相关实现、允许使用的依赖和当前状态。
给出简短证明路线；对困难部分提出具有明确输入输出的辅助引理。
区分执行推导、数学事实和表示转换，检查这些接口能组合到原目标。

一次推进一个局部义务，使用提供的检查入口获取反馈。
记录已验证事实、当前 goal、失败方法及下一步。
遇到超时先定位并缩小义务，不通过提高资源限制掩盖问题。

允许在授权范围内增加辅助引理；不能修改固定目标或生成代码。
缺少方便的 helper 时先尝试局部构造。
只有具体证据表明 statement、输入或工具存在缺陷时，才报告阻碍。

临时 proof hole 必须登记。最终目标和新增 helper 全部完成后，
执行完整构建及独立验收。只有机器检查通过才能报告接受。
预算耗尽时保存草稿、准确剩余 goal 和可恢复状态。
```

## 10. 实施顺序与评估方法

### 第一阶段：反馈和恢复

- 增加统一局部检查入口与进程管理。
- 增加结构化状态和 checkpoint。
- 开放 B 入口的 round 数配置。该入口目前硬编码一轮，无法在后续 round 使用现有 gate 反馈恢复机制。
- 明确总预算：增加 round 不能默默扩大总时间或费用预算。

### 第二阶段：轻量证明节点

- 用简单 manifest 登记 helper 的 statement、依赖和状态。
- 增加接口与顶层组合检查。
- 按依赖就绪顺序证明节点，允许草稿局部修订。
- 增加声明级验收及依赖信任检查。
- 暂不要求引入完整 LeanArchitect 或多 agent 编排。

### 第三阶段：受控实验

在固定模型、源码起点、依赖、总预算和验收规则的前提下，比较：

| 变体 | 改变 |
| --- | --- |
| 原 B | 保留当前基线 |
| Interactive | 使用现有小步反馈 prompt |
| 分阶段节点流程 | 加入检查工具、状态恢复和证明节点 |

统计完整成功率、编译等待时间、重复失败次数、总成本和最终验证时间。工具故障与数学证明失败分开统计。规划和检查所消耗的预算也应计入总成本。

对 `to_bytes`，可以用“执行证明／进位算术／字节表示转换”作为复盘得到的参考结构。但评测时必须分开记录：

- 人工提供拆分结构。
- 模型从相同初始材料自行发现拆分结构。

否则会把已知成功证明结构的帮助误算成 harness 改进。

优先落地第一阶段，再加入证明引理 DAG。现有 interactive 工作流已经具备合适的方向，最直接的收益来自让它可靠执行、保留进展并在失败后准确恢复。

## 参考文件

LeanMarathon 链接指向当前机器上的本地 checkout，不保证在其他环境中可用；实验记录也可能不随 Git 仓库分发。

- [LeanMarathon README](/home/zhang-liao/LeanMarathon/README.md)
- [Worker 合约](/home/zhang-liao/LeanMarathon/agents/Worker/AGENTS.md)
- [Blueprinter 拆分指南](/home/zhang-liao/LeanMarathon/agents/Blueprinter/docs/references/decomposition.md)
- [局部 refinement 合约](/home/zhang-liao/LeanMarathon/agents/Worker/docs/contracts/local-refinement.md)
- [Formalization 阶段](/home/zhang-liao/LeanMarathon/agents/Worker/docs/exec-phases/formalization/TASK.md)
- [按节点调度实现](/home/zhang-liao/LeanMarathon/.scripts/per_node_worker_loop.py)
- [Blueprint 验证实现](/home/zhang-liao/LeanMarathon/.scripts/verify_blueprint.py)
- [当前 top-spec harness](../harness/prove_top_spec.py)
- [当前 driver](../harness/driver.py)
- [当前 agent 启动实现](../harness/agentproc.py)
- [to_bytes B 实验说明](../experiments/to_bytes_b/README.md)
- [to_bytes interactive prompt](../experiments/to_bytes_b/interactive_harness_prompt.txt)
- [既有 revision 设计评审](PLAN-REVISE-LOOP-REVIEW.md)
