# 证明状态与恢复

现在除了保留会话、每轮诊断和代码，还会保存一份证明进度，供续跑或新会话接着工作。它记录模型正在处理的义务、报告完成的引理、剩余目标、失败路线和下一步，并把这些叙述与真实检查结果分开。

## 自动保存的内容

每个 `driver.run_rounds()` 任务在 transcripts 目录下创建独立的 `.proof-state-<任务>-<UUID>/`。通用 driver、bottom-up 和 `to_bytes` 都使用这个入口；每轮 ledger 的 `proof_state` 字段给出准确路径。

| 文件 | 内容 |
| --- | --- |
| `inputs.json` | 固定任务、源码修改范围、G1 statement 指纹、原始任务 prompt |
| `state.json` | 最新进度、源码与配置哈希、最近检查和 gate 结果、checkpoint 位置 |
| `state.md` | 同一份状态的可读恢复摘要 |
| `round-N.json` | 第 N 轮结束时的状态，保留历史 |
| `round-N-draft/files/` | 第 N 轮的可编辑源码草稿，即使编译失败也保存 |

模型在有意义的进展、失败尝试以及结束前，按 prompt 输出 `PROOF_STATE_JSON:` 加一个简短 JSON。harness 从 assistant 文本中提取，忽略工具输出和不完整 JSON，不需要模型在源码目录里写额外文件。记录在每轮结束后汇总；agent 因时限中断、来不及写最后总结时，也能利用此前已经输出的记录。若整个 harness 被强制杀掉，则只能保证此前写出的状态、原始 transcript 和小步检查产物保留，不能保证最后一轮已经汇总。

典型进度内容：

```json
{
  "current_node": "字节重建引理",
  "completed_nodes": [{"name": "carry_spec", "file": "Specs/ToBytes.lean"}],
  "remaining_goals": ["证明拼接的字节还原原始数值"],
  "failed_attempts": [{"approach": "直接 omega", "reason": "超时", "evidence": "对应检查日志路径"}],
  "next_check": "先拆出移位与取模的关系，再检查目标模块"
}
```

新记录更新当前进度；失败路线会去重累积，避免下一轮重新尝试同样的方法。模型若没有输出这些字段，harness 不会编造数学总结，但仍保存诊断和源码快照。

## 什么算“已检查”

`completed_nodes` 只是模型的报告。harness 只有找到同一任务、同一模块、对应源码版本的成功小步检查，且没有后续失败或 gate 矛盾时，才给节点标记 `module_compiled`。这意味着“节点所在模块的这个版本编译通过”，不是“这个引理的依赖闭包已经证明”。完整构建不会自动被用来推断任意节点所属模块均被检查。

带 `sorry` 的文件也可能编译成功。因此记录明确标注 `dependency_closure_checked: false`；最终接受与否仍来自原有独立 gate 和 accepted registry。这里没有实现第 7 节建议的声明级依赖闭包审计。

恢复前会重新计算项目 Lean 源码、`lakefile.toml` / `lakefile.lean`、`lake-manifest.json` 和 `lean-toolchain` 的哈希。文件、项目依赖源码或这些配置发生变化时，旧结果会显示为不匹配，不能继承原来的已检查标签。最近的失败诊断会随状态传给下一轮，不能被模型的完成声明覆盖。

这个哈希范围不包含 `.lake` 缓存、外部 package 的全部源码、外部工具链二进制或环境变量。它用于识别当前恢复记录是否过期，不是完整供应链审计；依赖固定版本、沙箱只读约束和独立 gate 仍然必要。

## 可恢复 checkpoint

小步检查工具现在会保存编译前后的输入哈希。只有编译成功、前后输入一致，并且所保存的源码字节与被检查版本一致时，才生成 `<检查ID>.checkpoint/files/` 和 `manifest.json`。harness 自动传入可编辑文件列表；无需改变源码 allowlist。

此后即使继续修改导致编译失败，最后一个通过编译的快照仍保留。它可能包含 `sorry`，也可能包含不在本次模块构建范围内的其他可编辑文件；manifest 会注明检查模块和证据范围。草稿快照、编译快照和正式接受结果是不同层次。

首次构建若创建或更新了 Lake manifest，前后配置哈希不同，不会生成编译快照；等配置稳定后再次检查即可。工具不会为了保存快照而改写工作区源码。

手动使用小步工具时，可指定要保留的源码：

```bash
python3 harness/lean_check.py Specs.ToBytes --snapshot-path Specs/ToBytes.lean
```

失败的 bottom-up / `to_bytes` partial 目录也会增加 `state.json`、`notes.md` 和 `proof-state.json`，复用现有 seed 的声明清单和诊断整理能力。清单是解析结果，不是独立验证证书；未出现在失败诊断中的文件也不会仅因此被标为编译通过。

## 如何恢复

同一任务的普通续跑和自动 reset 已自动带上摘要，不需额外参数。

### Claude Code 上下文压缩后的提醒

所有通过 `agentproc.run_round()` 启动的会话默认配置 `SessionStart` hook，匹配 `compact`。自动或手动压缩后，hook 通过 `additionalContext` 提醒 agent 使用 Read 重读本轮的 `workflow.md`、`round-context.md`，以及 prover 的 `lean-check.md`，再按其中引用查阅适用的 workflow/skill 文件。检查时机与证明策略仍由 agent 自主决定；不自动编译、不限制编辑，也不强制验证它确实完成了重读。

这些文件由 harness 在每次调用前生成，放在运行配置目录的 `local_check_tool/recovery-<UUID>/` 中；沙箱内该目录只读。内容分别来自本轮完整任务 prompt、实际继续消息（含已有状态交接）、检查工具说明。它们是本轮开始时的快照，不是实时进度；提醒明确要求结合本轮后续对话、源码和最新检查日志恢复，不能用旧摘要覆盖新进展。独立只读 reviewer 也有自己的任务恢复提醒，但没有 prover 检查说明。

生成的 settings 保留原 settings 的权限与 hooks，再追加压缩提醒；若显式设置 `disableAllHooks: true`，启动会报错，避免静默失效。每轮 provenance 的 `compact_recovery` 保存文件路径及哈希。运行时 hook 执行情况可查看 Claude Code debug 日志；provenance 记录配置，不代表模型已经重读。

此入口使用 Claude Code 的 [SessionStart(compact) hook](https://code.claude.com/docs/en/hooks#sessionstart)。本地验证覆盖配置合并、真实 hook 子进程输出和 harness 启动参数，未进行真实模型的长上下文压缩实验。

跨运行可以显式提供先前的 `state.json`，或者 partial 目录中的 `proof-state.json`：

```text
原有运行命令 ... --resume-proof-state /绝对路径/state.json
```

这个选项导入指定任务的进度记录，不自动覆盖当前源码。启动时检查目标、修改范围和原有 statement 是否兼容；新增加的 helper 不影响兼容性，但修改或删除原有 statement 会拒绝恢复。恢复的笔记不会修改 gate 输入或规则。

选项用于一个对应的目标任务：通用 driver 必须只选择一个目标；top-spec 支持单步或一个 joint 任务，不支持一次导入到多个 stepwise 步骤。`to_bytes` B 实验支持转发，但仍按原实验规则从固定 skeleton 开始，因此旧证明代码上的检查结果通常会显示过期。旧运行的日志／快照路径保留供操作者查阅，不会额外把旧运行目录暴露给新的 agent 沙箱。

如需回到某个源码快照，先查看其 `manifest.json` 确认范围，再将 `files/` 中所需源码恢复到相应工作区，并重新编译和验收；本实现不会自动回滚用户的当前代码。

## 验证

`harness/tests/test_proof_state.py` 覆盖中断后的笔记提取、源码与依赖变化后的失效、检查期间源码变化、不混入其他任务结果、保留最后编译快照、失败诊断优先、跨运行 statement 校验，以及续跑和 reset 的实际 prompt 接入。还使用项目固定 Lean 版本验证了真实 bwrap 内的编译快照、后续失败保留快照和检查器只读挂载。
