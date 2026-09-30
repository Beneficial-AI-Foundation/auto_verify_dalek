# to_bytes: B 路线

一键启动：

```bash
bash harness/run_to_bytes_b.sh
```

默认使用现有实验配置中的 `claude-sonnet-5`，一轮 3600 秒、300 turns。
可直接修改 Bash 脚本顶部的参数。每次自动创建唯一结果目录，终端输出
同时保存为该目录下的 `run.log`；实验文件在 `attempt/` 中。

只测试通用证明方法提示，不比较 A/C，不提供具体的数学拆分路线。
固定完整 `to_bytes_spec`；保留已有 `reduce` 证明；移除目标文件中的
`bytes_match_limbs` 定义，不携带旧草稿，让模型自行选择辅助引理。

预览定理和完整提示词（默认行为，不调用模型）：

```bash
python3 harness/prove_to_bytes_b.py
```

准备独立副本并检查 harness 能选中固定目标（不调用模型，也不编译 Lean）：

```bash
python3 harness/prove_to_bytes_b.py --prepare-only \
  --run-dir /tmp/to_bytes_b_prepare_01
```

准备目录用于检查，不可再次作为运行目录；正式运行请指定新的目录。

显式启动一次实验（模型名替换为实际使用的模型）：

```bash
python3 harness/prove_to_bytes_b.py --run --model MODEL_ID \
  --run-dir ledger/runs/to_bytes_b_01
```

每次一轮、最多 3600 秒和 300 turns，另有 harness 的构建与验证时间。
每次必须指定新的目录；使用相同模型、参数和源码起点重复实验。
提示词在 `prompt.md`；入口会替换默认 PROOF_SKETCH，而不是叠加策略。

目录中保存完整提示词、源文件哈希、参数、独立 bundle 和 harness 工作目录。
成功只回写该次实验的 bundle，不回写仓库的 dalek-top-spec-only。
通过现有固定陈述、编译、sorry 和范围检查才算成功。
每次结果写入该目录的 `results.jsonl`，会话在 `transcripts/`，执行状态
在 `status.json`。常规拒绝会在回滚前保存失败草稿至
`run/partials/attempt-1/`。异常中断时也应检查 `run/slot0/work/`。
构建超时可用 `--build-timeout` 配置；相互比较的实验保持此值相同。

本地验证：入口测试 3 项、现有 joint loop 测试 7 项通过；隔离副本完整
`lake build` 通过（33.4 秒），目标文件恰有一个待填的 `sorry`。
尚未启动真实模型实验；基线编译通过不代表目标证明完成。

## 可选：复用成功交互证明的工作流程

原 B 提示词和默认行为保持不变。添加 `--interactive-prompt`，使用
`interactive_harness_prompt.txt`：它改编自 `interactive_debug_prompt.txt`，
保留小步编译、逐次诊断反馈、资源耗尽时拆分证明和清理上下文等要求，
不提供成功日志中的具体拆分或证明答案。分支和骨架准备由 harness 完成。

```bash
# 预览，不调用模型
python3 harness/prove_to_bytes_b.py --interactive-prompt

# 一键运行
bash harness/run_to_bytes_b.sh --interactive-prompt

# 自选模型、预算和独立目录
python3 harness/prove_to_bytes_b.py --interactive-prompt --run \
  --model MODEL_ID --run-dir ledger/runs/to_bytes_interactive_01
```

可与 `--fv-skills` 组合，但不会自动开启 FVS。该模式在 `experiment.json`
中记为 `B-interactive`，同时记录 `prompt_mode`、提示词来源和最终提示词哈希。
模型实际收到的提示词与保存的 `prompt.txt` 使用同一模板。

交互提示词要求本地构建 90 秒时报告、120 秒时终止并调整证明；这是给模型的
操作指令，不是新增的进程监控器。harness 验收构建仍由 `--build-timeout`
控制（默认 1200 秒），会话仍默认 3600 秒、300 turns，原验收检查保持不变。

## 实时进度

运行时默认在 round 内实时显示每个模型 turn 的简短文字、工具操作、返回耗时，
以及 Bash/构建输出的最多三条关键诊断（无错误时显示末尾三行）。长文本会截断，
不显示内部思考、完整文件内容或大段补丁；完整 stream-json 仍保存在 transcripts。
多个槽位/轮次的输出带 slot 和 round 前缀。工具执行期间先显示操作，结果在工具
返回后显示，不是逐字或逐行转播正在执行的 shell 输出。

`--quiet-turns` 可关闭摘要，Python 入口及 Bash 包装脚本均支持，例如：

```bash
bash harness/run_to_bytes_b.sh --interactive-prompt --quiet-turns
```

该开关只控制终端显示，不修改证明提示词、模型权限、资源预算或验收流程。
