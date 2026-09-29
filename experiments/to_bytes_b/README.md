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
