# 小步 Lean 检查工具

`harness/lean_check.py` 把一次 `lake build` 包装为可重复调用的检查：负责超时、进程清理、日志保存和结构化反馈。**什么时候检查仍由 prompt 指导模型决定；工具负责把每次检查执行好。**

## 手动使用

在项目根目录运行：

```bash
python3 harness/lean_check.py Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.ToBytes --timeout 120
```

检查独立 bundle 时，用 `--work /绝对路径/bundle` 指定含 `lakefile.toml` 或 `lakefile.lean` 的目录。模块参数使用点分名称，不是 `.lean` 文件路径。

完整构建：

```bash
python3 harness/lean_check.py --full --timeout 1200
```

完整构建也只是编译；statement 身份、修改范围、未完成证明等条件仍由原有 harness gate 独立验收。

## 返回结果

标准输出是一份 JSON；详细编译输出保存在 `log_path`，同一份 JSON 保存在 `result_path`。例如：

```json
{
  "status": "failure",
  "finished": true,
  "exit_code": 1,
  "elapsed_seconds": 1.2,
  "first_error": {
    "file": "Check.lean",
    "line": 12,
    "column": 4,
    "message": "unsolved goals",
    "diagnostic": "error: Check.lean:12:4: unsolved goals\n⊢ True"
  },
  "goal_text": "error: Check.lean:12:4: unsolved goals\n⊢ True",
  "acceptance_checked": false
}
```

上例省略了命令、日志路径和警告计数等字段。

参数错误会像普通 CLI 一样打印用法并返回 2。运行中若连日志目录都无法创建或结果无法保存，会返回 `error` JSON，并将日志路径设为 `null`，不声称日志已保存。

| `status` | 含义 | 工具退出码 |
| --- | --- | --- |
| `success` | Lake 正常退出且退出码为 0 | 0 |
| `failure` | Lake 已退出，但退出码非 0 | 1 |
| `timeout` | 到时未完成，已清理构建进程组 | 124 |
| `busy` | 同一工作区已有本工具启动的检查，本次没有启动编译 | 75 |
| `interrupted` | 收到终止信号或调用者消失，已清理构建进程组 | 130 |
| `error` | 启动等基础设施错误，见 `message` | 2 |

`exit_code` 是 Lake 子进程的原始退出码，与上表的工具退出码不同；未启动时为 `null`，被信号终止时通常为负数。`finished` 表示观察到编译自行结束，失败编译也可以为 `true`。判断结果应以 `status` 为准。无输出且退出码为 0 可以是成功的缓存构建；无输出但超时绝不是成功。

`first_error` 优先展示日志中首个错误及位置。首个错误来自依赖模块时也会保留；它可能正是目标无法编译的原因。`goal_text` 只提取这个错误中 Lean 实际打印的 `unsolved goals`，不是实时 goal 查询，可能为 `null`。诊断摘要有长度限制，完整内容请读日志。

超时只返回 `last_output`，并把 `timeout_declaration` 设为 `null`：普通 Lake 输出不足以可靠确定卡住的声明。`warning_count` 和 `sorry_warning_count` 统计本次日志中的警告，不是对整个项目的完整扫描；缓存构建可能不重新打印它们。`success` 不能证明没有 `sorry`，也不能证明修改范围符合要求。

## Harness 中的使用

通用 driver、bottom-up 和 `to_bytes` 实验共用 `agentproc.run_round()`，启动或恢复 agent 时会自动追加工具命令和使用规则，并为该命令添加 Bash 权限。不需要开启 MCP 或 skill。

- bwrap 沙箱只暴露检查器的独立副本，目录只读；原有 `harness/` 和 gate 代码仍隐藏。
- agent 的检查日志保存在本轮运行的 `local_checks/`，不会写入可编辑证明源码；手动调用默认保存到 `<workspace>/.lake/harness-checks/`。可通过 `--log-dir` 指定位置。
- 每轮保存实际发送的 prompt（`*.jsonl.prompt.txt`），并在 provenance 中记录工具哈希、有效 prompt 哈希、权限和日志位置。实验的原始 `prompt.txt` 是模板渲染结果，实际调用时还会追加工具说明。
- 工具使用 `<workspace>/.lake/harness-check.lock` 串行化检查。`busy` 应等待已有检查结束；不能通过直接运行 Lake 绕开。

工具通过独立监督进程监控调用者的存活；即使 agent/命令被 `SIGKILL`，监督进程仍会清理它启动的构建进程组并保存结果。超时和正常完成后也会清理遗留后台子进程。不终止其他工作区的构建。这里依赖 Linux/POSIX 的 `fork`、进程组和文件锁，与现有 bwrap harness 的平台一致。

锁只协调本工具启动的检查，不能阻止用户或模型另外执行原始 `lake build`。这版没有实现“每次编辑后强制检查”，也没有接入 LSP、声明级检查、tactic 多次尝试或 profiling。这些可在模块级反馈可靠之后再增加。

## 验证

```bash
python3 -m unittest discover -s harness/tests -v
```

`test_lean_check.py` 使用真实子进程验证状态、诊断、超时、并发拒绝、调用者被杀后的清理、正常完成后的后台子进程清理，以及 agent 入口和沙箱挂载配置；不调用模型 API。

2026-10-01 实现验证还使用项目固定版本 `leanprover/lean4:v4.28.0-rc1` 在临时 Lake 项目中检查了正确证明、未解决 goal 和 `sorry` 三种情况，并实际验证 bwrap 内的调用和工具只读挂载。没有启动新的模型证明实验。

全套测试存在两个已在修改前 HEAD 代码上复现的 seed 相关失败：`test_snapshot_writes_state_and_notes`（接口缺少 `rounds` 参数）和 `test_seeded_sorry_left_in_planned_file_is_rejected`（现有 gate 接受了测试期望拒绝的情形）。本次未修改这些接口或验收规则。
