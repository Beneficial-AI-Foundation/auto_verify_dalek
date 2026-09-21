# Review: `PLAN-REVISE-LOOP.md`

审阅对象：[PLAN-REVISE-LOOP.md](PLAN-REVISE-LOOP.md)。

结论：计划的总体方向合理。把失败区分为“下层 spec 太弱”“当前步骤
自己选择的 statement 有误”和“证明搜索困难”，比失败后盲目重试更有针对性；
诊断 session、修订 session 和预算上限的划分也比较清楚。不过，当前版本在状态
模型、sandbox 可见性和 G1 豁免校验方面仍有实质性缺口，不宜直接照此实现。

## 必须先解决的问题

### 1. 第一个步骤无法纠正自己的 statement

主循环规定 `i == 0` 时直接失败，不进入诊断；但后文又规定 spec 步骤收到
`own_statement` verdict 后可以直接重跑。两者互相矛盾。

第一个叶子 spec 虽然没有可归因的 lower spec，仍然可能自己选择了错误的
statement。建议允许第一个步骤进入诊断，但在该步骤没有可用下层 spec 时，
确定性校验必须拒绝 `lower_spec` verdict；`own_statement` 和
`proof_difficulty` 仍可正常处理。

### 2. 无法修订以前运行中留下的 internal spec

当前 `build_plan()` 会跳过 `internal_specs.json` 中已经接受的函数，因此这些
函数不在本次 `steps` 中。计划却通过下面的方式寻找修订目标：

```text
j = step index of diag.revise[0].fn
run_revise(steps[j], diag)
```

如果真正太弱的 spec 来自以前一次计划，它有 registry 条目，但没有本次计划的
step index，算法就无法执行。这是实际运行中很可能出现的情况。

建议让修订目标直接来自 accepted-spec registry，例如
`{fn, path, theorems, pp}`，不要要求它一定对应本次 `steps[j]`。本次计划中已经
完成的步骤和以前运行留下的 spec 应使用同一种定位方式。

### 3. partial 文件在默认 sandbox 中可能不可读

计划把失败文件保存到 `run_dir/step<i>.partial.lean`，然后把路径交给诊断和重试
agent。当前 bwrap 配置只显式暴露 slot workspace 和配置目录，并会隐藏
`ledger/`；而 `run_dir` 位于 `ledger/` 下。因此，仅把该路径写进 prompt 并不能
保证 agent 能够读取它。

可选修正方案：

- 把对应 partial 文件作为额外只读路径挂载进 sandbox；或
- 在 slot 中建立只读的 evidence 目录并复制进去；或
- 将必要的 partial 内容直接嵌入诊断 prompt。

同时需要避免 evidence 文件被 agent 修改，不能简单地复制到普通可写目标路径后
就把它当作可信证据。

### 4. `theorem` 字段缺少确定性校验，可能错误放宽 G1

诊断 JSON 同时返回 `fn` 和 `theorem`，但当前验证规则主要验证 `fn` 是否为已接受
的 internal spec，随后却直接按诊断结果中的 theorem 名放宽 G1。如果诊断器误报
了同一文件中的另一个 theorem，就可能允许修改本应固定的声明。

在把名字传给 `g1_exempt` 前，建议确定性验证：

- `theorem` 使用完整限定名；
- 它属于该 `fn` 在 registry 中记录的 accepted theorem 集合；
- 它在当前 module fingerprint 中仍然存在；
- 它的 statement 确实引用目标函数；
- exemption 只能来自验证后的集合，不能直接使用模型输出。

如果采用新增 theorem 的 additive revision，则新增名字不需要 G1 exemption，因为
G1 本来就允许新增声明。

## 应在实现前明确的问题

### 5. additive revision 的结果识别和元数据更新不完整

计划允许保留旧 theorem、增加一个更强的 `@[progress]` theorem，但后续记录仍按
“某个 theorem 被修改”以及单个 `old_pp/new_pp` 处理。新增模式下，诊断器提供的
旧 theorem 并没有改变，新 theorem 的名字通常也无法预先知道。

建议 revision gate 明确返回：

```text
result_specs     当前文件中关于该函数的全部 @[progress] theorem
added_specs      本次新增的相关 theorem
changed_specs    本次获准修改的相关 theorem
selected_spec    推荐调用者使用的 theorem
```

接受 revision 后，应重新生成该函数完整的 `theorems` 和 `pp` 映射，而不是只追加
一个含义不清楚的 `old_pp/new_pp`。重试提示也应引用 `selected_spec` 的真实名称和
statement。

### 6. 应使用“可诊断失败白名单”，而不是不完整的 policy 黑名单

计划描述为：除 scope、forbidden attribute、migration、kernel budget 等 policy
violation 外，其余失败都可以诊断。但实际失败还包括：

- agent 进程或 transcript 错误；
- G1 fingerprint 失败；
- 原有 statement 被违规修改；
- sandbox 或构建基础设施故障；
- 尚未形成任何可解析 statement 的语法错误。

这些情况不能可靠地归因于 lower spec。建议明确列出允许进入语义诊断的 outcome，
例如正常 agent session 结束后的 `rejected_build`、`rejected_sorry_remains`，以及
带有有效 partial 文件的 `END_REASON:LIMIT`。基础设施错误和完整性违规应直接停止，
不消耗 revision budget，也不调用诊断模型。

### 7. 需要真正保存 build error tail

诊断输入要求包含 `rejected_build` 的 build error tail，但当前 `driver.gate()` 对
构建失败主要返回构建耗时，并没有把 stdout/stderr tail 放入 detail。仅解析
`broken_files` 也不足以说明 Lean 目标或类型不匹配的具体原因。

建议让构建接口在失败时返回有长度上限的、经过稳定截断的错误文本，并同时解析：

- 报错文件；
- 行列位置；
- 主要 Lean 错误消息；
- 是否能确认错误属于目标文件或其依赖文件。

这些内容既供诊断 prompt 使用，也应写入 ledger。

### 8. partial artifact 应按 attempt 唯一命名

固定使用 `step<i>.partial.lean` 会导致同一步后续重试覆盖先前证据，历史 ledger 因而
无法复现。

建议文件名至少包含 plan step 和 attempt，例如：

```text
step-003.attempt-02.partial.lean
```

文件写入后应保持不可变；ledger 记录相对路径和 SHA-256。

### 9. gate 没有证明 revision 真的是“strengthening”

G1 exemption 只能允许 statement 改变，无法证明新 statement 逻辑上强于旧
statement。agent 可能把它换成一个更弱、不可比但容易证明的 statement。

v1 更稳妥的策略是默认只允许 additive revision：保留原 theorem，再新增更强的
theorem。这样不会破坏旧调用者，也无需放宽旧 theorem 的 G1 identity。

如果仍允许原地修改，应在设计中明确说明“strengthening 只由 agent 意图保证，
没有机器验证”，并把它作为实验风险统计。也可以要求新 theorem 同时推出旧
postcondition，但自动构造和验证这一关系会增加实现复杂度。

### 10. revision 的持久化时机需要事务语义

计划在 revision accepted 后立即 copy back 并更新 registry，然后才重试失败步骤。
如果调用者依然失败，本次计划会停止，但 revision 已永久保留。对于原地修改，
这可能留下一个并未解决问题、甚至质量更差的 spec。

需要明确选择一种语义：

- revision 自身通过 gate 就视为独立成果，失败计划也保留；或
- revision 与调用者重试构成一个事务，只有调用者成功后才一起发布。

若选择第一种，建议 v1 只允许 additive revision，并在 ledger 中标记该 revision
最终是否被成功调用者验证过。

## 其他建议

### 11. “同一步再次选择同一 spec”不一定是 ping-pong

同一个 lower spec 可能需要两次逐步增强。当前规则只要再次选择它就终止，并命名为
`revise_pingpong`，但这并不一定发生了来回摆动。可以保留这一保守上限，不过更准确
的 outcome 名称是 `repeated_revision_target`，并记录两次缺失属性是否相同。

### 12. `--max-revisions` 的名称与实际计数不一致

该参数实际统计所有 diagnose cycle，包括没有执行 revision 的
`own_statement`、`proof_difficulty` 和无效诊断。更准确的名称可以是
`--max-diagnoses` 或 `--max-recovery-cycles`；或者分别维护 diagnosis 与实际
revision 的计数。

### 13. `progress` theorem 的选择必须在 v1 实现前验证

原计划已经指出，同一函数存在两个 `@[progress]` theorem 时，Aeneas 是否会选择
预期 theorem 尚不确定。由于 additive revision 很可能依赖这一行为，这不是普通的
后续优化，而是 v1 的前置验证项。

如果选择不可控，可以考虑：

- 只给新 theorem 加 `@[progress]`，旧 theorem 保留但移除属性；
- 在不改变 statement identity 的前提下显式管理 attribute；
- 或让调用者直接引用所选 theorem，而不依赖自动 progress 搜索。

需要同时确认 G1 fingerprint 是否记录 attribute；如果不记录，attribute 变化应由
额外 gate 检查约束。

## 建议补充的测试

除原计划已有测试外，至少增加以下场景：

1. 第一个 spec 步骤返回 `own_statement`，能够成功重试。
2. 下层 spec 来自以前运行的 `internal_specs.json`，不在本次 `steps` 中。
3. 诊断器返回同文件中不属于目标函数的 theorem，校验必须拒绝。
4. partial 文件在默认 bwrap sandbox 中确实可读，但不可写。
5. 同一步多次失败产生不同且不可变的 partial artifact。
6. additive revision 后能正确发现新 theorem、更新 `pp` 并生成 retry note。
7. `agent_error`、G1 error 和 sandbox error 不进入语义诊断。
8. build error tail 被保存进 detail 和 ledger，并受到长度上限约束。
9. revision 成功但调用者重试失败时，验证所选的持久化语义。
10. 同一文件包含多个函数的 accepted specs 时，只能豁免目标 theorem。
11. 两个同函数 `@[progress]` theorem 的实际选择行为。
12. `--max-revisions=0`、达到边界以及无效诊断是否按预期计数。

## 推荐的实现顺序调整

在原计划的实现步骤之前，建议先完成三个设计决策：

1. 将 accepted-spec registry 与本次 `steps` 解耦，确定 revision target 的统一数据
   结构。
2. 确定 additive-only 还是允许 in-place revision，以及失败后的持久化语义。
3. 明确可诊断 outcome 白名单和 evidence 在 sandbox 中的传递方式。

随后再实现：

1. immutable partial artifacts 和 build error evidence；
2. 严格的诊断 JSON schema 与 theorem membership 校验；
3. revision gate 及其结构化结果；
4. recovery 状态机和 ledger；
5. 单元测试；
6. 隔离 slot 中的 live trials。

这样可以避免在主循环完成后，才发现 revision target、G1 exemption 或 sandbox
证据路径需要整体返工。
