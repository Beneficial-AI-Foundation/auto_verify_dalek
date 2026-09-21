# CryptoProver 相对本项目 revise-loop 计划的优势

本文比较：

- 本项目的 [PLAN-REVISE-LOOP.md](PLAN-REVISE-LOOP.md)；
- CryptoProver 的 `launch_spec_proof.sh` 及其调用的 `run.py` 中已经实现的
  spec-proof 工作流。

这里关注的是 CryptoProver 已实现、而本项目当前计划尚未完整覆盖的能力。两者实验
目标并不完全相同：本项目强调单文件隔离、逐个生成 internal spec 和严格的 Lean
statement gate；CryptoProver 更强调长时间、多文件证明任务的持续推进和可靠恢复。

## 1. 支持多个依赖文件的联合求解

CryptoProver 可以在一次 spec-proof 任务中把多个依赖文件交给同一个 agent。agent
能够同时设计相互关联的中间 spec、辅助 lemma 和调用者证明，并根据全局验证结果
反复调整它们。

这对以下情况尤其有利：

- 下层 spec 和调用者需求必须一起设计；
- 加强一个 spec 后需要立即修复多个调用者；
- 多个函数共享同一个数学 lemma；
- 局部最自然的 spec 只有放进完整调用链后才能判断。

本项目当前坚持“一次 session 只编辑一个文件”。这种隔离更容易审计，但跨文件调整
必须经过 diagnose、revise、retry，或者等待 v2 repair queue；联合搜索能力弱于
CryptoProver。

## 2. 有真正的任务级总时间预算

CryptoProver 同时限制最大轮数和任务总分钟数。总预算不仅覆盖 agent 运行时间，
还覆盖每轮 verifier、快照和 gate 的时间，并在启动新一轮 agent 前为本轮及最终
gate 预留时间。

因此它可以避免：

- agent 还有轮数，但已经没有足够时间完成验证；
- 多次昂贵 gate 使实际运行时间远超名义预算；
- 剩余几十秒时仍启动一轮注定被杀死的 agent；
- 任务结束时没有时间生成权威的最终验证结果。

本项目当前主要依靠每一步的 `--rounds`、单轮 timeout 和整个计划的
`--max-revisions`，尚无覆盖 spec、diagnose、revise、retry 和完整 `lake build` 的
统一 plan-level wall-clock budget。

## 3. 完整的每轮快照和可靠回滚

CryptoProver 会保存基线以及每轮结束时所有可编辑文件的快照。发生预算耗尽、hang、
污染或不可继续的破坏性修改时，可以回滚到：

- 最近一次完全验证通过的状态；或
- 最近一次通过完整性 gate、且代表最好已确认进展的状态。

它不会简单地把所有失败轮次都恢复到任务起点，而是尽量保留可靠的中间成果。

本项目当前计划会保存失败目标的 partial 文件，然后回滚 slot。partial 主要作为
诊断证据，新 session 并不直接继承其中已经完成的证明工作。对于“statement 正确、
证明已完成大半”的失败，这可能损失有效进展。

## 4. 下一轮收到结构化、可执行的反馈

CryptoProver 将每轮 verifier 结果、失败文件、行列位置、错误类别、文件 diff 和
剩余 admit inventory 组织成下一轮的反馈，而不是只传递最后一段自然语言。

它还能针对不同失败生成不同指令，例如：

- `COMPLETE` 被 gate 拒绝：指出是 verifier error 还是仍有 admit；
- sibling 文件验证失败：给出具体失败文件及 diagnostics；
- 修改了 frozen 文件：恢复文件并要求把 lemma 移到合法位置；
- spec drift：恢复冻结 contract 并指出发生漂移的声明；
- session reset：生成由 runner 控制的 canonical handoff。

本项目计划中的“note + compact history”尚未定义稳定 schema，也没有明确要求绑定
文件 hash、gate receipt、错误位置和诊断来源。

## 5. 更细致的失败分类

CryptoProver 不把所有失败都视为普通证明失败。它区分：

- verifier 或 proof failure；
- agent 没有产生最终结果；
- API rate limit；
- 进程 hang；
- spec drift；
- frozen-file edit；
- 从 Git 恢复被删除证明；
- 不安全的进程或临时文件操作；
- 缺少辅助 lemma 或证明分解的 `NEEDS_DECOMP`；
- 可能为假的 contract。

这种分类可以决定应该继续、重置 session、恢复文件、增加预算、交给人工还是立即
终止。它也能防止把基础设施错误误记成数学证明失败。

本项目当前计划主要区分 policy violation 与可诊断失败，再由 AI 判断
`lower_spec`、`own_statement` 或 `proof_difficulty`。如果没有更细的确定性 outcome
白名单，基础设施故障可能被错误送入语义诊断。

## 6. 使用证明进展而非文件变化判断停滞

CryptoProver 的 plateau/stall 机制会观察更接近任务目标的指标，例如：

- 剩余 hard admit 数；
- source-span verifier error 数；
- 是否出现新的历史最低值；
- 当前 verifier 结果是否因 timeout/build failure 而不可判断。

它可以在持续无进展时重置 session，并在更长时间没有改善时停止任务。

本项目现有 `driver.run_rounds` 的 stall 信号较依赖目标文件是否发生字节变化。agent
反复重写但没有减少证明义务时，文件仍会变化；相反，某些有价值的等长修改也可能
被粗粒度指标误判。CryptoProver 的指标更接近真实证明进展。

## 7. session 生命周期管理更成熟

CryptoProver 会显式记录和管理 session id：

- 正常轮次 resume 精确的原 session；
- 达到 turn cap 时创建 fresh session；
- context 膨胀或 plateau 时自动 reset；
- fresh session 接收 runner 生成的 reset handoff；
- reset 前后的文件状态和 gate 状态保持可追踪。

这比单纯“新开 session，并附上 compact history”更可靠，可以减少续接错误、上下文
污染和状态描述与磁盘实际内容不一致的问题。

## 8. 能利用跨运行的失败记忆

CryptoProver 会查询同一目标以前的失败记录，并把仍与当前 source tree 和 gate
配置匹配的经验加入 prompt。它还支持 discovery brief，避免每次运行都重新探索
相同代码和错误。

如果以前的运行报告 `NEEDS_DECOMP`，后续运行会：

- 增加轮数；
- 增加 wall-clock budget；
- 明确要求先建立缺失的辅助 lemma 或 lemma chain。

本项目虽然有 ledger 和 `internal_specs.json`，但当前计划主要利用本次 plan 内的
失败历史；尚未定义如何把以前运行的诊断、partial proof 和失败 goal 安全地复用到
下一次计划。

## 9. 验证结果与具体源码状态绑定

CryptoProver 使用 source-tree receipt、gate signature 和 gate receipt，把一次验证
结果绑定到：

- 确切的源码树；
- 确切的 verifier 命令；
- 确切的 gate 配置；
- 当前 lineage 和 round。

这样可以避免把旧源码、不同 verifier 参数或只验证了部分 module 的结果误当成当前
候选的有效证明。相同 tree 和 gate 的结果还可以安全缓存，减少重复验证开销。

本项目 ledger 会记录 prompt、outcome 和 session，但计划尚未要求 partial、revision
和 build receipt 都绑定到不可变的源码 hash 与 gate signature。

## 10. 对异常退出和运行环境有更多防护

CryptoProver 已处理多种长期运行中常见的问题：

- agent 非零退出但没有最终 result；
- API 直接返回 429；
- agent 长时间没有任何 action；
- turn cap 到达；
- verifier 子进程控制方式不安全；
- agent 尝试使用 Git 找回被删除的原证明；
- detached 运行，避免调用它的 shell 被回收时任务一起终止。

这些能力不直接提高证明能力，但能显著减少实验被错误记录为 `LIMIT` 或留下损坏
工作区的概率。本项目计划目前主要描述正常控制流和 gate rejection，对这些运行时
边界覆盖较少。

## 11. 同一轮可以保留并评估“全局最佳前沿”

复杂证明任务可能从未达到完整绿色状态，但 verifier error 已从几十个降到几个。
CryptoProver 会区分：

- 最后一次全绿状态；
- 最后一次完整性合格状态；
- 最好的、经过权威 gate 判断的 partial frontier。

预算耗尽时，它可以按实验模式选择应保留的状态，而不是一律回到初始版本。这对于
长链条 proof reconstruction 很重要。

本项目当前以每个 spec 是否 accepted 为主要二值信号。未 accepted 的步骤即使取得
大量局部进展，也只留下一个供参考的 partial 文件，不会成为下一次执行的正式起点。

## 12. 已有大量来自真实失败案例的防回归逻辑

CryptoProver 的实现包含针对真实运行问题增加的处理，例如：

- target-only 验证漏掉 dependency proof failure；
- 零 admit 但仍有 verifier error 时的错误 plateau 判断；
- 多文件错误被截断后只看到一个 module；
- session 找错导致 resume 到其他任务；
- 最后几十秒反复启动无效轮次；
- 修改 sibling 后只验证 anchor 造成假绿色。

当前 revise-loop 计划设计更简洁，但许多这些工程问题尚未进入测试矩阵。实现时如果
只覆盖理想路径，可能在长时间 live trial 中重新遇到相同类别的问题。

## 适合优先借鉴的能力

如果不改变本项目“一次 session 只编辑一个文件”的核心实验约束，仍可优先引入以下
能力：

1. 增加整个 plan 的 wall-clock/cost budget，并为最终 gate 预留时间。
2. 为每次 attempt 保存不可变快照、源码 hash 和 gate receipt。
3. 使用明确的 failure taxonomy 和“允许 AI 诊断的 outcome 白名单”。
4. 将 build errors 保存为结构化 diagnostics，而不仅是文本尾部。
5. fresh session 使用 runner 生成的 canonical handoff。
6. 使用 sorry/error/goal 指标判断进展和 plateau。
7. 对失败步骤保留“最近可靠状态”和“最佳 partial frontier”。
8. 允许下一次 plan 安全复用与当前源码和 gate 配置匹配的失败记忆。

## 本项目仍然保有的相对优势

上述比较不表示应该直接复制 CryptoProver 的多文件自由编辑模式。本项目当前设计仍有
几个重要优势：

- 每次 session 只编辑一个文件，责任边界和失败归因更清楚；
- top statement 固定，不能由 agent 为了通过证明而削弱；
- G1 对已有 Lean declaration 做 statement identity 检查；
- internal spec 按依赖顺序逐个接受，实验结果更容易统计；
- diagnose/revise 明确指出哪个 lower spec 被认为不足。

因此，更合适的方向是保留本项目的隔离和 gate 约束，同时吸收 CryptoProver 在预算、
快照、失败分类、session handoff、进展度量和 provenance 方面的工程能力。
