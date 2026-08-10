# 项目计划：Lean 版 dalek 验证

**给实现方（Claude Code）的说明**：本文件是研究计划，不是任务清单。第 4 节（阶段 0）已完成，产物在 `harness/`；下一个开工点是优先级 1–2。第 5–10 节是设计约束，实现时必须遵守但不必一次做完。所有 Lean 代码片段是**示意**，Mathlib API 名称需要现场用 `exact?` / `loogle` / `#check` 核对，不要假定本文件里的名字正确。

参照论文：*An AI Approach to Verified Production Cryptographic Libraries*（CryptoProver，arXiv 2608.00965v1）。下称"原论文"。

---

## 0. 一句话定位

> 原论文把"人写的规约"这个变量按住没动。我们放开它，测量**人类规约努力**与**最终 claim 强度**之间的兑换率，并给出使削减安全的机制。

不是"把 CryptoProver 移植到 Lean"。移植没有新意，而且 Rust→Lean + AI prover 这条路已经有人占了（见第 15 节）。

---

## 1. 这不是什么

实现时如果发现自己在做下面任何一件事，说明方向跑偏了：

- ❌ 在 Lean 里重新实现八道闸门然后报告"我们也做到了"
- ❌ 把**我们新写的顶层契约**写成一组 `requires`/`ensures` 风格的规定式公式（那样信任基只是换了来源，结构完全相同；仓库里现成的 WP 规约树是参照物和中间层，不是顶层 claim 的形态，见第 3、5 节）
- ❌ 跨验证器比较"Lean 比 Verus 省 token"（无法控制变量，见第 12 节）
- ❌ 训练或改进 prover 模型本身（这条赛道极度拥挤，见第 15 节）
- ❌ 在 `Math/` 层的数学定理上花证明预算——该层整体假设成立、进信任基（第 4 节）；证密码数学不是本项目的核心

我们做的是 **harness / 信任层 / 规约经济学**。

---

## 2. 仓库现状（工作的起点）

本仓库是 [`curve25519-dalek-lean-verify`](https://github.com/Beneficial-AI-Foundation/curve25519-dalek-lean-verify)（commit `3136002`）的 **no-proofs benchmark 快照**：Aeneas 抽取、规约树、数学模型全部就位，所有证明体被机械替换为 `sorry`。陈述冻结是 benchmark 的契约（README 明文），`sorries.jsonl` 给每个 sorry 一个基于 elaborated goal state 哈希的稳定 id。

已有的资产：

| 资产 | 位置 | 状态 |
|---|---|---|
| 可执行代码（Aeneas 抽取产物） | `Funs.lean` / `Types.lean` | 完整，冻结 |
| 数学模型 | `Math/`：Edwards 曲线 + `AddCommGroup (Point Ed25519)` 实例、EightTorsion、Montgomery 曲线、Edwards/Montgomery/Ristretto 表示桥 | 陈述冻结；**整层假设成立**——已填的 ~214 条证明保留（kernel 照常检查，免费的强度），剩余 10 条 sorry 不再证，列入冻结假设清单（第 4 节） |
| 规约树 | `Specs/` 共 263 条 spec，其中 **94 条顶层**（38 公开 API + 56 trait 实例），编目于 `.verilib/top_level_specs.md` | 陈述在，Aeneas WP 风格，逐函数 |
| 待填证明总量 | 实测（2026-08-10，声明级，`lake build` warning 统计）：**347 个待填含-sorry 声明**（Specs 318 · Aux/TypesAux 29）。Math 10、FunsExternal 36、Aeneas 依赖 17 不在待填之列——全部入信任基（第 4 节） | 重新生成的清单：`.verilib/sorry_inventory.json` |
| 信任基 | 21 条外部 `axiom`（FunsExternal 20 + TypesExternal 1，opaque Rust 函数）；FunsExternal 内 **36 条有意 sorry 的规约定理**（opaque 函数的规约不可证只能信）；Math 层 **10 处数学假设**（sorry 形态，陈述哈希冻结）；**6 处 `native_decide` 站点**（基点阶、8-挠计算 ⟹ `Lean.ofReduceBool` + `Lean.trustCompiler`）；Aeneas 依赖包内 **17 条 sorry**（manifest 钉死）；3 条 spec 标记 trusted；`@[externally_verified]` 属性机制 | 全部枚举冻结于 `harness/frozen/`，G2 机械检查 |
| 素性证书 | `PrimeCert` 已是依赖，`Math/Edwards/Curve.lean` 已 import `PrimeCert.PrimeList` | 就绪 |
| 阶段 0 产物 | `harness/frozen/`（假设清单 · 外部公理 · native_decide 站点 · 文件哈希）· `harness/phase0_audit.lean` · `harness/gates/g2_trust_base.py` · `.verilib/sorry_inventory.json` | 已建，G2 全绿 |

⚠ 仓库自带的 `sorries_summary.json` / README（1062 条 / 138 文件）与实测不符：既有备份目录三倍重复计数的历史问题，也没反映 Math 层已填的工作。所有数字以重新生成的清单为准（附录优先级第 0 条）。

这份资产表决定了整个计划的形状：

1. **顶层规约已经存在**（94 条 WP spec + Math 层锚点）——所以"人写规约"这个变量可以被操作：整份删掉一部分让 agent 重新合成，与被删原文逐条对照（第 9 节），这是第 0 节那条曲线的测量装置
2. **被假设的数学以 sorry 形态存在**，不是以公理形态——goal-hash 给每条假设一个稳定 id，信任基可机器枚举、可冻结、不可悄悄膨胀（第 4 节）；证明这些假设不是本项目的工作
3. **陈述同一性检查有现成基底**——goal-hash id 正是"elaborate 后比对"的正确形态（第 7 节 G1）

---

## 3. 分层：谁写什么

```
┌─ 人写，冻结 ────────────────────────────────────┐
│  Layer 1  数学模型（Math/，陈述冻结，整层假设   │  ← 第 4、5 节
│           成立；商群/契约锚定层由阶段 1 补）    │
└─────────────────────────────────────────────────┘
┌─ agent 合成 ────────────────────────────────────┐
│  Layer 2  精化塔：Specs/ 规约树 + 表示桥        │  ← 第 6 节
│  Layer 3  全部证明体（当前 347 个待填声明）     │
└─────────────────────────────────────────────────┘
┌─ 人写，冻结 ────────────────────────────────────┐
│  Layer 4  可执行代码（Funs.lean，不改）         │
└─────────────────────────────────────────────────┘
```

**夹紧论证**：两端固定，中间被夹住——太弱撑不住顶，太假搭不起来。闸门的作用是**把两端摁住让这个论证成立**，不是检查中间。这是理解全部设计的关键。

原论文 §2.2 有这个论证的 Verus 版本。我们的版本更强，因为顶端不是规定而是数学（见第 5 节）。注意：顶端的数学定理一部分本身是假设（第 4 节清单）——夹紧论证需要的只是**顶端由人写且冻结**，与它是否被证无关。被证与否影响最终 claim 的表述强度，不影响对 agent 的钳制。

Layer 2 的归属随实验而变：**基线实验**里整棵 Specs/ 树给定、agent 只填证明（第 8 节）；**预算曲线实验**里被删掉的那部分 spec 由 agent 重新合成（第 9 节），此时第 6 节的满射义务和第 10 节的四条义务生效。

---

## 4. 阶段 0：信任基固化——Math 层整体划入假设 ← **已完成（2026-08-10）**

**本项目不证 Math 层的数学定理。** Edwards 群律、平方根正确性、Elligator 落曲线——这些是密码数学形式化的活，不是本项目（harness / 信任层 / 规约经济学）的核心。Math 层整体按"陈述冻结 + 假设成立"处理：已填的证明保留（kernel 照常检查，免费的强度），剩余 sorry 不占任何证明预算，逐条冻结为**命名数学假设**。

### 冻结假设清单（10 处源位置 = 11 条 kernel 级声明）

`harness/frozen/math_assumptions.json`，每条含 kernel 名、源位置、完整陈述、陈述 sha256。

| 位置 | 陈述 |
|---|---|
| `Edwards/Curve.lean:288` | `add_assoc_Ed25519`（Edwards 加法结合律） |
| `Edwards/Curve.lean:96` | `complete_addition_denominators_ne_zero`（完备性，分母非零） |
| `Basic.lean:495` | `sqrt_checked_spec` |
| `Basic.lean:501` | `sqrt_checked_iff_isSquare` |
| `Basic.lean:521` | `inv_sqrt_checked_spec` |
| `Basic.lean:534` | `inv_sqrt_checked_sq_mul` |
| `Basic.lean:543` | `inv_sqrt_checked_snd` |
| `Edwards/Representation.lean:48` | `decompress_edwards_pure._proof_6`（编码桥义务） |
| `Ristretto/Representation.lean:416` | `IsEven_iff_in_doubling_image_right` |
| `Ristretto/Representation.lean:1150` | `elligator_ristretto_flavor_pure._proof_1/_proof_2`（一个 def 两个义务，含 `on_curve`） |

这个取舍与原论文同构：Verus 侧的曲线/域代数性质也全部在 48 条 `axiom_*` 里假设掉——dalek 从未证明 Edwards 结合律，两边地位相同。差别在**形态**：我们的假设是 kernel 级命名声明 + 陈述哈希，`collectAxioms` 能看见 `sorryAx`，G2 机械确认"Math 里自带 sorry 的声明集合 = 恰好这 11 条、陈述哈希逐条一致"，假设集不可能悄悄膨胀。谁将来想收窄信任基，靶子是显式的、逐条命名的。

### 信任基（审计后的完整形态 = G2 白名单）

```
{propext, Classical.choice, Quot.sound}
∪ 21 条外部 axiom（Aeneas opaque 函数；FunsExternal 20 + TypesExternal 1）
∪ 11 条命名数学假设（Math 层 sorry，陈述哈希冻结）
∪ {Lean.ofReduceBool, Lean.trustCompiler}（native_decide：允许全程使用，
   站点由 collectAxioms 记账，当前基线 6 处：基点阶 L、8-挠计算）
∪ FunsExternal 内 36 条有意 sorry 的规约定理（opaque 函数的规约，文件哈希冻结）
∪ Aeneas 依赖包内 17 条 sorry 声明（lake-manifest 钉死）
```

审计发现（比计划纸面上多出来的三类，全部如实记账而非掩盖）：`native_decide` 把编译器拉进信任基；FunsExternal 的规约定理本身就是 sorry；依赖包自带 sorry。想收窄各有路径（PrimeCert/`decide` 换 native_decide；差分测试兜 FunsExternal；上游修 Aeneas），全部不占本项目预算。

**native_decide 政策**：证明中**允许使用**——它是真计算不是伪造，`collectAxioms` 会把每条依赖它的定理如实标出，最终报告"N 条定理依赖编译器"即可，禁它只会把 agent 逼去写更贵的证明。唯一要机械封死的口子：`@[implemented_by]` / `@[extern]` 属性能替换函数的编译版本，挂假实现即可让 native_decide 通过假命题——**agent 产出零新增这两个属性**（G2 检查项）。

### 产物

| 产物 | 内容 |
|---|---|
| `harness/frozen/math_assumptions.json` | 11 条假设：kernel 名 + 源位置 + 陈述 + sha256 |
| `harness/frozen/external_axioms.json` | 21 条外部 axiom（从环境枚举，非 grep） |
| `harness/frozen/native_decide_sites.json` | 当前 6 处站点 + 2 条编译器公理（记账基线，非禁令） |
| `harness/frozen/frozen_files.sha256` | 19 个冻结文件哈希：`Math/` 全部 + Funs/Types(+External) + Tactics + ExternallyVerified + lakefile/toolchain/manifest |
| `harness/phase0_audit.lean` | 环境审计：包内公理枚举、Math 全声明 `collectAxioms`、假设集识别、标签检查（G2 的 Lean 侧） |
| `harness/gates/g2_trust_base.py` | G2 闸门：文件哈希 + 公理闭包 ⊆ 白名单 + 假设集/陈述哈希精确相等 + build warning 与清单一致。负向测试通过（改一字节即抓） |
| `.verilib/sorry_inventory.json` | 重新生成的声明级清单（410 条：Math 10 · Specs 318 · Aux 29 · FunsExternal 36 · Aeneas 17），取代陈旧的 `sorries_summary.json` |

### 验收（全部达成）

```
✓ Math 工作已提交（19318ad），lake build 全绿（3503 jobs）
✓ 假设集 = 恰好 11 条，陈述哈希逐条一致
✓ Math 公理闭包 ⊆ 白名单；零新 axiom；零 @[externally_verified] 于 Math
✓ 待填基线：347 条声明（Specs 318 + Aux/TypesAux 29），阶段 2 靶区
✓ Math/ + 信任基文件 + 工具链全部哈希冻结
✓ G2 全绿；负向测试（篡改冻结文件）被抓
```

（可选，未做）dalek-lite 48 条 Verus `axiom_*`（`https://github.com/Beneficial-AI-Foundation/dalek-lite/pull/774`）与 Math 层陈述的对照表——纯对照，不做蕴含证明。

---

## 5. 阶段 1：Contracts 锚定层（人写，冻结）

**核心原则：顶层说"实现实现了一个到 Mathlib 数学对象的群同构"，不说"实现等于这个我规定的函数"。**

原论文的顶层是**规定**——没人证明过那组公式真的刻画了 Ristretto，所以它必须把 contract adequacy 排除在保证之外（§5.3），曲线和域的代数性质只能放进 48 条公理里假设掉。在 Verus 里这是**被迫的**：Verus 生态没有已证的椭圆曲线理论、没有商群、没有群同构库。在 Lean+Mathlib 里，它是一个**可以选的变量**。

仓库的 `Specs/` 树同样是逐函数的 WP 规定式，`Math/` 层则已经把它锚到一个真实的曲线群模型上——这比原论文强，但还差三样东西。本阶段在现有 `Math/` 层之上补一个薄的 `Contracts/` 模块：

1. **Ristretto 作为商群类型**：`Ristretto := Ed25519 ⧸ torsion8`（EightTorsion 已有，商没取）
2. **非空洞性证书**：`Fintype.card Ristretto = ℓ`、`IsCyclic Ristretto`
3. **同构/双射/模作用形态的顶层契约**，并证明它们**蕴含** `Specs/` 树里对应的 WP spec——这一步让新锚不悬空，也让 94 条 WP spec 获得数学背书

### 骨架（示意，API 名需核对；`Point Ed25519` 复用 Math/ 层现有定义）

```lean
abbrev ℓ : ℕ := 2^252 + 27742317777372353535851937790883648493

-- ── 商结构（架在 Math/Edwards 已有的 Point Ed25519 与 EightTorsion 上）──
def torsion8 : AddSubgroup (Point Ed25519) := ...
def Ristretto := Point Ed25519 ⧸ torsion8

-- ── 非空洞性证书（关键！）────────────────────────────
theorem card_ristretto  : Fintype.card Ristretto = ℓ
theorem ristretto_cyclic : IsCyclic Ristretto
```

### 三条契约写法原则

每条都在堵一个具体的空洞路径：

| 原则 | 写法 | 堵住什么 |
|---|---|---|
| **用同态/模作用，不用逐点** | `⟦impl_scalar_mul k P⟧ = k • P` （`k : ZMod ℓ`） | 逐点的 `∀ k P, f k P = g k P` 允许 `f` 和 `g` 一起退化；模作用一次约束联合行为，不允许 |
| **编码用双射，不用往返** | `Function.Bijective (compress : Ristretto → CanonicalBytes)` | `decompress (compress P) = some P` 这种单向往返退化映射也能满足 |
| **给模型本身发基数证书** | `Fintype.card Ristretto = ℓ` | `def Ristretto := Unit` 会让所有定理平凡成立。这是**顶层自己的非空洞性义务**，Verus 里没有对应物（那边"模型"就是几个 spec fn，没有基数可谈） |

原论文最离谱的那条伪造公理（`lemma_ristretto_compress_correct`，连 `requires` 都没有，声称任意字节等于任意点的压缩）在双射陈述下**连写都写不出来**。

**证明预算说明**：锚定层的价值在**陈述的形态**——商群类型、双射、模作用、基数证书都是人写且冻结的，夹紧与闸门只需要这一点。锚点定理本身与 Math 层同等待遇：陈述冻结、以假设入信任基（假设清单相应扩充并同样 goal-hash 冻结），证明是可选加强、不占本项目预算。假设 vs 证明影响最终 claim 的表述强度，不影响对 agent 合成层的钳制（第 3 节）。

---

## 6. 精化塔与满射义务

### 塔的形状（仓库中的实际对应物）

```
bytes
  ↓  编解码 + 规范性          Specs/**/FromBytes, ToBytes, Compress, Decompress
FieldElement51                Types.lean（5 肢 × 51 位，未归约，带松弛界）
  ↓  toF / Bounded            Math/*/Representation.lean 的桥函数与界谓词
ZMod p                        Math/Basic
  ↓  坐标表示                 Specs/Backend/**/CurveModels（扩展/射影，表示不唯一）
Point Ed25519                 Math/Edwards/Curve
  ↓  商掉 8-挠                Contracts/（第 5 节）
Ristretto
```

基线实验里整座塔的陈述给定、agent 填证明。预算曲线实验里（第 9 节）被删的层由 agent 重建——**此时以下义务生效，由闸门机械强制**：

```lean
-- agent 合成
def toF     : FieldElement51 → F      := ...
def Bounded : FieldElement51 → Prop   := ...

-- 闸门强制的义务（不是提示，是机械检查）
theorem toF_surj : ∀ x : F, ∃ f, Bounded f ∧ toF f = x

theorem mul_refines (a b : FieldElement51) (ha : Bounded a) (hb : Bounded b) :
    Bounded (fe51_mul a b) ∧ toF (fe51_mul a b) = toF a * toF b
```

`toF_surj` 精确对应原论文伪造公理的形状——"结论约束了前提从未绑定的输出"，翻译成精化语言就是"抽象函数的定义域谓词不可满足，或抽象函数不满射"。agent 想靠把 `Bounded` 收紧到空集蒙混，满射义务立刻打掉。

### 为什么这是架构定理而不是一道闸门

**满射性沿塔可合成**：

> 顶层被基数证书锚定 **+** 每层满射义务 ⟹ 整座塔任何一层都藏不下空洞

原论文 §2.2 的论证只保证顶层**不被削弱**；这个额外保证中间**不被架空**。

### 中间锚点

顶层锚到商群之后塔比 Verus 版更高，agent 重建整段塔时会在中间迷路（对应原论文的 `NEEDS_DECOMP` 路径）。预算曲线实验删层时预先固定 1–2 个中间锚点（例如射影坐标层单独钉下来），锚点本身也是预算的一部分、要记账。

---

## 7. 闸门套件：8 → 3 + 3

Verus 需要八道闸门，根本原因是它的信任基**弥散且语法性**：规约在 `spec fn`、契约在 requires/ensures、公理是带 `admit()` 的 `axiom_*`、旁路有 `assume()` 和 `external_body`。只能靠 grep。

Lean 里 `collectAxioms` **穷举**依赖闭包。黑名单变白名单，白名单是完备的——这捅破了原论文自己承认的天花板（*"does not rule out an unmodeled bypass"*）。

### 保留/升级的三道

| 闸门 | 实现 | 说明 |
|---|---|---|
| **G1 陈述同一性** | 两级。**v1（证明恢复实验）**：`sorries.jsonl` 已按 elaborated goal state 的 sha256 给每个 sorry 发 id，逐条比对即可。**v2（合成实验）**：新契约的 `Expr`，**消解实例后**、δ-展开到冻结定义为止，与参考逐项相同 | ⚠ v2 **不能做字节比对**。agent 可以塞 `local instance` / `local notation` 换掉 `CommRing` 或 `Fintype` 实例，pretty-print 一模一样、elaborate 出来是别的命题。这是 Verus 里不存在的攻击面 |
| **G2 信任基闭包** | 已实现：`harness/gates/g2_trust_base.py` + `harness/phase0_audit.lean`。检查：冻结文件哈希；Math 公理闭包 ⊆ {propext, Classical.choice, Quot.sound} ∪ 21 条外部 axiom ∪ `sorryAx` ∪ {`Lean.ofReduceBool`, `Lean.trustCompiler`}（native_decide 允许，站点记账）；包内零新 axiom；agent 产出零新增 `@[implemented_by]` / `@[extern]`（防 native_decide 劫持）；假设集（Math 里自带 sorryAx 的声明）与冻结清单**精确相等**、陈述哈希逐条一致；build warning 与清单一致 | 吸收了 Verus 的 admit-count + axiom-drift + forbidden-construct 三道。`sorryAx` 单独处理——kernel 只有一个 `sorryAx`，区分不了是哪条 sorry，所以按"自带 sorry 的声明集合"比对，agent 在 Specs/Aux 留下的任何 sorry 都落网。**比较类型不比较名字**——原论文的 axiom-drift 只检测新公理**名**，原地改公理陈述要靠 frozen-edit 恰好被配置上才拦得住，这是设计脆弱性 |
| **G3 工具链完整性** | `lakefile.toml` / `lean-toolchain` / `lake-manifest.json` / `Tactics.lean` 未被改动 | 比 Verus 里**更重要**：Lean 允许元编程，agent 能改 elaborator；仓库里就有自定义战术文件 |

### 新增的三道（Lean 特有）

| 闸门 | 目标 | 备注 |
|---|---|---|
| **N1 非空洞性** | 第 10 节四条义务 | **kernel 完全看不见这一类**。已有模式清单：Lean-GAP（arXiv 2606.02588）的 C1–C11，其中 C6 最阴险——`def ... : Prop := True`，每条提到它的定理平凡满足，失败藏在定理下面一层 |
| **N2 满射义务** | 第 6 节 | 塔的每一层，agent 合成时生效 |
| **N3 kernel 代价预算** | `decide` 爆炸；elaborate 通过但 kernel 检查跑 40 分钟 | Verus 有 `rlimit`，Lean 这块是新的 |

### 降级/失效的

- **frozen-edit**：保留但不再是主力（公理检查已语义化）
- **sibling 检查**：被 `lake build` 的全局性吸收
- **git-recovery**：⚠ **在 Lean 里近乎失效**——Mathlib 就是答案库，Hales–Raya 的 Edwards 群律证明是公开发表的。隔离实验需要重新设计论证

---

## 8. 阶段 2：全量证明恢复

全部待填的 **347 个含-sorry 声明**（Specs/ 树 318 + Aux/TypesAux 29，声明级实测；Math/FunsExternal/依赖的假设不在内），同一套 agent + 闸门跑完，得到**除冻结假设外全树闭合、`collectAxioms` 落在白名单内的参照树**。

三个作用：

1. 本身即成果：Lean 侧的"附录 C proof-only 实验"，与原论文 1,430/1,433、$748、中位 1.1 分钟/条 做描述性对照（同一 crate、不同验证器、不同信任结构）
2. **预算曲线的前提**：删除-重合成实验需要一棵已知可全部证通的树做对照，否则"合成失败"无法归因（是 spec 合成不出来，还是证明本来就证不动？）
3. token 分桶记账（第 12 节）在这一步积累第一批分布数据

---

## 9. 阶段 3：规约预算曲线 ← **核心 AI 实验**

原论文把"人写多少规约"固定在**"全部顶层契约"**这一个点上。没人扫过这条曲线。

### 设计

> **自变量：人写的规约预算。**

测量装置是**删除-重合成**：从完整参照树里删掉一部分顶层 spec（陈述连同证明），让 agent 重新合成陈述再证明，与被删原文逐条对照。`.verilib/top_level_specs.md` 的 94 条编目就是删除清单。

- **主实验**：按模块删。dalek 天然四个顶层模块（Edwards / Montgomery / Ristretto / scalar）= 4 点曲线：留 4 个、3 个、2 个、1 个
- **加做的 ablation**：按依赖深度删（94 条的粒度支持任意子集）

每个点测三件事：

1. 还能不能通过全 crate 验证（`collectAxioms` 干净）
2. 被合成的顶层契约里，空洞率 / 过弱率（第 10 节四条义务 + 第 11 节强度指标量化；被删原文即逐条 ground truth）
3. token 和成本（第 12 节分桶）

### 可测的方向性假设

**Ristretto 是由 Edwards 定义的**（对 8-挠取商）。所以"留 Edwards、删 Ristretto"应该显著比反过来容易。

→ **依赖方向对规约可合成性的影响**，具体、能出图。

### 论文的问题就是这条曲线的名字

> 人写规约的努力，和最终 claim 强度之间的兑换率是多少？

这正是原论文明说自己**没测**的那一半：11.4 小时测的是契约、可信库、规约词汇表、目标分解、证明顺序、harness 全部就位**之后**的 agent 时间，而八个月的人类努力**包含撰写这些输入**，所以两个数字不可直接比较（§5.3）。§5.2 又说目标和证明顺序是人供给的，让 agent 自己规划是 immediate future work。

**定位：不是"我们做了另一个 CryptoProver"，是"我们去量了它明说自己没量的那一半"。**

---

## 10. 合成顶层契约的四条义务

一旦顶层的一部分（记为 `B`）交给 agent 合成，**`B` 就是顶，它上面没有任何东西在拉它**。第 3 节的夹紧论证在 `B` 这一层完全失效。

### 一个重要的认识：已给的部分只锚定词汇，不锚定断言

设人给了 `A`，`A` 和 `B` 共同依赖底层函数 `C`。`A` 确实能透传认证 `C`（这是量最大的部分，价值就在这里），但：

- `A` 钉死 `C` ⟹ `B` 里每个符号有确定含义 ⟹ **语义被接地（grounding）**
- `A` 完全不约束 `B` 说的话有多强 ⟹ **词汇是真的，句子可以是废话（no strength）**

`grounding ≠ strength`。混淆这两者是这个方案唯一的失败模式。

### 四条机械义务

```lean
-- (1) 词汇限制：B 只能用冻结的 C 和 Mathlib，不许提及任何实现函数
--     （机械检查：B 的 Expr 依赖闭包 ∩ 实现函数集合 = ∅）

-- (2) 确定性：B 必须唯一钉住输出
theorem B_deterministic : ∀ x y₁ y₂, B x y₁ → B x y₂ → y₁ = y₂

-- (3) 全域性：每个合法输入都有满足 B 的输出（否则 B 可靠空前提逃逸）
theorem B_total : ∀ x, valid x → ∃ y, B x y

-- (4) 可证：实现满足 B
theorem impl_sat_B : ∀ x, valid x → B x (impl x)
```

### 对照退化形态

| 退化 | 被哪条杀掉 |
|---|---|
| `B := True` | (2) 没钉住输出 |
| `B := ∃ b, compress P = b` | (1) 提及实现，且 (2) 不确定 |
| `B := decompress (compress P) ≠ none` | (2) |
| `B x y := (y = impl x)` | (1) |

**(2) + (4) 合起来有个漂亮性质**：确定性意味着 `B` 已经是函数式规约的最强形式（钉死一个函数），(4) 又要求那个函数就是实现的函数。所以 `B` 不可能过弱，也不可能错。

### 剩下的洞：spec = code

```
B x y := (y = <把整个压缩算法用域运算逐步写出来>)
```

四条全过（确定、全域、词汇合法、`rfl` 级可证），但它只是把算法抄了一遍。

**这个洞的大小反比于 `C` 的数学程度**：
- `C` 只有"字节"和"域元素" → 抄算法是最自然的写法
- `C` 里有 `Ristretto` 商群和 Mathlib 的 `≃*` → **没法用群同构的语言把肢运算抄一遍**

⟹ **想省人写的规约，前提是留下的那部分足够数学。** 这个约束是自己掉出来的——也是第 5 节 Contracts 层必须先于预算曲线存在的原因。

### 更划算的替代：压缩 B，而不是删掉 B

strength 不损失，节省更大：**写 `A` + 一行关系 `R`**，让 agent 从 `A` 和 `R` 推出 `B`。

| B | R（人写的那一行） |
|---|---|
| `compress` | `decompress` 的逆：`Function.LeftInverse` + 单射 |
| Montgomery 契约 | 与 Edwards 的双有理等价 |
| 标量乘 | **由群结构强制**：`A` 一旦说了"这是到 `ZMod ℓ` 的群同构"，`k • P` 就是群运算迭代，规约没有自由度 |

`R` 就是那个上锚，只是它极短。而"不写 `B`"是把锚整个拿掉。预算曲线上这是介于"给全部"和"删掉"之间的第三类点，值得单独测。

---

## 11. 强度测量（不用 LLM-as-judge）

### ⚠ PBT 在顶层几乎无用（方向翻转了）

**PBT 是证伪器，只能发现"假"，不能发现"弱"。**

| B | PBT 结果 |
|---|---|
| `True` | 100% 通过 |
| `decompress (compress P) ≠ none` | 100% 通过 |
| `∀ P, as_nat (compress P) ≥ 0` | 100% 通过 |

三条全空，PBT 一条都抓不到——因为它们**确实是真的**。

- **中间层**：agent 写的假规约是**太强**（前提漏条件、结论过界）→ PBT 又快又准，**这里值钱**
- **顶层**：没有上锚拉着，退化方向翻成**太弱** → PBT 探测方向反了

### 替代 1：变异测试 → bug 捕获率

方向翻转时工具也要翻转。往**实现**里注入 bug，看 `B` 抓不抓得住：

```
翻一个符号 / 肢边界 off-by-one / 错误的约减常数 / 漏一次进位 / 交换两个坐标
```

对每个变异体 `m`：`B x (impl_m x)` 是否被违反。

- 抓住 → `B` 在这个方向上有约束力
- 放过 → `B` 在这个方向上是空的

⟹ "够不够强"变成一个数：**bug 捕获率**。有人类参考契约，可以报**相对**捕获率。

**关键好处：不需要任何人给 `B` 背书。** 不问"`B` 说得对不对"，只问"`B` 有没有约束力"，后者纯机械。

> 💡 PBT 和变异测试打**同一套可执行基础设施**（可计算镜像 + 连接引理）。见第 13 节 noncomputable 那条。

### 替代 2：证等价（把"判断"升级成"定理"）

预算曲线的每个合成点都有被删的人类原文 `B_human`。那就别 judge，去证：

```lean
theorem synth_eq_human : B_synth ↔ B_human
```

四种结果，每种都有信息：

| 结果 | 含义 |
|---|---|
| 等价 | 完美，机器检查 |
| `B_synth → B_human` | 合成的更强，值得分析 |
| `B_human → B_synth` | 合成的更弱，**且精确知道弱在哪**（哪个蕴含不成立）→ 可量化的差距刻画 |
| 互不蕴含 | 最有信息量 |

### LLM-as-judge 的正确位置：分诊，不是闸门

三个问题：

1. **不能当闸门**：原论文 451 轮，唯一被机械执行的规则零违反，两条留在提示词里的规则**恰好就是**被违反的两条。*rules without gates are only suggestions*
2. **判官需要参照物，而生产参照物正是要省的那份工作**：现有 spec 判官都在比对两样东西（如 MathArena 判"Lean 陈述是否忠实形式化了这段自然语言"）。人写精确描述 = 活已经干完；人写模糊描述 = 判官没判据。**循环依赖**
   - ✅ **例外**：存在既有规范文档时参照物免费（RFC 8439 / RFC 8032 / Ristretto 规范）→ **选有标准文档的目标**
3. **判官和生成器同源**：那 11 条伪造公理共享同一个形状，同族模型当判官很可能觉得这形状挺自然

⟹ 判官用于**把 20 条合成契约排可疑度序，让人先看最可疑的 3 条**。减少的是注意力分配成本，不是判断责任。

### 工作量减少怎么诚实地测

用**撰写 vs 确认**的不对称（形式化方法里众所周知：读一份规约并判断它是否说了你想要的，远比从零写出来便宜）：

- **对照组**：人从零写 `B`，计时
- **实验组**：机器生成 `B`，全部筛查跑完，人**确认**，计时
- 报告两个时间 + 确认阶段的拒绝率

⟹ "人仍然签字，但签字前的一切都是机器做的"是真实的大幅削减，**且没牺牲任何保证**。

### 分层回答审稿人"你到底证明了什么"

- **验证阶段（本仓库，有人类契约当 label）**：我们**证明了** `B_synth ↔ B_human`——定理，不是判断
- **部署阶段（chacha20 或新库，无参考契约）**：只报告筛查结果——四条义务 + 变异捕获率 + 判官分诊 + 人工确认耗时 X 分钟（对照：从零撰写 Y 小时）

这个答案没有洞。**别把它包装成免费的午餐——张力本身就是论文：我们不声称少写规约是免费的，我们在测量那个兑换率。**

---

## 12. Token 账本与 ablation

### ⚠ 方法论红线

**绝不跨验证器做因果比较。** 目标不同、库不同、难度不同、prompt 不同，任何数字都能被归因到别处。原论文自己承认其结果是 existence result 而非平均性能估计（非独立重复试验）——**做 AI 贡献必须修这条**，否则只是复制了它的方法论缺陷。

- ✅ **全部 ablation 在 Lean 内部做**：证伪闸门 on/off、算出的上下文 on/off、检索战术 on/off
- ✅ Verus 数字只当**描述性参照**
- ✅ **跑重复试验**，报分布。这是原论文做不到而我们能做到的事，本身就是贡献

### Token 去向分解（没人在证明合成上报过）

原论文只给到 19% / 81%（验证器 / agent）这个粗粒度。分五个桶：

| 桶 | 被哪个干预打 |
|---|---|
| 产出性生成 | — |
| 诊断重定向 | Lean 结构化目标状态 |
| 检索 | `exact?` / `apply?` / loogle / hammer |
| 死路（假陈述、调 rlimit） | 证伪闸门 + kernel 确定性 |
| 上下文重摄入 | 算出的最小上下文 |

### 四个干预

**① 证伪优先闸门（中间层）**

成本模型：

```
节省 = P(陈述为假) × ( E[在假陈述上的证明尝试成本] − E[证伪成本] )
```

`E[证伪成本] ≈ 0`（毫秒级，零 token）。baseline 见第 14 节 `repair_002_axioms` 和 `corefloor_006`。

⚠ **差异化**：arXiv 2606.04883 已做"Lean 里别把算力浪费在不可行/误形式化陈述上"，但用的是**轻量 router 预测**。我们的差异：
- router 是猜，**PBT 是证**（单向可靠）
- 他们的陈述来自人/benchmark（`P(假) ≈ 0`）；我们的来自 agent 自己（`P(假)` 就是整个问题）
- 他们只省钱；**我们的同一次判定同时是信任闸门**

⟹ 贡献不是"省 token"，是"**在 agent 自写规约的设定下，可靠证伪同时买到成本和信任**"。

**② 算出的最小上下文 ← 最强的一条**

原论文的 prompt 装的是"目标模块 + 剩余义务 + **来自相关模块的相关信息** + 持久失败记忆"。粗体是**启发式**——不知道什么算相关，只能宁多勿少。

它自己指出了这里的经济学张力：会话复用 prompt cache 并累积上下文——复用便宜但危险（context pressure 正是 11 条伪造的根因），fresh session 安全但扔掉 cache。折中是 stall / bloat / plateau 触发重置 + 每目标上限。**这是在两个都不好的选项之间调参。**

Lean 里每个 `sorry` 的目标状态是**闭合的项**，依赖闭包**可计算**：

> 启发式上下文组装 → **算出的**上下文组装

两个后果同时发生：每轮 input token 下降；且 context pressure 的**根因消失**（上下文不再随会话长度增长，由目标本身决定）。

**原论文是治症状（检测膨胀然后重置），我们是消除机制。**

可测量：per-round input tokens、fabrication rate、prompt cache 命中率（反直觉预测：最小上下文更稳定 ⟹ cache **更**容易复用）。

**③ 检索即战术**

`exact?` / `apply?` / `rw?` / loogle / hammer —— 一次工具调用替代一次生成。Verus **没有任何对应物**，这正是原论文必须自建四个 search skill 的原因。

**④ 无求解器预算调优**

`rlimit` 是 token 沉井。原论文最难的义务：试 `rlimit(600)` 再试 `rlimit(900)`，连续两次**撞挂钟上限、不返回任何裁决**——两轮 token 换零信息。附录 D 也直说大型非线性查询耗尽资源限制时诊断无法指出坏在哪一步。

Lean 的 kernel 检查确定性，这一整类非产出轮次消失。

### Lean 更费 token 的地方（诚实记录）

- Mathlib 二十几万条声明的检索负担（对比 dalek 的小可信库）
- elaboration / 实例解析错误消息极冗长、含 metavariable
- 没有 SMT 替你扛，证明本身更长（automation 部分抵消）

⟹ 诚实的 claim 不是"Lean 省 token"，是"**Lean 把 token 从一个桶搬到另一个桶，有趣的问题是哪些桶**"。

---

## 13. 已知坑

| 坑 | 说明 |
|---|---|
| **抽取进信任基（相对 Verus 的真实退步）** | 原论文验的是**真正 ship 的那份 Rust**；我们验的是它的 Aeneas 翻译，翻译的忠实性**没被证**，另有 21 条外部 `axiom` 兜底 opaque 函数。ref [25] 自己就把 Lean 工具链漂移和抽取限制列为主要工程缺口。**明写在 threats to validity 里，不要掩盖。** 缓解手段：差分测试（AWS Cedar 的做法） |
| **Mathlib 的 EC 支持是 Weierstrass 中心的** | 任意特征下的群律有形式化；Edwards 群律那条初等路线是 Hales–Raya 在 **Isabelle/HOL** 里做的，Lean 侧没有现成物——本项目不走这条路，结合律留在假设清单里（第 4 节）；**Ristretto 商群 + 基数证书同样没有现成物**——阶段 1 只写陈述、以假设入信任基，真要证按人月算 |
| **noncomputable 挡住塔顶的 PBT** | 商群、`Fintype.card` 不可 `#eval`。**但这个张力自己解开了**：需要 gate 的不是塔顶（人写的、冻结的），是 agent 合成的中间层，而中间层（`FieldElement51 → ZMod p`）恰好全可计算。⟹ 需要"可计算镜像 + 连接引理"的强制分层（见下） |
| **git-recovery 失效** | Mathlib 是答案库，Hales–Raya 证明公开发表，且本仓库的上游 repo 里就有全部原始证明。隔离论证要重新设计：网络封印 + 上游 repo 不进容器，并如实报告这层边界 |
| **PBT 抓不到"弱"** | 见第 11 节。顶层用变异测试，不要指望 PBT |
| **陈旧元数据** | `sorries_summary.json` / README 的 1062 是三倍重复计数（备份目录已删）。所有报告数字以 `.verilib/sorry_inventory.json`（声明级，由 build warning 重新生成）为准 |
| **依赖包自带 sorry** | Aeneas 的 Lean 支持库有 17 条含 sorry 的声明（`Aeneas/Std`），随 lake-manifest 钉死、随白名单入信任基。上游修掉之前，这层要写进 threats to validity |

### 一个应该直接采纳的设计：把可计算镜像变成强制义务

原论文里有句容易滑过去的话：agent **自发**添加了辅助 spec fn 用于 **computable mirrors**、归纳度量和循环目标，每一条都配了证明接回固定规约词汇表。

⟹ **agent 在没人要求的情况下已经造出了 PBT 需要的全部基础设施。**

那就把它从偶然产物变成强制义务：

> 每条 agent 新写的内部规约 `S`，必须同时提交可计算镜像 `S_exec` 和连接引理 `S_exec x = S x`（后者由 Lean 检查）。PBT 和变异测试都打 `S_exec`。

三重好处：
1. 连接引理由验证器保证镜像忠实
2. PBT 在原生速度上跑，不受 Mathlib noncomputable 和解释器性能影响
3. **这条义务本身就是一道非空洞性闸门**——写不出可计算镜像的规约，多半根本没在说事情

---

## 14. 基线数字（校准与对照用）

全部来自原论文，用于成本模型校准和描述性对照。**不要当因果对比。**

### proof-and-spec 合成（§4.1，主实验）

| 项 | fable-5 | opus-4.8 复现 |
|---|---|---|
| elapsed | **11.4 h** | 62.3 h（5.5×） |
| API 成本 | **$466.99** | $856.55 |
| checks verified | 2,031 | 2,114 |
| 最终公理数 | **48**（全部来自可信库） | 同 |

- baseline（Claude Code 裸跑）：7.42 h，**$1,117.17**，声称完成但残留 5 编译错误 + 2 验证错误；日志记录 5 次抓取 + **38 次 history probe**（全被网络封印挡下）
- agent 196 proof fn vs 人类 235；证明行数 48.5%；108 个无人类对应物，147 个人类的缺席

### 全 crate proof-only（附录 C）—— 阶段 2 的直接参照

- no-hints：opus-4-8，1,433 条义务关掉 **1,430**，**$748.02**；残留 3 条在 deep Ristretto/Lizard curve-algebra core（**人类参考也没关**，留 8 条开放含这 3 条）
- with-hints：3 次跑 $730 / 154 轮，同样 3 条残留
- 主 sweep 每条 admit 中位 **1.1 分钟**；hard-frontier retries **30–60 分钟/条**且"adds little"
- 验证器占 active proving time **19%**，agent **81%**

### campaign（§3.1 + 附录 B）—— 证伪闸门的 baseline

| run | 结果 | 轮 | h | $ |
|---|---|---|---|---|
| 全部 24 次 | 声称 97.1%，实际 11 条伪造公理 + 5 处兄弟破坏 | 451 | 52.2 | 1,452 |
| `repair_002_axioms` | **0/11**（10 条本身是假命题） | 34 | 0.9 | **15** |
| `repair_003_inline` | **11/11**（新上下文，从零重证） | 4 | 2.2 | **45** |

- `corefloor_006`：整个续跑停在 **47 条非公理 admit 开放**，≥2 条因 agent 生成的假内部规约而无法证明
- 反例（⚠ PDF 上标丢失，实际值）：`carry8 = 2^53 + 13`；前提 `l4 < 2^52` → 换成调用点事实 `l4 = 2^44`；Ristretto 那条是 `x = 0, y = p + 1`
- 11 条伪造公理分布：**4 条 Montgomery ladder**（差分加倍、转 Edwards、基点在曲线上、Elligator）、1 条 27 步标量求逆链、**6 条 Ristretto**（compress / decode / Elligator / batch）

### 💡 那个分布不是随机的 —— 这是第 9 节假设的 pilot 证据

那些位置**恰好是 dalek 里唯一需要商结构才能说清楚的地方**：Ristretto 是对 8-挠子群取商；Montgomery 的 x-only 差分加法活在 Kummer line 上（对 ±1 取商）。

**SMT 逻辑里没有"商"这个概念。** agent 面对这些义务时，除了把结论直接写成公理，**没有别的表达方式**。

⟹ 原论文把伪造归因于 context pressure——那是**触发条件**；**表达能力缺口才是结构性原因**。这个再解释可证伪，且用的全是别人的数据。

### 求解器预算

- 最难的义务：`rlimit(600)` → `rlimit(900)`，两次**撞挂钟上限无裁决**；靠抽出闭式辅助引理 + 拆两个子引理才关掉
- 最终树有高于人类参考最大值的 rlimit 站点；`scalar::non_adjacent_form` 在 `rlimit(150)` 不可移除；opus 复现里 13 个站点有 2 个必需

### chacha20（转移实验）

opus-4.8，**一轮**（15 分钟，$4.14），13 verified items，无错误。规约是**人工撰写并独立校验**的 RFC 8439 形式化。

---

## 15. 相关工作与差异化

| 工作 | 是什么 | 我们的差异 |
|---|---|---|
| **ref [25]** arXiv 2605.30106（Runtime Verification）| Charon/Aeneas 或 hax → Lean 4；ArkLib/CompPoly 提供**人写**规约；Aristotle/Aleph 关证明；Plonky3 FRI + RISC Zero Merkle。CAV 2026 AIMACS 接收 | **他们的规约是人写的**，所以摘要那句 *"Every proof is checked by the Lean kernel, so AI output cannot compromise soundness"* 在他们设定下成立。一旦 agent 也写规约，这句话不成立——**kernel 保证证明，不保证命题**。这就是我们的题眼 |
| **arXiv 2606.04883** | Optimizing the Cost-Quality Tradeoff of Agentic Theorem Provers in Lean。router 避免在不可行/**误形式化**陈述上浪费算力 | 见第 12 节 ①：router 是猜 vs PBT 是证；benchmark 陈述 vs agent 自写陈述；纯省钱 vs 同时是信任闸门 |
| **Lean-GAP** arXiv 2606.02588 | LLM 生成 Lean 陈述的 C1–C11 病态模式清单（含 C6 `def ... : Prop := True`） | 他们做的是数学 benchmark 上的**语法模式匹配 / LLM 判官**；我们做**生产密码库上的机械闸门**（原论文已证伪"用提示词层检查"这条路） |
| **Verus-SpecGym** arXiv 2605.26457 | 扩展 Verus `exec_spec` 把规约编译成可执行 Rust 检查（原生只支持原始类型 + 单变量具体区间量化；他们扩到 Seq/Set/Multiset/Map） | 证明 Verus 侧 PBT **也可行**——所以别声称"只有 Lean 能做 PBT"。差的是工程量不是能力 |
| **LemmaNet** arXiv 2603.22114 | agentic program verification 的引理发现（Rocq），报告 per-VC 成本 | 成本报告方法可借鉴 |

### ⚠ 别去做 prover

AlphaProof / Seed-Prover / AxiomProver / Aristotle / Leanstral 等在竞赛级基准上厮杀。**做 harness、信任层、规约经济学。**

---

## 16. 仓库结构

冻结区（G1/G2/G3 保护）与工作区：

```
auto_verify_dalek/
├── lakefile.toml / lean-toolchain / lake-manifest.json   # G3 冻结（deps: aeneas, mathlib, PrimeCert）
├── Curve25519Dalek/
│   ├── Funs.lean / Types.lean       # Layer 4：Aeneas 抽取产物，冻结
│   ├── FunsExternal.lean            # 信任基：20 条外部 axiom，清单冻结（G2 不许扩展）
│   ├── TypesExternal.lean           # 信任基：1 条外部 axiom，同上
│   ├── ExternallyVerified.lean      # @[externally_verified] 属性机制
│   ├── Tactics.lean                 # 自定义战术，G3 冻结
│   ├── Math/                        # Layer 1：冻结；整层假设成立（10 条 sorry = 假设清单）
│   │   ├── Basic / BitList
│   │   ├── Edwards/    (Curve · EightTorsion · Basepoint · Representation)
│   │   ├── Montgomery/ (Curve · Representation)
│   │   └── Ristretto/  (Representation)
│   ├── Contracts/                   # Layer 1 锚定层（阶段 1 新写）：商群 + card/cyclic 证书
│   │                                #   + 双射/模作用契约 + 蕴含 Specs/ 树的证明
│   ├── Mirrors/                     # 可计算镜像 + 连接引理（强制义务，第 13 节）
│   ├── Specs/                       # Layer 2：263 条 spec（94 顶层），陈述冻结，sorry 待填
│   └── Aux.lean / TypesAux.lean     # 辅助引理，sorry 待填
├── Utils/                           # 上游状态工具（listfuns, syncstatus）
├── .verilib/
│   ├── probes/                      # 263 条 spec 的机器可读清单
│   └── top_level_specs.{md,json}    # 94 条顶层 spec 编目 = 第 9 节的删除清单
├── harness/                         # G3 冻结
│   ├── phase0_audit.lean            #   环境审计（已建）：包内公理枚举 · Math 全声明
│   │                                #   collectAxioms · 假设集识别 · 标签检查
│   ├── frozen/                      #   信任基冻结产物（已建）：math_assumptions ·
│   │                                #   external_axioms · native_decide_sites · 文件哈希
│   ├── gates/                       #   g2_trust_base.py（已建，全绿）
│   │                                #   待建：g1 v2 Expr 比对 · g3 工具链 · n1 非空洞性 ·
│   │                                #   n2 满射 · n3 kernel 预算
│   ├── context/                     #   typed hole → 算出的最小上下文
│   ├── falsify/  mutate/  ledger/   #   PBT · 变异测试 · token 分桶记账
└── experiments/
    ├── phase2_full_recovery/        #   阶段 2：347 条待填声明
    ├── spec_budget_curve/           #   阶段 3：删 N 份顶层 spec 重合成
    └── ablations/                   #   闸门 on/off × 重复试验
```

---

## 附：优先级

0. **阶段 0（信任基固化）—— 已完成（2026-08-10）**：Math 工作已提交（`19318ad`）、`lake build` 全绿（3503 jobs）、清单重生成（`.verilib/sorry_inventory.json`）、假设/公理/native_decide/文件哈希全部冻结（`harness/frozen/`）、G2 闸门已建且全绿
1. **token 分桶记账 + G2 接进驱动循环** —— 阶段 2 开跑前必须就位
2. **算出的最小上下文** —— 最强的 AI 侧贡献
3. **阶段 2（全量证明恢复，347 条声明）** —— 产出预算曲线所需的参照树
4. **阶段 1（Contracts 锚定层，只写陈述，假设入信任基）** —— 与 3 并行推进
5. **阶段 3（规约预算曲线）** —— 需要 3 的参照树；Contracts 层就位后加测"数学锚定"刻度
6. **抽取忠实性（Aeneas 差分测试）** —— 最后做，工程最重且信任故事最弱
