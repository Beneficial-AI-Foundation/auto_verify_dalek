# TODO：移出主计划的工作

## Contracts 锚定层（原阶段 1，2026-08-10 移出）

**移出理由**：阶段 2（规约预算曲线）不需要它就能跑——被删的人类原文是逐条 ground truth，agent 合成的空规约（含"抄算法"型）靠 `synth_eq_human` 比对即可现形。Contracts 层堵的是**部署场景**的洞（无参考原文时机械封死 spec = code 转写），属于论文后半章的加固，不挡实验。先跑实验。

**何时捡回来**：
1. 写部署阶段（chacha20 / 新库，无参考契约）的 claim 之前——那时"四条义务 + 变异捕获率"堵不住转写洞，需要词汇级封死
2. 预算曲线想加测"数学锚定"刻度（同一删除点，底层词汇字节/域元素 vs 商群/同构，比较合成质量）
3. 测量结果显示转写型空规约占比高，需要机械对策时

**成本**：只写陈述、假设入信任基（与 Math 层同待遇）≈ 人周级；真证 card/cyclic 证书 ≈ 人月级（Mathlib 无现成物）。

以下为原文，编号按移出时的旧版 plan.md（"第 3 节"=分层，"第 9/10 节"=现 §8/§9）。

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