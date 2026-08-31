# Decisions for the PR

Use the decision IDs in PR comments. `OPEN` means there is no preferred answer
yet. `PROPOSED` means the text gives a suggested starting point, not a final
decision.

When a decision is accepted, add the date, owner, and link to the discussion.

## Experiment design

### DEC-01 — What belongs in this repository?

**Status:** PROPOSED

**Question:** Is this only a runner script, or the reviewed home of the whole
experiment setup?

**Suggested start:** Keep docs, schemas, builder/runner/checker code, manifests,
and small result summaries here. Keep large run files elsewhere.

### DEC-02 — Where do large run files live?

**Status:** OPEN

**Question:** Which BAIF-managed storage should hold transcripts, patches,
logs, and sealed bundles?

**Suggested start:** Use storage with restricted access and file hashes.
Keep failed runs as well as successful ones.

### DEC-03 — Is Aeneas extraction part of the task?

**Status:** PROPOSED

**Question:** Do agents receive translated Lean, or must they start from Rust?

**Suggested start:** Give pinned Aeneas-generated Lean in the first experiments.
Test Rust-to-Lean later as a separate experiment.

### DEC-04 — How do we choose the top-level set `T`?

**Status:** PROPOSED

**Question:** Which graph rule and which API/trait targets should define `T`?

**Suggested start:** Check in a deterministic script using pinned probe data.
Use `A → B` for “A calls B,” and report `api` and `trait-instance` targets
separately.

### DEC-05 — How do we choose the supplied seed `S`?

**Status:** PROPOSED

**Question:** What must the JSON contain, and what can agents see for targets
in `W = T \ S`?

**Suggested start:** The JSON lists `S`, compile-support mode, Math input, and
whether missing targets include their translated Lean bodies. The builder
computes `W`. Rust function names are always visible. Hidden reference
statements remain verifier-only.

Start with `S = T`, then test smaller seeds. Report the smallest seed that
passes a fixed number of repeated runs, not an unproven global minimum.

### DEC-06 — How much of `Math/` is visible?

**Status:** OPEN

**Question:** Which definitions, lemmas, assumptions, comments, and proofs may
the agents read?

**Suggested start:** Give only definitions and structures required to compile
the input. Make the agents derive useful lemmas. Run larger Math-input modes
separately if the minimal mode is too hard.

### DEC-07 — Which agent roles do we use?

**Status:** PROPOSED

**Question:** One long-running agent, or separate writer, reviewer, and prover
roles inspired by FVS?

**Suggested start:** Use fresh writer and reviewer sessions, at most three
review rounds by default, then freeze an accepted statement before proving it.
Also run a simpler baseline for comparison.

## Isolation and checking

### DEC-08 — What sandbox is enough?

**Status:** PARTIAL (2026-08-28, Zhang-Liao; filesystem layer implemented in
`harness/agentproc.py` `bwrap_prefix` / `sandbox_selftest` and
`harness/driver.py` `make_slot`; network/credential/broker layer OPEN)

**Question:** Is a locked-down container enough, or do scored runs need a
microVM or remote worker?

**Minimum requirement:** No host checkout, sibling repositories, old Git
history, credentials, shared writable caches, or general network access. Model
calls go through a restricted broker. Verification runs elsewhere.

**Current state, item by item:**

| Requirement | Status | Mechanism / evidence |
| --- | --- | --- |
| no host checkout | closed | every agent runs in a per-job slot: rsync copy of the tree, sealed with `git init` + one commit; the operator's checkout is never mounted |
| no sibling repositories | closed | `$HOME` is an empty tmpfs inside bubblewrap; only `~/.elan` and the `claude` binary are bound read-only |
| no old Git history | closed | slot `.git` holds exactly the baseline commit and is additionally hidden by an empty tmpfs; `git rev-parse HEAD` fails inside the sandbox |
| no shared writable caches | closed | `.lake/packages` is bound read-only (`packages_readonly` probe); `~/.cache` does not exist; each slot has its own `.lake/build` |
| no credentials | open | the per-run `CLAUDE_CONFIG_DIR` holds a copy of the OAuth `.credentials.json`, readable by the agent process |
| no general network access | open | `--share-net`: the agent has the host's network; the only control is the `--settings` deny-list (`curl`, `wget`, `git fetch`, …), which a `python3`/`lean` one-liner bypasses |
| broker; verification elsewhere | open | `claude` talks to the API directly (optionally through the logging wire proxy); gates run on the same host |

A 12-probe self-test runs inside each slot's sandbox before the first target
and is recorded under `isolation.sandbox_selftest`; the driver aborts if any
probe fails. Toolset: `--tools Read,Grep,Glob,Edit,Write,Bash`,
`--disable-slash-commands`, `--strict-mcp-config` (no subagents, no web
tools, no skills, no MCP).

**What may be claimed today:** runtime *filesystem* access to the solution
history, sibling checkouts and caches was blocked and receipted. Network
egress was restricted by a deny-list, not blocked. This is the same
operational-isolation profile CryptoProver's Docker launcher reaches, and its
`docker/README.md` draws the same line: not a `scoreable` profile until
provider-only egress and negative reachability receipts exist. Parity with
CryptoProver is a comparison, not a standard; a run labelled "sandboxed" must
say which of the three open items were still open.

**To close the remaining items (planned, small):** bwrap `--unshare-net`
(loopback only) with the API reached through the existing wire proxy bound
into the sandbox; move the credential to the proxy side so the agent
process never holds it; record a negative reachability receipt (a `curl` to
a public host must fail) in the self-test. Whether a microVM is needed
depends only on this network layer — for the filesystem layer a mount
namespace is sufficient.

### DEC-09 — What can we say about cheating?

**Status:** PROPOSED

**Question:** How should results be labelled when known solutions are public?

**Suggested start:** Claim only that runtime access was blocked and checked.
State that training-data contamination is unknown. Do not claim a fully clean
room unless there is stronger evidence.

### DEC-10 — What counts as success?

**Status:** ACCEPTED (2026-08-26, Zhang-Liao; phase-1 mechanics implemented —
`harness/driver.py` gate c′, `harness/replay.py`, `harness/report.py`;
phase-2 spec-quality checks still OPEN)

**Question:** Is a clean build or zero `sorry` enough?

**Decision:** No. A phase-1 (`S = T`) experiment is COMPLETE only when all of
the following hold, each checked mechanically:

| Requirement | Where checked | Failure outcome |
| --- | --- | --- |
| every target in `T` proved (no `sorry` at its location) | `report.py` joins inventory, ledger, and the tree | `INCOMPLETE: k of n targets still open` |
| supplied statements unchanged | per attempt: driver gate c′ fingerprints every constant of the target module before and after (`StmtCanon --module`: kind + α-invariant canonical type, agent-territory definitions δ-unfolded so aliasing a weakened bound behind a helper `def` is detected); whole tree: `replay.py` compares every Specs/Aux module against `harness/frozen/statements.json` | `rejected_statement_changed` (policy violation, attempt aborts); replay `FAIL` |
| no new trusted assumptions or shortcuts | G2 (`collectAxioms` closure inside the frozen whitelist, no new `axiom`, frozen-file hashes) per attempt and in replay; forbidden-attribute scan per attempt (DEC-11) | `rejected_g2`, `rejected_forbidden_attr` |
| fresh replay | `replay.py`: `git worktree` of the ref (+ tracked diff for runs without `--commit`), empty `.lake/build`, `lake build`, G2, G1; dependency packages shared by symlink but content-hashed against `harness/frozen/packages.sha256` | replay `FAIL` |

`report.py --replay <report>` prints the single verdict and exits non-zero
unless COMPLETE. Zero `sorry` in the selected zones is required *in the
replay*, not only in the working tree. Adding helper declarations is allowed;
removing or changing any declaration that existed at baseline is not.

Still OPEN (phase 2, agent-authored statements): which spec-quality checks
are mandatory. The N1 vocabulary audit in `resynth.py` is the current
candidate hard check; comparison against the hidden reference statement is
data, not a gate (see `log/plan.md` §10).

### DEC-11 — Which Lean features are allowed?

**Status:** ACCEPTED (2026-08-22, Zhang-Liao; policy in `log/plan.md` §4)

**Question:** Should features such as `native_decide`, custom tactics, macros,
plugins, and native code be banned or allowed under a list?

**Decision:** `native_decide` is allowed in proofs. It is real computation, and
`collectAxioms` faithfully marks every theorem depending on it; the final
report states "N theorems depend on the compiler." Sites are ledgered in
`harness/frozen/native_decide_sites.json` (baseline: 6 sites plus the two
compiler axioms `Lean.ofReduceBool` and `Lean.trustCompiler`). The only
mechanically closed hole: agent output must contain zero new
`@[implemented_by]` or `@[extern]` attributes, since these can swap a
function's compiled version and let `native_decide` prove a false proposition.
This is a G2 gate check (`harness/gates/g2_trust_base.py`). All other trusted
assumptions are governed by the frozen axiom whitelist, enumerated by
`collectAxioms` over the dependency closure rather than by grep.

### DEC-12 — Can humans help during a scored run?

**Status:** ACCEPTED (2026-08-28, Zhang-Liao; seal implemented in
`harness/driver.py` `tree_manifest` / `seal_check`)

**Question:** May a person repair statements or guide agents after the run
starts?

**Decision:** No human changes after the run starts. Human work is allowed
while designing the experiment and reviewing results afterwards.

*Mechanism.* The agent never works in the operator's tree (slots, DEC-08),
so the only way a human change reaches a run is through the files the slot
was copied from or the gates read. At run start the driver hashes every
tracked or untracked-not-ignored file of the operator tree (`ledger/`
excluded; ~350 files, well under a second) into
`ledger/runs/<ts>/tree_manifest.json` and records two digests in
`environment.seal`:

| Digest | Over | On change |
| --- | --- | --- |
| `input_tree_sha256` | the input set: `Curve25519Dalek/`, `Utils/`, `curve25519-dalek/` (Rust), `lakefile.toml`, `lake-manifest.json`, `lean-toolchain`, `harness/` (gates, prompt, `frozen/`), `.verilib/sorry_inventory.json`, `.claude/settings-offline.json` | **violation** — `provenance.seal.input_ok = false` and the paths are listed; the run continues so the evidence is complete, and the record is not scorable |
| `tree_sha256` | every non-ignored file | **drift** — listed under `provenance.seal.drift`, not a violation (README edits, notes) |

The check re-runs before every target and once at the end of the run.
Accepted merge-backs change target files in the operator tree legitimately;
the expected manifest is updated with the post-accept hash so they are not
violations. Anything the agent could read but that is not in the input set is
still hashed, so an audit can see whether e.g. `docs/` changed mid-run; the
decision not to fail on it is deliberate — "which files matter" is a judgement
left to the audit, not to the code.

Not covered: `.lake/packages` (its own `harness/frozen/packages.sha256`,
checked by replay) and the running `claude` binary (version recorded only).
Whether a broken seal aborts the run or only marks it is part of the open
question "what event invalidates a run".

## Running and reporting experiments

### DEC-13 — Which models and how many repeats?

**Status:** PARTIAL (2026-08-31, Zhang-Liao)

**Question:** Which providers/models do we test, with what limits, and how many
runs make a comparison credible?

**Decision (for now):** Start like CryptoProver: single runs (n = 1) with one
pinned model, to save tokens. Every record already carries what a later
comparison needs (DEC-17 hashes, DEC-16 limits, `models_used`), so repeats can
be added without changing the ledger format.

**What n = 1 buys and what it doesn't:** CryptoProver's own P2 A/B (2 repeats
per arm) showed per-attempt variance is large — same arm, same target: one
attempt failed and one succeeded; identical wins cost $2.25 vs $6.06. So a
single run tells us whether the harness works, but its numbers are anecdotes:
**no cross-model or cross-configuration comparison may be claimed from n = 1.**

**Still open (the "partial"):** `--repeats K` in measurement mode (K independent
cold slots from one sealed baseline, never merge-back — otherwise repeat 2's
baseline differs from repeat 1's and DEC-19 fires), and success-rate
aggregation in `report.py` (k/K per model × target; runs comparable only on
equal tree hash + limits). Needed before any comparative claim.

### DEC-14 — What is the first project scope?

**Status:** ACCEPTED (2026-08-22, Zhang-Liao; experiment design in `log/plan.md` §7)

**Question:** One module, one portable backend, or the full crate?

**Decision:** As the suggested start. Small slices are for debugging the
harness only: the `Scalar/Scalar` vertical slice (33 proofs, 20 top-level
specs; `log/plan.md` §7.1) shakes out the driver batch mode and the Phase-2
measurement instruments. The full-project `S = T` baseline — all 347
sorry-bearing declarations proved with `collectAxioms` inside the frozen
whitelist (Phase 1, §7.2) — must exist before any end-to-end claim with a
smaller seed, because without a tree known to close, a synthesis failure
cannot be attributed (spec not synthesizable vs. proof not provable).

### DEC-15 — Who can read raw run data?

**Status:** OPEN

**Question:** Are full model transcripts public, restricted to reviewers, or
deleted after a fixed period?

**Suggested start:** Keep raw evidence in restricted storage long enough for
audit. Publish hashes, costs, outcomes, and redacted summaries.

### DEC-16 — When does a run stop?

**Status:** ACCEPTED (2026-08-25, Zhang-Liao; implemented in `harness/driver.py`
`run_rounds`, ported from CryptoProver `run.py` and adapted to one-sorry targets)

**Question:** What are the fixed limits for cost, time, tokens, retries, review
rounds, and stalled progress?

**Decision:** All limits live in a run JSON (`harness/limits.default.json`,
passed with `--run-config`; CLI flags override) and every ledger record
carries the effective values under `limits`.

*Rounds.* Work on a single theorem is divided into **rounds**, where each round is
one headless `claude -p` process. Even when Claude believes the proof is complete,
we still need to run tools such as `lake build` to confirm that the `sorry` has
actually been discharged — hence this parameter.

*Turns.* The number of operations (read, edit, etc.) performed by Claude Code
within a single round.

| Limit | Default | Outcome when hit |
| --- | --- | --- |
| agent rounds | 5 | last gate verdict (`rejected_*`) |
| turns per round (the round's work budget; model- and machine-independent, so runs stay comparable across models) | 30 | round ends normally, transcript and cost complete, gate runs |
| wall clock per round (safety net, not a budget: one `claude -p` process, process-group SIGKILL, transcript truncated and cost unreported) | 15 min; the per-target bound is rounds × timeout = 75 min | `agent_error{deadline}` for that round; later rounds may still run. Frequent deadlines mean the timeout or the build is wrong, not that the agent ran out of work |
| reported cost | off (`max_cost_usd = 0`) | `budget_exhausted{cost_usd}` |
| harness-side `lake build` | 20 min | `rejected_kernel_budget` |
| agent `END_REASON:LIMIT` | — | `agent_limit` (honest give-up; recorded, not retried) |
| stall: target file byte-identical after 2 consecutive rounds | reset session | `stalled` after 3 resets |
| context bloat: session cache-creation tokens > 200k | reset session | `stalled` after 3 resets |

A session reset starts a fresh context with the original prompt plus a compact
round history (edits stay in the file). Policy violations (scope, forbidden
attribute, sorry migration, trust-base, kernel budget) abort at once. No
outcome is discarded: timeouts, budget exhaustion and checker failures are
ledger records like any other. Unlike CryptoProver there is no separate
whole-target clock: a round is one agent process with a fixed slice, and the
target bound is simply rounds × timeout. CryptoProver's plateau guard is not ported —
with one sorry per target the progress metric is binary and collapses into
the round cap.

### DEC-17 — What environment details are recorded?

**Status:** ACCEPTED (2026-08-26, Zhang-Liao; implemented in `harness/driver.py`
`environment_snapshot` / `record_provenance`)

**Question:** How much OS, image, CPU, toolchain, and model-version information
is needed to repeat a run?

**Decision:** Every ledger record carries two provenance blocks in addition to
`limits` and `isolation`.

*`environment`* (captured once per driver run):

| Field | Purpose |
| --- | --- |
| `git_head`, `git_branch`, `git_describe`, `git_untracked` | problem version: targets, `Math/`, prompt template and gates all live in the tree; untracked files are listed because HEAD does not cover them |
| `lean_toolchain`, `lake_manifest_sha256`, `lakefile_sha256`, `lean_version`, `lake_version` | toolchain and dependency lock |
| `inventory_sha256`, `prompt_template_sha256`, `driver_sha256`, `agentproc_sha256` | harness version independent of commit state |
| `claude_version`, `python_version` | agent runtime |
| `os`, `kernel`, `arch`, `cpu_model`, `cpu_count`, `mem_total_kb` | machine; needed to interpret wall-clock limits and `lake build` times |

*`provenance`* (captured per target, before the first round): `git_head` —
drifts within a run under `--commit`, so the run-level value is not enough
to replay attempt *k* — and `prompt_sha256` of the rendered prompt.

*`models_used`*: union over rounds of the model ids the API billed
(`modelUsage` in the result event). This is the record of what actually ran;
`model` is only what was requested.

Two records are comparable only when `environment.git_head`,
`environment.lean_toolchain`, `environment.lake_manifest_sha256`,
`models_used` and `limits` agree. Not recorded: container image digest (no
container yet, see DEC-08) and API-side model snapshot dates beyond the id.

### DEC-19 — How are conflicting parallel edits merged?

**Status:** ACCEPTED (2026-08-31, Zhang-Liao; implemented — grouping and
merge-back in `harness/driver.py` `make_slot` / the accept path; a per-run
`file_owner` map catches a file group reaching two slots, and the merge-back
copy is refused (`rejected_merge_conflict`, job rolled back) when the operator
tree's copy of the file no longer matches the expected manifest)

**Question:** Two parallel jobs edit the same file — how do we merge their
changes?

**Decision:** We never merge code. Conflicts are prevented, not resolved.

- Targets are grouped by file, and a whole file group goes to one slot, so
  two slots never edit the same file. Merge-back is a plain copy under one
  lock, not a git merge.
- If a conflict still appears, it is a grouping bug in the driver: roll back
  both jobs, fix the driver, rerun. No hand-merging during a run — a human
  change mid-run breaks the DEC-12 seal and the run is not scorable.
- After the run, a human may resolve ordinary git conflicts when moving
  accepted files to the main branch. Correctness is then decided by
  `replay.py` (fresh worktree, empty cache, all gates), not by reading the
  diff.

*Precedent.* CryptoProver works the same way: one git worktree per agent,
whole-tree accept/discard between runs (promotion receipts).

## Claim boundary

### DEC-18 — Which properties are in scope?

**Status:** PROPOSED

**Question:** Does a result cover only Lean functional correctness, or also
constant-time and cryptographic security?

**Suggested start:** The first experiments cover only functional correctness
under the listed assumptions. Constant-time, side-channel, memory-safety, and
cryptographic-security claims need separate work.

## Other questions

- [ ] Which service pays for and runs the agents?
- [ ] What success rate makes a seed “validated”?
- [ ] Which seed-search method fits the available compute budget?
- [ ] How do we test that the sandbox really blocks files, Git, DNS, and web
      access?
- [x] How are parallel agents isolated from one another? — `--jobs N`, one
      sealed slot workspace + sandbox + config dir per job, file groups never
      span slots, `.lake/packages` shared read-only (2026-08-28,
      `harness/driver.py` `make_slot`; see ISOLATION-AND-INTEGRITY.md).
      Still open: CPU contention between concurrent `lake build`s changes
      what the wall-clock limits mean, so `jobs` is part of `limits` and
      records with different `jobs` are not directly comparable.
- [ ] Which hidden-spec quality checks are mandatory?
- [ ] Is a private or post-training-cutoff test target available?
- [ ] What event invalidates a run and requires a rerun?
- [ ] What evidence would satisfy an external reviewer despite unknown model
      training data?

See [PROJECT-SCOPE.md](PROJECT-SCOPE.md),
[EXPERIMENT-PROTOCOL.md](EXPERIMENT-PROTOCOL.md), and
[EVALUATION.md](EVALUATION.md) for the short supporting rules.
