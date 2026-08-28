# The harness as built (2026-08-28)

This page describes what `harness/` does today and maps it onto the questions
in [DECISIONS.md](DECISIONS.md). It is a snapshot; the decision IDs are the
stable reference.

## 1. What the harness is for

Phase 1 of the experiment (DEC-14): every `sorry` in the extracted
curve25519-dalek Lean tree is a target; an agent must replace it with a proof
that the harness accepts. The harness is the part that makes an accepted proof
mean something: the agent could not see the answers, could not change the
statement it was proving, could not add trusted assumptions, and the result
can be rebuilt from scratch by someone else.

Phase 2 (agent-authored statements, `resynth.py`) shares the mechanics but is
not wired into the driver yet.

## 2. Components

| File | Role |
| --- | --- |
| `harness/driver.py` | the run loop: baseline build, slot workspaces, per-target rounds, gates, accept/rollback, ledger |
| `harness/agentproc.py` | one `claude -p` round as a subprocess: session UUID + `--resume`, wall-clock kill of the process group, bubblewrap sandbox, isolated `CLAUDE_CONFIG_DIR`, optional wire proxy |
| `harness/gates/StmtCanon.lean` | G1: canonical fingerprint of every constant's kind and α-invariant statement in a module |
| `harness/gates/g2_trust_base.py` | G2: `collectAxioms` closure against the frozen axiom whitelist, no new `axiom`/`@[implemented_by]`/`@[extern]`, frozen-file hashes |
| `harness/replay.py` | fresh rebuild of a ref in a new worktree with an empty `.lake/build`, then G2 + G1 against `harness/frozen/statements.json` |
| `harness/report.py` | the whole-`T` verdict: inventory × ledger × tree × replay → `COMPLETE` or `INCOMPLETE: k of n` |
| `harness/buckets.py` | post-hoc transcript classification (turn buckets, usage totals) |
| `harness/resynth.py` | Phase-2 instruments: delete/restore statements, N1 vocabulary audit — not yet called by the driver |
| `harness/api_top.py` | the api-top catalog (DEC-04): which specs are user-facing API surface |
| `harness/limits.default.json` | the default stop rules (DEC-16), passed with `--run-config` |
| `harness/frozen/` | axiom whitelist, statement fingerprints, `packages.sha256`, `native_decide_sites.json` |
| `ledger/rounds.jsonl`, `ledger/transcripts/`, `ledger/runs/<ts>/` | one record per attempt; raw stream-json per round; per-run slots and config dirs |

## 3. One run, end to end

```
driver.py --zones specs --jobs 2 --model <id> [--commit]
│
├─ preflight    tracked tree must be clean; baseline `lake build` (sorry count
│               per file); G1 baseline fingerprints for every target module
│
├─ slots        for each job i:
│                 rsync tree → ledger/runs/<ts>/slot<i>/work  (no .git, no
│                 ledger/, .lake/build copied warm, .lake/packages → symlink
│                 to the main checkout)
│                 git init + one sealed commit
│                 fresh CLAUDE_CONFIG_DIR with only the credential file
│                 bwrap prefix + 12-probe self-test (abort on any failure)
│
├─ queue        targets grouped by file, inventory order; a file group is
│               handed to exactly one slot
│
├─ per target   resolve the sorry in the slot's current file
│    └─ rounds  round 1: fresh session; rounds 2..N: --resume with the gate
│               verdict as feedback; stall/bloat → session reset with a
│               compact history (DEC-16)
│         └─ gate (all in the slot, on the host, outside the sandbox)
│               a  scope: only the target file changed
│               b  no new axiom / @[implemented_by] / @[extern] in the diff
│               c  lake build exits 0 within --build-timeout
│               c′ G1: every baseline constant of the module still exists
│                  with the same kind and canonical statement
│               d  target file's sorry count strictly down; every other
│                  file's unchanged
│               e  G2 trust base
│    accepted → commit in the slot; copy the file to the main checkout
│               (+ git commit with --commit)
│    rejected → rollback to the slot's HEAD (last accept or baseline)
│    always   → one ledger record (limits, isolation, environment,
│               provenance, per-round cost/tokens/models)
│
└─ afterwards   replay.py <ref> → report.py --replay → COMPLETE / INCOMPLETE
```

What the agent sees inside a round: the slot at its real path, `~/.elan`, the
`claude` binary, `/usr` and `/etc` read-only; nothing else under `$HOME`; no
`.git`, no `harness/`, no `ledger/`; `.lake/packages` read-only. Tools:
`Read, Grep, Glob, Edit, Write, Bash` with `Bash(lake build*)` and
`Bash(grep*)` auto-approved; no subagents, web tools, skills or MCP servers.

## 4. Decisions: solved, partial, open

### Accepted and implemented

**DEC-10 — what counts as success.** Four mechanical conditions: every target
in `T` proved, supplied statements unchanged (gate c′ per attempt, replay
against `harness/frozen/statements.json` for the whole tree), no new trusted
assumptions (G2 per attempt and in replay), and a fresh replay. `report.py
--replay` prints the single verdict. Phase-2 spec-quality checks remain open.

**DEC-11 — allowed Lean features.** `native_decide` allowed; `collectAxioms`
reports what depends on it. `@[implemented_by]` / `@[extern]` are the one
hole closed mechanically (G2). Everything else is governed by the frozen
axiom whitelist.

**DEC-14 — first project scope.** Full-project `S = T` baseline first; the
Scalar slice is for shaking out the harness.

**DEC-16 — when a run stops.** Rounds × per-round wall clock, turns per round,
optional cost cap, `END_REASON:LIMIT`, stall and context-bloat resets, a
20-minute harness-side build budget (`rejected_kernel_budget`). All limits in
a run JSON, recorded in every record. `jobs` is now part of `limits` because
concurrent builds change what the wall clock means.

**DEC-17 — environment provenance.** `environment` (git, toolchain, lock
files, harness file hashes, tool versions, OS, CPU, RAM) once per run;
`provenance` (HEAD and prompt hash) per target; `models_used` from the API
result, not the requested model.

### Partially solved

(DEC-12 moved to "accepted" above — see the seal paragraph below.)

**DEC-08 — what sandbox is enough.** Filesystem layer closed: no host
checkout (slots), no sibling repositories (empty `$HOME`), no old Git history
(sealed slot + hidden `.git`), no shared writable caches (`.lake/packages`
read-only). Self-test receipts in every record. Open: the agent process holds
a copy of the OAuth credential; network is shared (`--share-net`) and only
deny-listed, not blocked; no broker; gates run on the same host. This is the
same operational-isolation profile CryptoProver's Docker launcher reaches,
and like it is not yet a scoreable profile. Planned closure: `--unshare-net`
with the API reached through the wire proxy, credential moved to the proxy
side, a negative reachability receipt in the self-test.

**DEC-09 — what can be said about cheating.** The label the harness supports
today: runtime filesystem access to the solution history was blocked and
receipted; network egress was restricted, not blocked; training-data
contamination is unknown. Nothing stronger.

**DEC-12 — humans during a scored run.** Implemented as a seal: every
non-ignored file of the operator tree is hashed at run start
(`environment.seal`, manifest under `ledger/runs/<ts>/`), re-hashed before
each target and at the end. A change in the input set (Lean/Rust sources,
lock files, `harness/`, inventory, settings) is a violation recorded in
`provenance.seal`; a change elsewhere is drift. Accepted merge-backs are
expected and excluded.

**Open question "how are parallel agents isolated" — answered.** One sealed
slot, one sandbox, one config dir per job; file groups never span slots;
merge-back is a copy under a lock. Records with different `jobs` are not
directly comparable (CPU contention).

### Proposed or open, nothing implemented

| Decision | What is missing |
| --- | --- |
| DEC-01/02/15 — repo contents, large-file storage, who reads raw data | transcripts and slots live under `ledger/` in the repo directory (gitignored); no hash manifest, no separate storage, no redaction |
| DEC-03 — Aeneas extraction | agents receive pinned extracted Lean; Rust-to-Lean is a separate experiment |
| DEC-04 — choosing `T` | `api_top.py` exists; the driver still takes every sorry in the inventory zones (equivalent under `S = T`, not in Phase 2) |
| DEC-05/06 — seed `S`, visibility of `Math/` | always `S = T`, `Math/` fully visible; no builder for `W = T \ S`, no minimal-`Math` mode, no hidden-reference channel |
| DEC-07 — agent roles | one agent fills one sorry; no writer/reviewer/prover split, no statement freeze step |
| DEC-13 — models and repeats | `--model` is required and recorded, but there is no `--repeats`; every target runs once per invocation and `report.py` does not aggregate success rates |
| DEC-18 — claim boundary | functional correctness only; the report does not yet print this boundary |
| "What event invalidates a run" | undefined; `agent_error{deadline}`, baseline timeouts, host restarts are recorded but not classified |

## 5. Known gaps in the mechanics (not decisions)

- Slot workspaces are ~0.8 GB each and are left in `ledger/runs/<ts>/slot*/work`
  after a run; there is no automatic cleanup.
- The gate's `lake build` runs on the host in the slot; with `--jobs 2` two
  builds compete for cores.
- Multi-round logic (`--resume`, stall reset, bloat reset) has been exercised
  only in short smoke runs (`--max-turns` 2–6). The first real shakeout is
  still step 1 of `harness_plan.md`.
- The Phase-2 agent loop (`resynth.py` into the driver, N1 audit as a gate,
  G3 toolchain-file hashes) does not exist.

## 6. Commands

```
# what would run
python3 harness/driver.py --zones specs --dry-run

# Scalar slice, two parallel agents, commit each accept
python3 harness/driver.py --match Specs/Scalar/ --jobs 2 \
    --run-config harness/limits.default.json --commit

# whole-T verdict after a batch
python3 harness/replay.py --ref HEAD --out ledger/replay/<name>.json
python3 harness/report.py --zones specs,aux --replay ledger/replay/<name>.json
```
