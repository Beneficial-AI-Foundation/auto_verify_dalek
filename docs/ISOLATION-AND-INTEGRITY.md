# Isolation and integrity

Known BAIF solutions are public. A scored agent must not be able to read them
during a run.

The [CryptoProver paper](https://arxiv.org/abs/2608.00965v1) and repository
describe stripped proof bodies, fresh agent sessions, Git-history checks,
containers, and mechanical checks. We still need to trace which controls
applied to the reported run and what evidence was saved. This matters because
related BAIF solutions were already public.

## What we can claim

With a good sandbox, we may say:

> The agent could read only the declared input bundle during the run, and the
> result passed a fresh independent check.

We cannot prove that a hosted model never saw public solutions during training.
That remains unknown and must be stated in every result.

## Main risks

| Risk | Example | Basic defence |
| --- | --- | --- |
| Network access | Web search, `git fetch`, package download | Block general network access; allow only the model broker. |
| Git history | Deleted proofs remain in Git objects or reflogs | Copy allowed files into a new repository with no old `.git`. |
| Local files | Sibling BAIF clones, old runs, host caches | Mount only the sealed bundle and a new work directory. |
| Input leakage | A required Math file also contains hidden lemmas or specs | Prefer declaration-level copies and scan the final bundle. |
| Checker changes | The agent edits the rules that judge its result | Keep the checker and inputs read-only and verify elsewhere. |
| Weak specifications | The agent proves something empty or much weaker | Review generated specs and compare with hidden references. |
| Lean shortcuts | New axioms, `unsafe`, plugins, native code tricks | Use an allowlist, inspect declarations, and rebuild cleanly. |
| Training data | The model memorised a public solution | Cannot be removed by the sandbox; disclose it. |

## Building a clean bundle

The bundle builder should:

1. copy only allowed source and tool files;
2. exclude `.git`, credentials, build caches, previous results, and sibling
   repositories;
3. create a new repository with one baseline commit;
4. record `T`, `S`, `W`, all visible declarations, and all hashes;
5. keep hidden statements and proofs for `W` in separate verifier data; and
6. scan the agent bundle for known solution text before sealing it.

Do not use a shared Git worktree. Its `.git` file can still reach the parent
object store.

## Running the agents

The sandbox receives only:

- a read-only input bundle;
- a new writable work directory;
- a result output channel; and
- access to the model through a restricted broker.

It should not receive the host home directory, SSH agent, Docker socket, cloud
keys, package caches, or unrestricted DNS/network access. Parallel agents
should not share writable caches or work directories.

The broker holds the model key, allows only the chosen provider, and records
usage. The agent should never receive a reusable API key.

## Harness-level controls (implemented in `harness/driver.py` + `agentproc.py`)

These are the host-side controls the driver enforces today. They are weaker
than a container (the agent still sees the host filesystem) and are recorded
in every ledger record under `isolation`.

| Leak | Control | Flag / evidence |
| --- | --- | --- |
| Operator's interactive Claude Code state: auto-memory under `~/.claude/projects/<repo-slug>/memory`, `~/.claude/settings.json` (model, hooks, plugins, skills), `~/.claude.json` MCP servers (`probe-lean`, …) | Every run gets a fresh `CLAUDE_CONFIG_DIR` seeded with **only** `.credentials.json`; all `CLAUDE*` env vars inherited from a parent Claude Code session are stripped | `ledger/runs/<ts>/claude_config/` (gitignored, mode 0700), `isolation.config_dir`, `isolation.credentials_seeded` |
| Repo-level `.claude/settings.local.json` (operator allowlist, e.g. `lake env`) and `CLAUDE.md` | `--setting-sources user` — only the (empty) fresh user dir is read | `isolation.setting_sources` |
| Network: web tools, `curl`/`wget`, `git fetch/pull/clone`, `lake update`, `lake env`, package installs | `--settings .claude/settings-offline.json` deny-list, on top of the `--allowedTools` allowlist (`Read,Grep,Glob,Edit,Write,Bash(lake build*),Bash(grep*)`) | `isolation.settings`, `isolation.settings_sha256` |
| Subagents (`Agent`/`Task` — write-capable, share the worktree, their turns are outside `--max-turns`), `WebFetch`/`WebSearch`, `Skill`, slash commands | `--tools <base names of the allowlist>` (currently `Read,Grep,Glob,Edit,Write,Bash`) filters tool *availability*; `--allowedTools` alone is only a permission allowlist and did not stop an `Agent Explore` spawn in the 2026-08-28 smoke run. `--disable-slash-commands` drops every skill. Verified: `system.init.tools == [Bash, Edit, Glob, Grep, Read, Write]`, `skills == []` | `isolation.tools`, `isolation.allowed_tools`, `isolation.disable_slash_commands` |
| Parallel agents sharing one worktree (`git status` scope check sees the other agent's edits, rollback deletes them, concurrent `lake build` in one `.lake/build`, one agent reads another's half-written proof) | `--jobs N`: one sealed slot per job — rsync of the tree without `.git`/`ledger/`/`.lake/packages`, `.lake/build` copied warm, `.lake/packages` symlinked to the main checkout and bound **read-only** in bwrap (8.5 GB shared, never copied), `git init` + one commit so the slot's history is exactly the baseline. Targets are grouped by file and a file group never spans slots; accepts are committed in the slot and copied back to the main checkout under a lock. Each slot has its own `CLAUDE_CONFIG_DIR` and sandbox self-test | `slot`, `isolation.work`, `isolation.sandbox_selftest.packages_readonly`, `limits.jobs` |
| A human (or stray process) edits an input file in the operator tree while a run is in progress — `harness/frozen/statements.json`, the prompt, `Math/` | Seal (DEC-12): every non-ignored file hashed at run start; input-set changes are violations, others drift; re-checked before each target and at run end; accepted merge-backs excluded | `environment.seal`, `provenance.seal`, `ledger/runs/<ts>/tree_manifest.json` |
| MCP servers from any config | `--strict-mcp-config` with no `--mcp-config` ⇒ zero servers (`system.init.mcp_servers == []` in the transcript) | `isolation.strict_mcp_config` |
| Model drift | The fresh config dir carries no `model` setting; the driver records the models actually billed per round | `rounds[].models_used`, `rounds[].cost_usd` |
| Host filesystem: this repo's `.git` history, sibling checkouts under `~`, `~/.cache/mathlib`, `~/.ssh`, `~/.gitconfig`, other targets' transcripts in `ledger/`, gate code and frozen statements in `harness/` | `--sandbox bwrap` (default): the agent process runs in a bubblewrap mount namespace — `/usr`, `/etc` read-only; fresh `/proc`, `/dev`, `/tmp`; `$HOME` is an empty tmpfs with only `~/.elan` and the `claude` binary bound read-only; the repo is bound read-write at its real path with `.git`, `ledger/`, `harness/` replaced by empty tmpfs; the run's `CLAUDE_CONFIG_DIR` is bound back in. Before the first target the driver runs 10 probes inside the sandbox (no `git rev-parse`, `$HOME` contents exactly the allowed set, `ledger/` holds only the config dir, `harness/` empty, `lake`/`claude` run, repo and config dir writable) and aborts if any fails | `isolation.sandbox`, `isolation.sandbox_hidden`, `isolation.sandbox_selftest` |

`--no-isolation` disables the fresh config dir for debugging and marks the
record `isolated: false`; `--sandbox none` keeps the config dir but drops the
mount namespace and marks `sandbox: "none"`. Neither kind of record is
scorable.

Slot workspaces are ~0.8 GB each (`.lake/build` copy) and are left under
`ledger/runs/<ts>/slot*/work` after the run as evidence; delete them when the
ledger record is all you need.

Not covered here (needs the container described below): network. bwrap runs
with `--share-net`, so the agent has the host's network (loopback is needed
for the wire proxy, egress for the API); DNS/egress control is still only the
permission deny-list. Also not covered: the reusable OAuth
credential handed to the agent.

## Final verification

The final verifier runs in a different fresh environment. It receives only the
sealed bundle, the candidate patch, and its own hidden reference data. It does
not reuse the agents' build output.

It checks the Lean build, remaining holes, statement hashes, trusted
assumptions, forbidden features, file scope, and bundle hashes. A result that
passes only inside the agent workspace is rejected.

## Lean rules

By default, reject new uses of:

- `sorry`, `admit`, and `axiom`;
- `unsafe`, `implemented_by`, `extern`, and external verification attributes;
- new macros, elaborators, tactics, plugins, or generated binaries used to
  avoid a proof; and
- edits to the toolchain, dependency lock files, generated functions, frozen
  inputs, or checker code.

Some existing assumptions may be allowed, but each one needs an exact name,
hash, reason, and owner. The run may use the listed baseline but may not expand
it.

## Evidence kept for each run

Keep a small machine-readable receipt containing:

- input, image, toolchain, and checker hashes;
- `T`, `S`, `W`, and compile-support hashes;
- mount and network policy;
- Git-history and bundle scans;
- model and usage record;
- candidate patch hash; and
- clean-build and fresh-replay results.

Missing evidence makes the run unscored. It should not be filled in later from
memory.

The PR should ask directly: what stopped the paper's agents from finding the
public BAIF solution, and which logs or sandbox records support that answer?
