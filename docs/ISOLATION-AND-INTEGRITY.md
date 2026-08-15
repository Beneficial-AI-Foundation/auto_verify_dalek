<!-- generated-by: gsd-doc-writer -->
# Isolation and integrity

This document defines the evidence threshold for a curve25519-dalek Lean
formalisation experiment. Its purpose is not to accuse a model, an author, or a
repository of misconduct. It is to make the experiment's claim legible: an
accepted result should be reproducible from a declared input bundle, rather
than relying on trust that an agent could not obtain an existing solution.

## Claim boundary

The motivating [CryptoProver paper](https://arxiv.org/abs/2608.00965v1) reports
that its proof-and-specification run removed original proof bodies from the
machine, used a network-sealed container and fresh sessions, rejected history
recovery and fetch attempts, and applied mechanical integrity gates. Those are
useful design precedents. They are not, by themselves, an independently
reproducible sterility certificate for this project.

### Why the public-solution chronology matters

The concern is concrete, not hypothetical. The paper's reference [7] points to
[BAIF's `dalek-lite` PR #774](https://github.com/Beneficial-AI-Foundation/dalek-lite/pull/774),
which GitHub records as public and merged on 26 March 2026. The paper artifact's
[canonical record of the headline 11.4-hour run](https://github.com/ChuyueSun/CryptoProver/blob/e9f29b6b6fb98ace8bfedeab249fb2f23bc59c04/docs/run_stats/stage3_certificate_record.md)
dates its two attempts to 2–3 July 2026. The cited BAIF solution tree was
therefore public before the recorded run. That chronology makes runtime
isolation and honest contamination language mandatory; it does not establish
that the model or authors actually accessed the solution.

The paper gives a substantive runtime answer: it says the original proof
bodies were absent from the machine, describes a network seal, uses fresh
sessions, and adds a history-recovery gate; its baseline trace reports five
fetch attempts and 38 history probes blocked by the seal. Those controls address
channels available *during* a run if the stated boundary and logs are complete.
They do not answer whether a hosted model had incorporated public material
before execution, and a command-pattern gate alone would not substitute for an
isolated filesystem and object store.

| Question | Evidence reported by the paper | Evidence required here |
| --- | --- | --- |
| Were reference proof bodies readable locally? | The paper says they were absent from the machine for the proof-and-specification run. | An allowlisted bundle manifest, mount inventory, isolated Git-object audit, and independent inspection. |
| Could the agent fetch a solution during the run? | The paper reports a network seal and blocked fetch/history attempts. | Provider-only egress enforcement, allow/deny logs, negative connectivity tests, and complete launcher receipts. |
| Could Git recover deleted proof objects? | The paper says the bodies were absent and also used a `git-recovery` command gate. | A fresh isolated object store with no remotes, reflogs, unexpected refs, or unreachable solution objects. |
| Could the model already know a public solution? | Runtime gates cannot establish this. | Label training contamination unknown, disclose the public timeline/model identity, and use held-out controls where possible. |

The public `dalek-lite` Verus formalisation and
`curve25519-dalek-lean-verify` Lean formalisation are therefore treated as
known contamination threats. Their existence is not evidence that the paper or
any future run cheated. A serious evaluation must publish enough machine-
readable evidence for another reviewer to test the stated isolation boundary.

The current, later `CryptoProver` checkout is also informative but must not be
silently substituted for the paper experiment. Its
[`docker/README.md`](https://github.com/ChuyueSun/CryptoProver/blob/e9f29b6b6fb98ace8bfedeab249fb2f23bc59c04/docker/README.md) explicitly labels the
container profile as **not** `scoreable:true`: general network egress remains
open and usage auditing is not sealed on every launcher exit path. That is an
honest limitation of a post-paper implementation snapshot, not a retroactive
claim about the paper's execution environment.

The strongest honest result wording is: **the run reconstructed an accepted
Lean development under the declared runtime-isolation boundary and trusted
base**. It must not be described as proving that the model had no pretraining
knowledge of public solutions, nor as establishing cryptographic security
beyond the checked functional statements.

## Threat model

| Threat | Example | Required control and evidence |
| --- | --- | --- |
| Runtime retrieval | Browser, `git fetch`, package download, public code search, or an undeclared model-tool call | Deny all egress except an authenticated inference broker; record allow/deny logs and a negative reachability test. |
| Git and filesystem leakage | A worktree points to an object store containing removed proofs; reflogs, remotes, caches, or sibling mounts reveal them | Build a new repository from copied working-tree bytes, without `.git`, `target`, credential files, or sibling directories; audit refs, remotes, reflogs, and unreachable objects. |
| Reference-material leakage | The container includes `dalek-lite`, the full Lean verification repository, old run output, or generated proof caches | Use an explicit allowlist of input paths and hashes; mount only the sealed task bundle, private scratch space, and an append-only result channel. |
| Harness tampering | The agent changes a checker, frozen baseline, model wrapper, or result classification | Keep harness, gate configuration, toolchain, and frozen inputs read-only and outside agent write authority; independently replay the candidate. |
| Specification laundering | A proof succeeds only because contracts were weakened, definitions were hollowed out, or an implication became vacuous | Canonicalise and hash frozen statements and specification bodies; enforce approved target changes only and run adequacy checks for generated specifications. |
| Lean escape hatches | `sorry`, a new axiom, `unsafe`, `implemented_by`, `extern`, untrusted evaluator shortcuts, or an unreviewed macro/plugin | Parse and compare declarations plus source text against an explicit baseline and allowlist; rebuild cleanly with a pinned toolchain. |
| Cache or build poisoning | A precompiled artifact, altered lake cache, environment variable, or plugin changes what is checked | Start verification from a fresh image with controlled caches; record hashes of source, lock files, toolchain, compiler output, and verifier command. |
| Training-data contamination | A hosted model memorised a public proof before the run | Cannot be ruled out by a runtime sandbox. Disclose it, use post-cutoff/private holdouts where possible, and avoid claims of clean-room novelty. |

## Required sealed execution boundary

The proposed architecture has three separately owned stages:

```text
offline bundle builder        inference broker             independent verifier
---------------------         ----------------             --------------------
source + tool pins ──> sealed task image ──> agent scratch ──> candidate patch
       │                         │                                 │
       └── sterility manifest    └── usage/egress receipt          └── fresh replay
```

### 1. Build the task bundle offline

The trusted builder resolves dependencies, runs the declared extraction and
target-selection tools, and produces a content-addressed task bundle. It must
record the source revision, Aeneas/probe outputs, allowed Lean files, task
manifest, toolchain, package locks, and hashes for every input. The builder is
where network access, if any, is allowed; the scored agent runner is not a
general development environment.

The bundle must be made from copied working-tree bytes. Do **not** provide a
shared `git worktree`: its `.git` pointer can reach the parent repository's
object store, including deleted or unreferenced proofs. Instead:

1. Copy only allowlisted task bytes into a new directory, excluding `.git`,
   `target`, result directories, credentials, editor state, and sibling clones.
2. Run `git init` in that directory and create one sealed baseline commit.
3. Remove remotes and non-baseline refs; ensure detached or single-branch
   history has no parent containing reference material.
4. Run `git fsck --no-reflogs --unreachable` and record that no unexpected
   objects remain. Check `git remote -v`, `git reflog`, and `git show-ref` as
   part of the receipt.

This is stronger than merely stripping visible history, and mirrors the
isolated-object-store reasoning documented in CryptoProver's container design.

### 2. Run the agent with minimal authority

The agent container should receive only:

- a read-only sealed bundle, including the exact editable-target policy;
- a writable per-run scratch/work directory;
- a write-only or append-only result export; and
- an inference endpoint reachable through a dedicated broker.

The container must not mount the host checkout, home directory, SSH agent,
cloud credentials, Docker socket, shared package caches, sibling repositories,
or a writable harness. Run it as an unprivileged user with a read-only root
filesystem where practical, no host networking, no privileged capabilities,
and resource/time limits. Per-agent work and compiler caches must be isolated:
sharing a writable `target` or package cache creates both cross-run leakage and
nondeterministic interference.

The inference broker is the only permitted network route. It should accept
requests only to declared provider endpoints, attach a run ID, reject arbitrary
URLs and DNS, and emit an append-only request/response-metadata and usage log.
Provider credentials stay at the broker; the agent receives no reusable API key.
If the chosen model client cannot be constrained to that route, the resulting
run is exploratory rather than scoreable.

### 3. Verify outside the agent boundary

A separate verifier rebuilds the submitted candidate in a new container from
the sealed input and the exported patch, not from the agent's filesystem. It
has no model credentials and does not accept a precompiled target directory.
It recomputes all hashes, executes the full agreed Lean check, runs gates, and
writes the final status. Acceptance is an outcome of this verifier, never an
agent self-report or a green terminal excerpt.

At least one replay should be performed on an independently created fresh
bundle/image. A replay failure makes the original result non-reproducible,
even if the original agent environment reported success.

## Sterility receipt

Each run must emit a signed or otherwise tamper-evident JSON receipt. A PR may
show a human summary, but the JSON is the authoritative evidence. At minimum it
contains:

```json
{
  "schema_version": 1,
  "run_id": "content-addressed identifier",
  "input_manifest_sha256": "...",
  "source_revision": "...",
  "image_digest": "...",
  "lean_toolchain": "...",
  "allowed_mounts": ["/task:ro", "/scratch:rw", "/results:append-only"],
  "network_policy": "provider-broker-only",
  "egress_audit": {"allowed": [], "denied": [], "negative_test": "pass"},
  "git_audit": {"remotes": [], "unexpected_refs": [], "unreachable_objects": []},
  "frozen_file_hashes": {"...": "..."},
  "baseline_trust_hash": "...",
  "candidate_patch_sha256": "...",
  "verification": {"fresh_replay": "pass", "full_build": "pass"},
  "usage_receipt": {"complete": true, "provider": "declared separately"}
}
```

The actual schema should include timestamps, command hashes, exit codes,
resource limits, model identifier, prompt/template hashes, and explicit
failure labels. Sensitive prompt content or provider responses may be stored
under access controls, but the public receipt must say what is withheld and
why. Missing evidence is a failed or unscored run, not a detail filled in by
narrative.

## Integrity gates

Gates compare a candidate to the frozen baseline and fail closed. They apply to
all files in the declared scope, not only the target file.

| Gate | Reject when | Notes |
| --- | --- | --- |
| Completion | Any task-scope `sorry`, `admit`, placeholder proof, or unresolved error remains | Count declarations after elaboration where possible; text scans are a supplementary check. |
| Trust-base | A new axiom/theorem-as-axiom, unsafe declaration, or trusted-kernel assumption is introduced | Compare exact declarations and transitive trust closure to the baseline. Existing, disclosed assumptions are not silently reclassified. |
| Foreign implementation | `implemented_by`, `extern`, code generation, native linkage, or an unapproved opaque implementation bypasses the intended proof | Use a declaration and source allowlist. Exceptions need a reviewed identifier, rationale, and baseline hash. |
| Frozen statement | A frozen theorem/specification signature, proposition, definition body, or namespace binding changes | Canonicalise elaborated statements when feasible and hash source-level definitions as a second check. |
| Tooling | Lean/Lake/mathlib versions, manifest/lock files, tactics, macros, plugins, checker scripts, or gate configuration change | The agent has no write access; the verifier nevertheless checks image and file hashes. |
| Scope | A candidate edits a non-editable file, changes generated extraction output, or adds a helper outside its declared allowance | Enforce at patch import and compare the whole tree. |
| Environment | Unapproved process, mount, environment variable, network request, package download, or cache write is observed | Record container policy and command/egress audit; do not rely only on an agent prompt. |
| Fresh rebuild | The candidate only succeeds with agent-produced cache artifacts or in the original process | Rebuild from source in a newly created verifier environment. |

### Explicit Lean policy

The default policy forbids new occurrences of `sorry`, `admit`, `axiom`,
`unsafe`, `implemented_by`, `extern`, `opaque` declarations used as proof
escapes, unapproved `native_decide`, and new elaborator/tactic/macro/plugin
code. It also forbids edits to Lake configuration, toolchain files, generated
extraction inputs, gate code, and trusted Math files unless the experiment arm
expressly declares them editable.

Some constructs are legitimate in a pinned baseline. For example, a project
may intentionally retain a finite, reviewed mathematical assumption set, and a
computational tactic may be acceptable under a known Lean version. Such cases
require an **allowlist** containing the exact declaration/file, justification,
owner, baseline hash, and whether it contributes to the reported trusted base.
The gate then rejects additions, removals, or changes; it must not use a vague
"no suspicious code" rule.

Metaprogramming deserves extra care. A lexical ban alone is insufficient:
macros, elaborators, generated source, command quotations, environment
extensions, compiled plugins, and imported bytecode can alter what Lean sees.
The scoreable baseline should allow only pre-pinned, read-only packages and
disallow newly added imports, plugins, and generated modules. The fresh replay
must use only the declared toolchain and source closure.

## What sandboxing cannot establish

Runtime controls can provide evidence that a run did not fetch or read a local
reference during execution. They cannot show that a proprietary model was not
trained on, memorised, or otherwise influenced by the public `dalek-lite`,
CryptoProver, or Lean verification material. They also cannot make a weak or
inadequate top-level specification into a meaningful correctness claim.

Mitigations are still useful: disclose model and release dates; use private or
post-training-cutoff held-out targets when available; run multiple models;
compare outputs for suspicious overlap with known references; and publish
negative controls. A similarity check may find copying but cannot prove its
absence. None of these measures converts the result into a proof of
decontamination.
Reports should distinguish:

- **runtime-isolated reconstruction** — supported by a complete sterility
  receipt and fresh replay;
- **reference-aware or reference-assisted experiment** — inputs intentionally
  include prior specifications, mathematical infrastructure, or proof clues;
- **training-contamination unknown** — the normal status for public targets and
  closed-weight hosted models.

This distinction lets the project measure useful automation without promising a
clean-room property that it cannot evidence.

## Review questions

1. What is the minimal evidence package that makes a run scoreable for this
   repository: container recipe, receipt, logs, replay, or all of them?
2. Which Lean features belong in the first baseline allowlist, particularly
   `native_decide` and existing Math assumptions?
3. Can the selected inference provider be brokered and usage-audited without
   exposing credentials to the agent?
4. Which targets can plausibly be held out from model training, and how should
   we label all other results?
5. Who owns the offline bundle builder and the independent verifier, so that an
   agent run cannot modify the authority that accepts it?
