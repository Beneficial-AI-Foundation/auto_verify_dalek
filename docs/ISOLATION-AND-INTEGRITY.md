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
useful design precedents.

## Threat model

| Threat | Example | Required control and evidence |
| --- | --- | --- |
| Runtime retrieval | Browser, `git fetch`, package download, public code search, or an undeclared model-tool call | Deny all egress except an authenticated inference broker; record allow/deny logs and a negative reachability test. |
| Git and filesystem leakage | A worktree points to an object store containing removed proofs; reflogs, remotes, caches, or sibling mounts reveal them | Build a new repository from copied working-tree bytes, without `.git`, `target`, credential files, or sibling directories; audit refs, remotes, reflogs, and unreachable objects. |
| Reference-material leakage | The container includes `dalek-lite`, the full Lean verification repository, old run output, or generated proof caches | Use an explicit allowlist of input paths and hashes; mount only the sealed task bundle, private scratch space, and an append-only result channel. |
| Support-closure leakage | Copying a required Math file also exposes helpful lemmas, comments, or a withheld top-level reference statement | Compute a declaration-level closure where possible; distinguish elaboration support from the semantic Math budget; scan the sealed agent bundle against the verifier-only reference inventory. |
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
record the source revision, Aeneas/probe outputs, top-level universe `T`,
supplied seed `S`, derived withheld set `W = T \ S`, target-visibility and
support-closure policies, allowed Lean declarations/files, task manifest,
toolchain, package locks, and hashes for every input. It emits an agent bundle
that contains no reference statement or proof for `W`, plus a separately
stored verifier-only reference manifest for post-run assessment. The builder is
where network access, if any, is allowed; the scored agent runner is not a
general development environment.

The bundle must be made from copied working-tree bytes. Do **not** provide a
shared `git worktree`: its `.git` pointer can reach the parent repository's
object store, including deleted or unreferenced proofs. Instead:

1. Copy only allowlisted task bytes into a new directory, excluding `.git`,
   `target`, result directories, credentials, editor state, and sibling clones.
   When a whole source file contains both required support and hidden reference
   material, slice declarations or fail the build rather than copying the file
   opportunistically.
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
  "top_level_universe_sha256": "...",
  "allowed_spec_ids_sha256": "...",
  "withheld_spec_ids_sha256": "...",
  "support_closure_sha256": "...",
  "reference_manifest_mounted_in_agent": false,
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
| Contract state | A supplied contract in `S` changes, or a generated contract in `W` changes after reviewer acceptance and canonical freezing | Canonicalise elaborated statements when feasible, record the supplied/generated status, and hash source-level definitions as a second check. |
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
6. How will the builder prove that its support closure contains everything
   needed to elaborate the seed but no hidden reference statement or semantic
   lemma outside the declared Math budget?
