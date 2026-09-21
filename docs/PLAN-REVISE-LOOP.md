# Plan: joint multi-file revise loop for `prove_top_spec.py --bottom-up`

Status: phase 1 implemented (2026-09-18): joint batch construction, multi-file
session/gate/stall tracking, atomic publication, registry updates and immutable
partial snapshots. Structured diagnosis and recovery remain planned. Extends
the bottom-up mode described in [TOP-SPEC-RESULTS.md](TOP-SPEC-RESULTS.md).

## Problem

In bottom-up mode the agent designs internal specs itself. A locally proved spec
can still be too weak, or have the wrong shape, for a caller. The current
leaves-first implementation accepts one function at a time and gives every
session exactly one editable file. This makes scope and attribution simple, but
it prevents the agent from jointly designing mutually dependent specs and from
repairing a lower spec together with the caller that exposed the problem.

Wanted: give one agent session the explicitly enumerated spec files in the
target's dependency closure, plus the top-spec file, so it can synthesize and
prove the whole chain together. If the joint attempt still fails, use a
read-only diagnosis to decide whether an already accepted lower spec must be
revised, a statement invented in the current attempt is wrong, or the remaining
problem is proof search. Retry the whole joint batch with the relevant evidence.

The top theorem statement remains fixed. Function implementations and files
outside the explicit edit allowlist remain immutable.

## Core invariants

1. A joint session may edit multiple files, but only files in its explicit
   `editable_files` allowlist.
2. All files in a joint attempt are accepted and published atomically. No
   newly generated internal spec is published before the top theorem builds.
3. The supplied top statement is never exempt from G1 statement identity.
4. Existing declarations stay statement-identical unless a diagnosis names an
   exact, validated accepted spec theorem for revision.
5. Every newly planned internal function must end with a proved `@[progress]`
   theorem that mentions that function.
6. The complete project must pass `lake build` before the joint batch is
   accepted.
7. A session may not edit `Funs.lean`, implementation code, unrelated spec
   files, or any file outside its allowlist.

## Plan construction

For a selected kept top theorem:

1. Compute the transitive internal-function dependency closure as today.
2. Stop traversal at kept top specs and accepted entries in
   `internal_specs.json`; these are initially available but read-only.
3. For every still-unspecified internal function, resolve its spec path with
   `spec_path_for`. Several functions may map to the same file.
4. Create skeleton files and root imports in the sealed slot before the agent
   starts.
5. Build one joint batch:

```text
planned_fns    = all unspecified internal functions, in dependency order
spec_files     = unique spec paths for planned_fns
top_file       = file containing the fixed top theorem
editable_files = spec_files ∪ {top_file}
```

The dependency order is still included in the prompt as guidance, but it is no
longer a sequence of separately accepted steps. The agent may move between
lower specs, callers and the top proof as verification feedback requires.

`--max-joint-files N` may impose a preflight size limit (`0` = unlimited). If
the closure exceeds a nonzero limit, v1 stops with `joint_scope_too_large`
rather than silently changing the atomic full-closure experiment. A future
batched mode needs separate publication and boundary-spec semantics.

## Main loop

```text
batch       = plan_joint_batch(target)
attempt     = 1
recoveries  = 0
revision_targets = []
retry_note  = none

while true:
    outcome = run_joint(batch, revision_targets, retry_note)
    if outcome == accepted:
        publish_all_files_atomically(batch, revision_targets)
        succeed(plan)

    save_immutable_partial_snapshot(attempt)
    rollback_to_last_accepted_baseline()

    if outcome is not semantically diagnosable
       or recoveries == --max-recovery-cycles
       or plan wall-clock/cost budget is exhausted:
        fail(plan)

    diag = diagnose_joint(batch, outcome, partial_snapshot)
    recoveries += 1

    match diag.verdict:
      case "lower_spec":
        targets = validate accepted specs named by diag.revise
        if targets is empty: fail(plan, reason="diagnosis_unusable")
        revision_targets = union(revision_targets, targets)
        retry_note += accepted lower specs to strengthen, with evidence

      case "own_statement":
        if diag.fn is the fixed top theorem/function:
            fail(plan, reason="top_unprovable")
        if diag.fn is not a planned internal function:
            fail(plan, reason="diagnosis_unusable")
        retry_note += current-attempt statements to replace, with evidence

      case "proof_difficulty":
        if not --retry-on-difficulty:
            fail(plan, reason="proof_difficulty")
        retry_note += failed goals, diagnostics and useful partial work

      case _:
        fail(plan, reason="diagnosis_unusable")

    attempt += 1
```

`revision_targets` accumulates one or more previously accepted spec files until
the plan succeeds or stops. A later diagnosis of an additional problem must not
discard an earlier validated lower-spec repair requirement. The recovery
session revises all accumulated targets and repairs/completes the current caller
and top proof in the same session. This replaces the old one-file
`run_revise()` followed by a separate retry.

## Session types

| session | edits | tools | gate |
|---|---|---|---|
| **joint** | all explicitly listed batch files; on recovery, validated lower-spec files too | Read, Grep, Glob, Edit, Write, `lake build` | `joint` |
| **diagnose** | none | Read, Grep, Glob | parsed structured output |

There is no separate one-file revise session in v1. Revision is a capability of
a recovery joint session and is limited to the exact theorem names validated by
the harness.

## Joint session

### Prompt inputs

The joint prompt contains:

1. The fixed top theorem name, file and pretty-printed statement.
2. The complete internal call graph for the target, with functions listed in
   dependency order and direct caller/callee edges.
3. `planned_fns`, grouped by destination spec file.
4. The exact `editable_files` allowlist. Files outside it are read-only.
5. Accepted internal specs and kept top specs that are available but initially
   immutable, including theorem names and pretty-printed statements.
6. Relevant `Funs.lean` source ranges for every planned function.
7. On recovery, the diagnosis, verifier evidence, previous partial-snapshot
   manifest, and exact accepted theorem names that may be strengthened.

### Agent task

The agent must jointly:

- design a true, useful `@[progress]` spec for every function in
  `planned_fns`;
- prove every new spec without adding `sorry`;
- add the required imports between the allowed spec files;
- fill the fixed top theorem;
- revise validated accepted lower specs when the recovery prompt permits it;
- run `lake build` and repair any affected allowed caller in the same session.

The prompt should encourage dependency-order work, but it must not force the
agent to finish a lower file before inspecting or testing its callers. The main
benefit of the joint session is that spec shape can be refined against the
actual top-level obligation.

### Edit scope

Initial attempt:

```text
editable_files = planned spec files ∪ {top file}
g1_exempt       = ∅
```

Recovery after `lower_spec`:

```text
editable_files = planned spec files ∪ {top file}
                 ∪ files containing validated revision targets
g1_exempt       = exact validated revision theorem names
```

Adding new helper declarations and new spec theorems is allowed inside the
allowlist. Changing or removing any other existing declaration is forbidden.
The top theorem statement can never appear in `g1_exempt`.

## Joint gate

`driver.gate(mode="joint")` extends the existing spec/fill gates.

### G0: scope and forbidden constructs

- `changed_files(work)` must be a subset of `editable_files`.
- New files are allowed only when they are predeclared skeleton paths.
- Scan added lines in every changed file for forbidden declarations and
  attributes.
- `Funs.lean`, generated implementation code, harness files and frozen files
  are never editable.

### G1: statement identity over all editable modules

Before each attempt, fingerprint every module in `editable_files` after the
baseline slot builds. After the agent runs, fingerprint them again.

`stmt_diff(base, after, exempt=validated_revision_theorems)` must report no
other missing or changed declaration. Exemptions must not come directly from
model output. For each exemption, the harness verifies that:

- it is a fully qualified theorem name;
- it belongs to the diagnosed function's accepted registry entry;
- its current statement mentions that function;
- its file matches the registry path;
- it is not the top theorem or a kept fixed theorem.

New declarations do not require exemptions. Additive strengthening is preferred:
keep the old theorem and add a stronger theorem, especially when the old theorem
has callers outside the current batch.

### G2: proof and spec obligations

- The top file's `sorry` count must strictly decrease.
- No other editable file's `sorry` count may increase.
- For every function in `planned_fns`, the final fingerprints must contain at
  least one proved `@[progress]` theorem whose statement mentions the function.
- For every revised accepted function, the file must still contain at least one
  such theorem.
- The complete `lake build` must pass.
- Sorry migration across all files remains forbidden.

The gate returns structured data per function:

```text
result_specs[fn]  = all matching @[progress] theorem names and pp statements
added_specs[fn]   = matching theorems added by this attempt
changed_specs[fn] = exempt theorems whose statements changed
counts_after      = project sorry counts
broken_files      = files parsed from build diagnostics, on failure
build_error_tail  = bounded Lean error text, on failure
```

### Atomic acceptance

Only after every gate passes:

1. commit all changed allowed files in the slot as one joint commit;
2. copy all of them back to the bundle;
3. update all affected `internal_specs.json` entries from `result_specs`;
4. add root imports created for new spec modules;
5. optionally create one outer repository commit.

If the joint gate fails, none of the newly generated or revised specs is
published. This prevents a failed top-level plan from leaving behind locally
valid but globally useless specs.

## Diagnose session

Diagnosis runs after a semantically diagnosable joint failure in a fresh,
read-only session. Infrastructure errors, agent transport errors, scope
violations, forbidden constructs, G1 failures, sorry migration and kernel
budget failures are not semantic diagnoses.

Semantically diagnosable failures are an explicit allowlist, initially:

- exhausted rounds ending in `rejected_build` with valid Lean diagnostics;
- exhausted rounds ending in `rejected_sorry_remains`;
- a valid agent `END_REASON:LIMIT` with a partial snapshot;
- a final build/proof failure after the agent otherwise completed normally.

### Immutable partial snapshot

Before rollback, save every file in the attempt's edit scope:

```text
run_dir/partials/attempt-<n>/
  manifest.json
  files/<collision-free relative paths>
```

The manifest records original relative path, SHA-256, baseline SHA-256, whether
the file changed, and its associated functions. Snapshots are never overwritten.
They must be mounted read-only into the diagnose and retry sandboxes, or their
relevant contents must be embedded in the prompt.

### Diagnosis inputs

1. The partial snapshot and its manifest.
2. The fixed top statement and all attempted new spec statements recovered from
   the partial files' G1 fingerprints when they compile.
3. Bounded, structured build diagnostics with file and line information.
4. The last assistant message, `END_REASON`, round history and optional
   `BLOCKED_BY: <function>: <missing fact>` hints.
5. Accepted internal specs and kept fixed specs, with theorem names and `pp`.
6. The function call graph and relevant `Funs.lean` source ranges.

### Diagnosis questions

In order:

1. Is one of the statements invented in this failed joint attempt false or
   incompatible with its function body? If so, return `own_statement` and name
   the function.
2. If the attempted statements are true, is an already accepted, initially
   read-only lower spec missing facts needed by this batch? If so, return
   `lower_spec` and name the exact accepted theorem(s).
3. Otherwise return `proof_difficulty`.

A weak statement invented inside the failed joint attempt is
`own_statement`, not `lower_spec`, because it was never accepted. `lower_spec`
is reserved for specs already present in the accepted registry at the attempt's
baseline.

### Output contract

The final message ends with one fenced JSON block:

```json
{"verdict": "lower_spec | own_statement | proof_difficulty | unknown",
 "revise": [{"fn": "<lean name>", "theorem": "<accepted theorem name>",
             "missing": "<property needed by the joint batch>",
             "proposed_statement": "<suggestion only>"}],
 "own_statement": {"fn": "<planned function>",
                   "wrong_because": "<why it conflicts with the body>",
                   "proposed_statement": "<suggestion only>"},
 "evidence": [{"file": "<path>", "line": 0,
               "detail": "<goal, hypothesis or build diagnostic>"}]}
```

### Deterministic validation

- `lower_spec` requires one or more non-duplicate `revise` entries.
- Every `fn` must be an accepted internal spec reachable by this target.
- Every `theorem` must pass the exact registry/G1 membership checks described
  above.
- Naming a newly planned function is normalized to `own_statement`.
- Naming the fixed top theorem or a kept top spec produces
  `blocked_by_fixed_spec` and stops for human review.
- Naming anything else produces `unknown`.
- `--max-revise-files N` bounds how many distinct accepted spec files may be
  accumulated in the recovery allowlist for the whole plan; default 2.
- Repeating the same `(failing batch, theorem, missing)` revision target stops
  as `repeated_revision_target`.
- `own_statement.fn` must be in `planned_fns`. Naming the fixed top target is
  `top_unprovable`.

## Recovery joint session

A recovery is a fresh joint session over the original batch plus any validated
lower-spec files. It receives the original joint prompt and a canonical handoff:

- cause of recovery and validated verdict;
- immutable partial-snapshot path and hashes;
- exact lower theorem(s) allowed to change, if any;
- old `pp`, missing property and suggested replacement;
- structured build errors and relevant goals;
- compact round history;
- current accepted-baseline tree hash.

The partial files are evidence, not automatically restored. For
`proof_difficulty`, an implementation may optionally seed the retry from the
best integrity-clean partial snapshot instead of the baseline, but only after a
deterministic gate confirms that all statements and scope constraints remain
valid. Baseline retry is the v1 default.

## Dependents outside the joint batch

The recovery session can repair any caller already in its original batch. A
revised accepted spec may also have callers outside that batch.

v1 requires the full `lake build` to pass. If an in-place change breaks an
out-of-batch caller, the agent must use additive strengthening: keep the old
theorem and add a stronger one for the current batch.

v2 may expand the allowlist with deterministically discovered broken dependent
spec files and repair them in the same recovery session. Such expansion must be
bounded, recorded before the session starts, and must never include arbitrary
implementation or harness files.

## Budgets and stop rules

- `--max-plan-minutes N`: hard wall-clock budget for the entire plan, including
  agent sessions, diagnoses and all gates. Reserve enough time for a final full
  build before starting another agent session.
- `--max-recovery-cycles N` (default 2): total diagnose/recovery cycles.
- `--max-revise-files N` (default 2): accepted lower-spec files that the plan
  may accumulate across all recoveries.
- `--retry-on-difficulty` (default off): permit one recovery when diagnosis
  finds no bad statement.
- Joint and recovery sessions use `--rounds`, stall and context-reset rules.
- Diagnose uses `--diagnose-max-turns` and does not edit files, but its elapsed
  time counts against `--max-plan-minutes`.
- No nested diagnosis after an infrastructure or integrity failure.
- Repeated identical revision target, unusable diagnosis, fixed-spec blockage,
  or exhausted budget stops the plan.

## Progress and session reset

Multi-file stall detection hashes every file in the edit allowlist. A round is
byte-stalled only if none of them changes.

Where available, prefer semantic progress signals over hashes:

- total project sorry count;
- number of planned functions with an accepted-shaped `@[progress]` theorem;
- number and location set of Lean build errors;
- whether the top theorem's sorry disappeared;
- best integrity-clean partial state.

Fresh-session reset preserves disk state within `driver.run_rounds` and carries
a runner-generated handoff. A recovery after diagnosis is always a fresh
session because its edit authority and assumptions may have changed.

## Registry and ledger

### `internal_specs.json`

Each accepted function entry stores:

```json
{"path": "<spec file>",
 "theorems": ["<fully qualified theorem>"],
 "pp": {"<theorem>": "<pretty-printed statement>"},
 "run_id": "<run>",
 "revisions": [{"attempt": 2,
                "old_pp": {"<theorem>": "<statement>"},
                "new_pp": {"<theorem>": "<statement>"},
                "missing": "<diagnosed fact>"}]}
```

Entries are written only after atomic joint acceptance.

### Ledger

One record per session, all sharing `plan.id`:

- `plan.mode = "joint" | "diagnose" | "recovery"`;
- attempt number and recovery cause;
- planned functions, editable-file allowlist and validated G1 exemptions;
- prompt SHA-256 and baseline tree hash;
- transcript/session IDs, round history and usage;
- per-file before/after hashes;
- immutable partial-snapshot manifest on failure;
- structured diagnostics and gate outcome;
- complete `result_specs` on acceptance;
- publication commit or atomic-copy result.

## Implementation steps

1. Generalize `driver.gate` from one `target_path` to an explicit set of
   `editable_paths`; scan scope, forbidden constructs, G1 and sorry deltas over
   the whole set. Add `mode="joint"` and exact `g1_exempt` validation hooks.
2. Generalize `driver.run_rounds` file hashing and stall detection to multiple
   files. Keep one session ID across normal rounds and generate a canonical
   handoff after reset.
3. Replace the leaves-first step list in `prove_top_spec.py` with
   `plan_joint_batch`: planned functions, path grouping, call graph and a single
   joint prompt.
4. Create all skeletons/root imports in the sealed slot before the G1 baseline;
   fingerprint every editable module.
5. Implement the joint gate's per-function `result_specs`, full build details
   and atomic accept/copy/registry update path.
6. Save immutable multi-file partial snapshots with manifests and expose them
   read-only to sandboxed sessions.
7. Implement structured diagnosis parsing and deterministic validation,
   including exact theorem membership and multi-target bounds.
8. Implement the recovery loop, dynamic validated allowlist expansion, total
   plan budget and ledger records.
9. Add semantic progress metrics where Lean diagnostics make them reliable;
   keep all-files hash stall as the fallback.

## Tests without an agent

1. Scope gate accepts changes to two allowlisted files and rejects a third.
2. G1 fingerprints all editable modules and never exempts the top theorem.
3. A diagnosis cannot exempt an unrelated theorem in the same file.
4. Joint gate requires a matching `@[progress]` theorem for every planned
   function, including two functions sharing one file.
5. Sorry accounting covers all allowlisted files and detects migration.
6. Atomic acceptance writes all files and registry entries together; injected
   copy/update failure publishes none of them.
7. A failed attempt produces immutable, uniquely named snapshots for every
   editable file with correct hashes.
8. First attempt with no accepted lower candidate rejects `lower_spec` but can
   retry `own_statement`.
9. A prior-run accepted spec can be added to a recovery by registry path even
   though it is not in `planned_fns`.
10. Multiple validated lower specs in distinct files can be revised in one
    recovery, up to `--max-revise-files`.
11. Infrastructure, transport, G1 and scope failures never invoke diagnosis.
12. Total plan budget prevents a new session when the final-build reserve would
    be consumed.
13. Multi-file stall requires all editable files to remain unchanged.
14. An out-of-batch dependent broken by in-place revision blocks acceptance;
    additive strengthening passes.

## Live trials

1. `identity_spec` with all currently missing dependency spec files and the top
   file in one joint session; expect the agent to refine lower statements while
   attempting the top proof.
2. Seed an accepted weak `from_limbs_spec` (`⦃ _ => True ⦄`), keep it initially
   read-only, and expect diagnosis plus a recovery session that edits both the
   lower-spec file and the current caller/top files.
3. Seed a false statement for a newly planned function in a partial attempt;
   expect `own_statement` and a full joint retry without G1 exemptions.
4. Use two mutually constraining dependency specs in different files; verify
   that one session can adjust both before atomic acceptance.

## Trade-offs and open points

- A joint prompt and workspace are larger, so context pressure is higher than
  in one-file sessions. `--max-joint-files` can reject an oversized task, and
  fresh-session handoffs bound context growth during an accepted-size task.
- Failure attribution is less local: several files may change in one round.
  Per-file hashes, structured diagnostics and diagnosis evidence are therefore
  mandatory.
- Atomic acceptance sacrifices reusable locally proved specs when the top proof
  fails. This is intentional: it prevents weak intermediate specs from being
  treated as globally useful. Immutable partial snapshots preserve the work for
  analysis and later retries.
- G1 cannot prove that an exempt replacement is logically stronger. Additive
  strengthening is preferred, and every recovery must still prove the complete
  joint batch and pass the full build.
- Whether `progress` chooses the intended theorem when several matching
  theorems exist must be tested against the pinned Aeneas version. Direct
  theorem use in the top/caller proofs may be more deterministic.
- Very large dependency closures may eventually require topologically ordered
  joint batches, but their publication and boundary-spec semantics are outside
  v1 and must be designed explicitly before implementation.
