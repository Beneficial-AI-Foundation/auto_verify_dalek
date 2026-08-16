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
