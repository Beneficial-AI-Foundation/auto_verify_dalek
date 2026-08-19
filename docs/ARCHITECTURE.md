# Proposed architecture

The system has four parts. The agents may edit proofs and generated
specifications, but they may not edit their inputs or the checks that decide
whether a run passed.

```text
pinned source and tools
          |
          v
   1. bundle builder  ----> hidden reference data
          |
          v
   2. sandboxed agents
          |
          v
   3. fresh verifier
          |
          v
   4. result storage
```

## 1. Bundle builder

The builder runs before the agents. It should:

1. pin the Rust, Lean, Aeneas, probe, and toolchain versions;
2. generate the full top-level target set `T`;
3. read the run JSON and its supplied seed `S`;
4. compute `W = T \ S`;
5. include only the allowed code, specifications, and compile support; and
6. write a manifest with the files, declarations, settings, and hashes.

The builder produces two outputs:

- the **agent bundle**, which contains the allowed inputs; and
- the **reference data**, which may contain the original specifications for
  `W` and is available only to the final verifier.

This split matters because current `harness/resynth.py` manifests keep original
statements for comparison. Those manifests must not be copied directly into a
sealed agent workspace.

## 2. Sandboxed agents

Each run starts in a fresh workspace. Agents can edit only the candidate Lean
files. They must not see:

- the host checkout or its `.git` history;
- sibling BAIF repositories;
- previous run outputs;
- API keys or host caches; or
- unrestricted network access.

Model requests should go through a small broker that records usage and blocks
other destinations.

A role-based run may use:

1. a specification writer;
2. an independent specification reviewer;
3. up to a fixed number of rewrite/review rounds; and
4. fresh prover agents after each accepted statement is frozen.

The exact prompts and round limit are part of the run settings.

## 3. Fresh verifier

The verifier starts from a clean copy of the bundle plus the candidate patch.
It does not reuse the agents' build cache.

It checks that:

- the whole declared Lean target builds;
- every required `sorry` is gone;
- all targets in `T` have specifications and proofs;
- supplied specifications in `S` did not change;
- generated specifications in `W` passed the chosen quality checks;
- no new axioms or forbidden Lean shortcuts were added; and
- the bundle, toolchain, and checker files did not change.

Only this verifier can mark a run as passed.

## 4. Result storage

Git should hold small files that colleagues can review: manifests, schemas,
scripts, checks, and result summaries.

Large files should go to separate storage: transcripts, patches, build logs,
sandbox logs, and provider usage records. Git stores a link and hash for each
one. Failed runs must be kept in the result summary too.

## Suggested repository layout

```text
docs/                 # scope, protocol, checks, decisions
experiment/
  manifests/          # run input JSON files
  schemas/            # JSON formats
harness/
  builder/            # creates sealed bundles
  runner/             # starts agents in the sandbox
  gates/              # Lean and integrity checks
  verifier/           # clean final build and verdict
runs/
  index/               # small summaries and artifact links
```

The existing `harness/`, `.verilib/`, and `Curve25519Dalek/` directories are
useful starting points. They do not yet implement the full design above.

Open choices are listed in [DECISIONS.md](DECISIONS.md).
