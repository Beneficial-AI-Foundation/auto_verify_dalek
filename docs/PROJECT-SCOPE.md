# Project scope

## Goal

We want to test how much of the Lean formalisation of `curve25519-dalek` can be
done by agents from a small, clearly listed set of inputs.

The main question is:

> Given some top-level specifications, can the agents recover the missing
> specifications and complete all proofs without reading an existing solution?

This project is inspired by the
[CryptoProver paper](https://arxiv.org/abs/2608.00965v1), but it must have its
own rules, sandbox, and checks.

## Experiment types

These experiments answer different questions and should be reported separately.

### A. Proof recovery

All statements are given. The agents only fill proof holes. This is useful for
testing the prover, but it does not test specification discovery.

### B. All top-level specifications given

The Aeneas-generated Lean code and every top-level specification are given.
The agents write internal specifications and proofs. This is the first useful
baseline.

### C. Only some top-level specifications given

This is the main experiment.

- `T`: all top-level targets;
- `S ⊆ T`: the specifications given at the start; and
- `W = T \ S`: the specifications the agents must recover.

Each run gets a small JSON file naming `T`, `S`, and the allowed supporting
definitions. A deterministic script builds the starting workspace.

For a target in `W`, the Rust function name is always visible. We still need to
decide whether its translated Lean body from `Curve25519Dalek/Funs.lean` is
also visible.

Success means that every target in `T` has a good specification and a full
proof, and that the rest of the declared project work is also complete. If
smaller seeds are too difficult, `S = T` remains the default experiment.

### D. Rust-to-Lean

A later experiment may start from Rust and include Aeneas extraction. This is a
separate question from the size of `S` and should not be mixed into the first
results.

## What “top-level” means

Use `A → B` to mean “A calls or depends on B.” A target is top-level when no
other specified function calls it, directly or through helpers without their
own specifications. With this arrow direction, top-level targets are graph
sources.

The current file `.verilib/top_level_specs.json` contains 94 candidates from
263 specifications (35.7%). This list is exploratory until a checked-in script
can reproduce it.

## Main questions

1. How should we build the input bundle for each seed `S`?
2. Which definitions from `Math/` are required just to make the input compile?
3. Should agents also see the translated Lean body for missing targets?
4. Does a writer → reviewer → prover workflow work better than one long agent
   session?
5. How many repeated runs are enough to call a seed reliable?
6. What is the smallest seed that works under a fixed budget?
7. How do we block known solutions without removing useful Lean documentation?

## What belongs in this repository

Keep the small, reviewable parts here:

- documentation and decisions;
- JSON schemas and experiment manifests;
- scripts that build input bundles;
- agent prompts and workflow code;
- sandbox and verification code; and
- short result summaries with hashes.

Large run outputs should live in separate storage: transcripts, model replies,
patches, build logs, sandbox logs, and usage records. This repository should
link to them and record their hashes.

Runs should use metered project or institutional API access. They should not
depend on a contributor's personal subscription.

## Out of scope for the first experiments

The first result is about Lean functional correctness under the listed
assumptions. It does not by itself prove constant-time behaviour, side-channel
resistance, Rust memory safety, or the security of Curve25519.

## Short glossary

**Input bundle:** Everything the agents can read during a run.

**Compile support:** Imports, types, structures, notation, and definitions
needed for the starting files to compile. This should not silently include
helpful lemmas or hidden specifications.

**Trusted assumptions:** Existing axioms and external declarations that the run
is allowed to use. A run may not add new ones.

**Scored run:** One run made from a fixed input JSON, with recorded limits and
a fresh final check.
