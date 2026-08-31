# AutoFV controller

`autofv` runs the trusted, host-side part of a sealed formal-verification
experiment. It validates the target and run config before starting an agent
worker. It also checks data returned across the sandbox boundary against the
pinned experiment contract.

## Current entry points

- `experiment.py` defines the `autofv run` CLI and the programmatic
  `run_experiment(...)` seam.
- `../docker/autofv/toolchain-lock.json` pins the worker, tools, proxy route,
  receipt schema, verifier launcher, and control-bundle rules.
- `../tests/test_cli_snapshot.py` is the executable contract for this package.

## `native_decide` policy

For the current vertical slice, AutoFV allows `native_decide` in both the input
project and agent edits. The result must list every use, its source hashes and
whether it came from the input or the agent. It must also list the compiler
assumptions behind `native_decide`. The final claim is limited to functional
correctness under those recorded assumptions.

All checks go through `evaluate_native_decide_policy(...)`. It returns the same
four hash-bound fields to every downstream gate: `native_decide_policy`,
`native_decide_policy_sha256`, `native_decide_uses`, and
`compiler_assumptions`. A future policy can replace the current
`audited_use_inventory` criterion with a count cap or a named-spec allowlist.
The downstream gates keep using these four fields instead of choosing their own
defaults.

## Why `cryptography` is here

AutoFV treats all sandbox output as untrusted. The receipt used for accounting
and result state must come from the model proxy, which signs each receipt with
Ed25519. `experiment.py` uses `cryptography` to verify that signature and the
pinned public key before accepting the response hash, token counts, or cost.

Only the public verification key is recorded in the toolchain lock. The private
signing key stays proxy-side and must never enter the repository, worker image,
agent volume, or exported artifacts. SHA-256 shows that the receipt bytes have
not changed. Ed25519 shows that the receipt came from the proxy rather than the
agent.

## Local development

Use the repository virtual environment; do not install into system Python:

```bash
uv venv --python 3.12 .venv
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv sync --active
.venv/bin/python -m unittest tests.test_cli_snapshot
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv build --offline
```
