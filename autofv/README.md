# AutoFV controller

`autofv` is the trusted host-side controller for a sealed formal-verification
experiment. It validates inputs before starting an agent worker and rejects
cross-boundary data that does not match the frozen experiment contract.

## Current entry points

- `experiment.py` defines the `autofv run` CLI and the programmatic
  `run_experiment(...)` seam.
- `../docker/autofv/toolchain-lock.json` pins the worker, tools, proxy route,
  receipt schema, verifier launcher, and control-bundle rules.
- `../tests/test_cli_snapshot.py` is the executable contract for this package.

The `native_decide` policy is intentionally `decision_required` until the
operator chooses a policy. AutoFV must not run while that choice is pending.

## Why `cryptography` is here

The sandbox can return untrusted model output, but it must not be able to forge
the receipt used for accounting or result state. The trusted model proxy signs
each canonical receipt with Ed25519. `experiment.py` uses `cryptography` only to
verify that signature and the pinned public-key identity before accepting the
receipt's response hash, token counts, or cost.

Only the public verification key is recorded in the toolchain lock. The private
signing key stays proxy-side and must never enter the repository, worker image,
agent volume, or exported artifacts. SHA-256 is also checked for canonical
identity and integrity, but a hash alone would not authenticate who issued a
receipt because an agent could recompute it.

## Local development

Use the repository virtual environment; do not install into system Python:

```bash
uv venv --python 3.12 .venv
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv sync --active
.venv/bin/python -m unittest tests.test_cli_snapshot
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv build --offline
```
