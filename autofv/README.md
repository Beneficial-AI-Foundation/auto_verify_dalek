# AutoFV

AutoFV is the trusted host-side controller for experiments that ask an agent
to recover Lean specifications and proofs inside a sealed Linux worker.

This page describes the code as it exists on 3 September 2026. Phase 1 is
still in progress. Keep this file and [README.html](README.html) in sync.

## Status

The focused local contract set passes. One broader native-policy test now
reaches Lima unexpectedly and fails in restricted environments. No production
experiment has completed.

| Area | Current evidence |
| --- | --- |
| Input, policy, image, and receipt contracts | Focused local checks pass; the full CLI suite has one worker-boundary regression |
| Pinned probe output | Captured from the toolchain image and checked byte-for-byte |
| Fixed proxy route under `runsc` | Tested against the local deterministic proxy fixture |
| End-to-end controller flow | Tested with worker, proxy, persistence, and verifier functions replaced by test doubles |
| Provider model call and billed usage | Not run |
| Full agent worker to clean-verifier experiment | Not run |
| Malformed probe and graph mutation matrix | Next task in Plan 01-05 |

The current `$0.022350` result is fixture data. It is the sum of eight
handwritten receipt amounts for 2,235 invented tokens at a flat
`$0.000010` per token. It is not provider spend. The fixture uses
`fixture-model-v1`; no API key or provider response takes part in that test.
The values live in
[`tests/fixtures/model-proxy/diamond-responses.json`](../tests/fixtures/model-proxy/diamond-responses.json)
and are repeated as expectations in the proxy fixture test.

Receipt validation rejects changes to a receipt's run identity, sequence,
request hash, response hash, usage, cost, or signature. A valid fixture
signature proves that the local fixture has not changed. A production proxy
receipt will be needed before `cost_usd` can mean measured spend.

## Intended run

```text
trusted host
  autofv run
    ├── copy the approved target and control files into a fresh Docker volume
    ├── run the pinned image with gVisor runsc in the autofv-agent Lima VM
    ├── retain and validate probe-rust and probe-aeneas output
    ├── send fixed-shape requests through one trusted proxy route
    ├── accept one-file candidates only after deterministic checks
    ├── export the accepted tree to the separate autofv-verifier Lima VM
    └── write result.json and an L0 evidence receipt
```

The worker must not receive the developer checkout, a container runtime
socket, provider credentials, the complete proxy response program, or the
hidden verifier reference. The trusted host copies an allowlisted control
bundle into the managed volume. Only the accepted source tree crosses into
the verifier.

The tracer test in
[`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) exercises
the controller order and failure rules with test doubles. It records the
orchestration contract. It does not exercise the two VMs or provider path.

## Local setup

AutoFV requires Python 3.12. Use the repository virtual environment and `uv`;
do not install packages into the system Python.

```bash
uv venv --python 3.12 .venv
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv sync
```

Run the fast local contracts:

```bash
.venv/bin/python -m unittest -v \
  tests.test_phase1_diamond.TracerTests
```

The full `tests.test_cli_snapshot` module is not a local-only check at this
commit. Its
`test_launch_exports_hash_bound_policy_without_environment_fallback` test now
enters `worker.prepare_run(...)` and tries to contact Lima. Fix that boundary
before adding the module back to the fast command.

Show the CLI without starting a worker:

```bash
.venv/bin/python -m autofv.experiment --help
```

## Experiment command

The current CLI form is:

```bash
.venv/bin/python -m autofv.experiment run \
  --target "$PWD/tests/fixtures/diamond" \
  --run-config "$PWD/tests/fixtures/diamond/run.json"
```

It currently expects all of the following:

- the `autofv-agent` and `autofv-verifier` Lima instances;
- the pinned image and `runsc-hardened` runtime in the agent VM;
- `AUTOFV_PROXY_BASE` in the trusted host process;
- a run-scoped `AUTOFV_RUN_TOKEN` in the trusted host process;
- a proxy that implements the locked `POST /v1/autofv/infer` contract and
  signs usage receipts with the pinned key.

The provider credential belongs in the proxy service. Do not put it in this
repository, either VM, the container, or either environment variable above.
The current repository does not include a production proxy deployment or a
provider signing trace, so this command is still an integration target.
The key pinned today belongs to the local fixture. A production proxy needs a
separate signing key and a corresponding lock update.

The CLI prints the result JSON. The current worker also writes `result.json`
and `evidence/l0.json` under a host temporary run directory. A stable output
directory has not been added to the CLI yet.

## What the result fields mean today

| Field | Meaning in the current diamond tracer |
| --- | --- |
| `outcome` | The controller reached a matching verifier `PASS` |
| `targets_verified_final` | Fixture-specific value: `1` on success |
| `internal_specs_accepted` | Fixture-specific value: `2` on success |
| `internal_proofs_accepted` | Fixture-specific value: `2` on success |
| `proxy_requests` | Number of accepted signed receipts |
| `cost_usd` | Sum of `cost.amount` from accepted receipts; synthetic for fixture receipts |
| hash fields | Identities of the snapshot, probes, policy, image, control bundle, accepted tree, and verifier report |
| `events` | Ordered controller transitions, not a provider or VM execution trace by itself |

The three accepted-count fields are currently fixed for the diamond fixture.
They do not yet measure an arbitrary target.

## Where to change things

| Change | File | Notes |
| --- | --- | --- |
| Model name, wall-clock limit, cost ceiling | [`tests/fixtures/diamond/run.json`](../tests/fixtures/diamond/run.json) | Per-run input. `max_cost_usd` stops on signed receipt totals. `max_wall_seconds` is validated but not enforced yet. |
| Target function, supplied specification, verifier command | [`tests/fixtures/diamond/autofv.json`](../tests/fixtures/diamond/autofv.json) | Per-target input. The verifier command is an argv array, not shell text. |
| Image digest, tool versions, proxy route, receipt schema, verifier identity, control-bundle allowlist | [`docker/autofv/toolchain-lock.json`](../docker/autofv/toolchain-lock.json) | Trust contract. Update its hashes and contract tests with every change. |
| `native_decide` rule | `native_decide_policy` in the toolchain lock and `evaluate_native_decide_policy(...)` in [`experiment.py`](experiment.py) | Phase 1 uses `allow_audited`. The inventory evaluator exists, but the tracer currently validates only the policy selection and hash. Count caps or named-spec allowlists belong behind this one policy function. |
| Probe byte, node, and edge limits; dependency scheduling | [`probes.py`](probes.py) | Current limits are 16 MiB, 10,000 nodes, and 100,000 edges. |
| Agent VM name, UID, CPU, memory, PID, temporary filesystem, and Docker arguments | [`worker.py`](worker.py) | Current container limits are 2 CPUs, 2 GiB, 256 PIDs, and two 64 MiB temporary filesystems. |
| Candidate scope and acceptance checks | `accept_candidate(...)` in [`worker.py`](worker.py) | It currently checks one-file scope, base and patch hashes, forbidden additions, and `lake build`. |
| Canonical statement and trust-base implementations | [`../harness/gates/StmtCanon.lean`](../harness/gates/StmtCanon.lean) and [`../harness/gates/g2_trust_base.py`](../harness/gates/g2_trust_base.py) | These gates exist in the earlier runner and are locked into the control bundle. The new tracer does not call them yet. |
| Clean verifier command and report binding | [`verifier.py`](verifier.py) | A matching report must name a worker distinct from the agent VM. |

`worker.accept_candidate(...)` currently returns the labels `statement`,
`native_decide`, `trust`, and `kernel` after its smaller check set. Treat those
labels as planned gate coverage until the dedicated gate implementations are
wired into this path.

## Tests worth reading

| Test | What it checks |
| --- | --- |
| [`tests/test_cli_snapshot.py`](../tests/test_cli_snapshot.py) | Input schemas, toolchain lock, control bundle, policy, and prepared target. One test currently reaches Lima unexpectedly. |
| [`tests/test_model_proxy_fixture.py`](../tests/test_model_proxy_fixture.py) | Deterministic proxy route, signed fixture receipts, tamper rejection, and a separate `runsc` route smoke test |
| [`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) | Controller flow with the external boundaries replaced by test doubles |
| [`tests/test_image_contract.py`](../tests/test_image_contract.py) | Pinned image contents and runtime contract |
| [`harness/gates/tests/test_g1.py`](../harness/gates/tests/test_g1.py) | Canonical Lean statement fingerprinting |

The older runner under `harness/` remains useful reference code. Its behavior
is documented in [`docs/HARNESS-DETAIL.md`](../docs/HARNESS-DETAIL.md). It is
not the sealed AutoFV execution path.

## Rules for updating this guide

- Update `README.md` and `README.html` in the same commit.
- State whether a check used test doubles, a local fixture service, a real VM,
  or a provider call.
- Call fixture usage and cost synthetic.
- Never add a proxy signing key, provider credential, hidden reference, or
  complete future-response program to the target or worker volume.
- Do not call a run successful until the accepted tree passes on the separate
  clean verifier and every bound identity matches.

Phase 1 should next produce one saved run directory containing raw probe bytes,
proxy receipts based on provider usage, the accepted source tree, a distinct
verifier report, `result.json`, and `evidence/l0.json`.
