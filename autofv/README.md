# AutoFV

AutoFV is the trusted host-side controller for experiments that ask an agent
to recover Lean specifications and proofs inside a sealed Linux worker.

This page describes the code as it exists on 4 September 2026. Phase 1 is
still in progress. Keep this file and [README.html](README.html) in sync.

## Status

One sealed diamond fixture completed across the dedicated agent and verifier
VMs. The agent work ran in the pinned image under `runsc`; the verifier rebuilt
the exact accepted tree in the same image from a fresh no-network volume.
Model responses and cost were synthetic fixture data. No provider call ran.

| Area | Current evidence |
| --- | --- |
| Input, policy, image, and receipt contracts | Focused local checks and all 29 CLI snapshot tests pass |
| Pinned probe output | Captured from the toolchain image and checked byte-for-byte |
| Fixed proxy route under `runsc` | Tested against the local deterministic proxy fixture |
| End-to-end controller flow | One real two-VM run accepted all three source files and received a distinct verifier `PASS` |
| Provider model call and billed usage | Not run |
| Full agent worker to clean-verifier fixture | Passed on 4 September 2026; agent used `runsc`, verifier used a fresh Docker volume and the pinned image |
| Malformed probe and graph mutation matrix | Eight local tests cover malformed bytes, wrong tool identity, incomplete or failed closure data, unsafe paths, deterministic ordering, and cycles |

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

The successful run recorded `execution_tier: sealed_runsc` and
`cost_classification: synthetic_fixture`. It accepted three commits, processed
eight receipts, and ended with `clean_verifier:PASS`. Failures retain completed
hashes, accepted-receipt counts and cost, and the last accepted commit.
Probe and allocated-worker launch failures write a non-success result and L0
receipt before exit, without making a model request. Invalid target or run
configuration still stops before worker allocation and returns a non-zero CLI
status; durable records for those pre-allocation attempts are later Phase 1
work.

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

The local tracer test in
[`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) exercises
the controller order and failure rules with test doubles. It records the
orchestration contract and reports `execution_tier: simulation`. The sealed
fixture run exercised both VMs and the local trusted proxy. Neither path called
a model provider.

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
  tests.test_cli_snapshot \
  tests.test_probe_graph \
  tests.test_phase1_diamond.TracerTests
```

The native-policy launch test replaces worker preparation, graph execution,
and result persistence. It checks policy binding without contacting Lima; it
is not VM or full-run evidence.

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

The agent VM must already contain the pinned image and `runsc-hardened`. The
verifier VM must contain Docker and the same pinned image. Verification creates
a fresh Docker volume, runs with `--network none`, and removes that volume when
the build ends. Both launchers use `--pull never`; the verifier does not reuse
the agent volume or caches.

The provider credential belongs in the proxy service. Do not put it in this
repository, either VM, the container, or either environment variable above.
The current repository does not include a production proxy deployment or a
provider signing trace, so this command is still an integration target.
The key pinned today belongs to the local fixture. A production proxy needs a
separate signing key and a corresponding lock update.

The CLI prints the result JSON. The current worker also writes `result.json`,
`evidence/l0.json`, and raw probe files in a host temporary run directory.
Find the newest fixture directory and inspect it with:

```bash
run_dir=$(ls -td "${TMPDIR%/}"/fixture-diamond-run-0001-* | head -1)
.venv/bin/python -m json.tool "$run_dir/result.json"
.venv/bin/python -m json.tool "$run_dir/evidence/l0.json"
```

A stable output directory has not been added to the CLI yet. The L0 receipt
binds the result and eight proxy receipt hashes; separate receipt and verifier
report files arrive in the later evidence phase.

## What the result fields mean today

| Field | Meaning in the current diamond tracer |
| --- | --- |
| `outcome` | The controller reached a matching verifier `PASS` |
| `execution_tier` | `sealed_runsc` for the real worker path; `simulation` when tests replace external boundaries |
| `cost_classification` | `synthetic_fixture` for the current locked proxy fixture |
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
| Agent VM name, UID, CPU, memory, PID, temporary filesystem, and Docker arguments | [`worker.py`](worker.py) | Current container limits are 2 CPUs, 2 GiB, 256 PIDs, and two 64 MiB temporary filesystems. Real runs report `sealed_runsc`. |
| Candidate scope and acceptance checks | `accept_candidate(...)` in [`worker.py`](worker.py) | It currently checks one-file scope, base and patch hashes, patch application, forbidden source markers, and the configured build. |
| Canonical statement and trust-base implementations | [`../harness/gates/StmtCanon.lean`](../harness/gates/StmtCanon.lean) and [`../harness/gates/g2_trust_base.py`](../harness/gates/g2_trust_base.py) | These gates exist in the earlier runner and are locked into the control bundle. The new tracer does not call them yet. |
| Clean verifier command and report binding | [`verifier.py`](verifier.py) | A matching report must name a worker distinct from the agent VM. The accepted archive hash is checked before extraction into a fresh no-network volume. |

Canonical statement, complete `native_decide`, and trust-base gates are still
planned work. The current candidate receipt names only the checks it runs.

## Tests worth reading

| Test | What it checks |
| --- | --- |
| [`tests/test_cli_snapshot.py`](../tests/test_cli_snapshot.py) | Input schemas, toolchain lock, control bundle, policy, and prepared target. Worker preparation is replaced in the native-policy unit test. |
| [`tests/test_model_proxy_fixture.py`](../tests/test_model_proxy_fixture.py) | Deterministic proxy route, signed fixture receipts, tamper rejection, and a separate `runsc` route smoke test |
| [`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) | Controller flow with test doubles, failure-state retention, worker command construction, and clean-verifier isolation arguments |
| [`tests/test_probe_graph.py`](../tests/test_probe_graph.py) | Probe schema and closure mutations, deterministic graph direction and scheduling, raw-byte retention, and pre-model failure results |
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

Later Phase 1 plans add complete gate receipts, durable proxy and verifier
artifacts, and a stable run directory.
