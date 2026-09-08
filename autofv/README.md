# AutoFV

AutoFV is the trusted host-side controller for experiments that ask an agent
to recover Lean specifications and proofs inside a sealed Linux worker.

This page describes the code as it exists on 8 September 2026. Phase 1 is
still in progress. Keep this file and [README.html](README.html) in sync.

## Status

An earlier sealed diamond fixture completed under `runsc` and passed on the
separate verifier VM. The launcher now uses a disposable VM for each attempt;
its isolation and proxy paths have passed their Linux system matrices. The
remaining Phase 1 plan will rerun the whole diamond through this new lifecycle.
No provider call has run.

| Area | Current evidence |
| --- | --- |
| Disposable worker boundary | Nine Linux system tests clone a stopped template, inspect the actual Docker/`runsc` boundary, deny general egress, export state, delete the run VM, and restore onto a fresh clone |
| Fixed proxy and accounting boundary | Four Linux system tests reject seven caller-controlled capabilities, accept eight signed fixture receipts, exercise a real timeout, and scan retained surfaces |
| Pinned probe output | Captured from the toolchain image and checked byte-for-byte |
| Earlier end-to-end diamond | Overlapped both leaf requests, accepted all three source files serially, and received a distinct verifier `PASS`; this predates the disposable-VM change |
| End-to-end diamond on the current launcher | Not run yet |
| Provider model call and billed usage | Not run |

The current `$0.022350` result is fixture data: eight handwritten receipts for
2,235 invented tokens at `$0.000010` per token. The fixture uses
`fixture-model-v1`; no API key, provider response, or billing record takes part
in that test. The values live in
[`tests/fixtures/model-proxy/diamond-responses.json`](../tests/fixtures/model-proxy/diamond-responses.json)
and are repeated as expectations in the proxy fixture test.

`cost_usd` is never guessed from terminal activity. It changes only after the
controller validates a signed proxy receipt containing usage and cost for the
current run, request, response, model, route, and sequence. A real deployment
needs an external proxy that obtains provider billing data, signs that receipt,
and binds it to the institutional account. This repository does not yet ship
that proxy.

The `cryptography` Python package verifies the receipt's Ed25519 signature.
The repository contains only the public verification key. The signing key
stays in the trusted proxy. This signature protects the accounting record; it
is unrelated to the curve25519-dalek code being verified by the experiment.

The earlier successful run recorded `execution_tier: sealed_runsc` and
`cost_classification: synthetic_fixture`. It created separate worktrees, caches,
and result paths for the two leaves, overlapped their proxy calls, then accepted
the left, stale right, and stale top patches one at a time. Stale patches were
applied and rebuilt against the latest accepted tree. It processed eight
receipts and ended with `clean_verifier:PASS`.
The controller writes canonical, hash-checked checkpoints around model, probe,
build, apply, verifier, and result-export transitions. At the end of an attempt,
it exports the accepted Git tree, repository bundle, working patch, untracked
files, result, evidence, and checkpoints to the host run directory. It checks
their hashes and scans retained state before deleting the disposable VM. Resume
validates that export and recreates the project in a new disposable VM and
volume.

`max_wall_seconds` uses monotonic controller time and keeps up to five seconds,
or ten percent of a smaller budget, for final result persistence.
`max_cost_usd` changes only when a unique signed proxy receipt matches the
current run, request, response, model, route, currency, and sequence. A limit
produces `budget_exhausted` with partial counts and retained state. Rejected
receipts leave cost unchanged and appear as hash-only evidence.
Probe and allocated-worker launch failures write a non-success result and L0
receipt before exit, without making a model request. Invalid target or run
configuration still stops before worker allocation and returns a non-zero CLI
status. The remaining Phase 1 plan adds durable records for those
pre-allocation attempts and completes the evidence contract.

## Intended run

```text
trusted host
  autofv run
    ├── clone the stopped autofv-agent-template VM into autofv-agent-run
    ├── copy the approved target and control files into one fresh Docker volume
    ├── run the pinned image with gVisor runsc
    ├── retain and validate probe-rust and probe-aeneas output
    ├── create private one-file worktrees for each proof-ready leaf
    ├── overlap both fixed-shape leaf requests through one trusted proxy route
    ├── checkpoint returned patches serially against the latest accepted tree
    ├── export the accepted tree to the separate autofv-verifier Lima VM
    └── export and scan state, write receipts, then delete autofv-agent-run
```

Lima creates Linux virtual machines on macOS. AutoFV uses it so the local
experiment has the same Linux Docker/`runsc` boundary expected on a cloud
worker. `autofv-agent-template` is a stopped, prebuilt seed. Each attempt gets
a fresh `autofv-agent-run` clone, and the launcher deletes that clone after it
has verified the export. `autofv-verifier` is a separate VM; it never receives
the agent volume or caches.

The worker receives no developer checkout, container-runtime socket, provider
credential, complete proxy response fixture, or hidden verifier reference. The
trusted host copies an allowlisted control bundle into the managed volume.
Only the accepted source tree crosses into the verifier.

The local tracer test in
[`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) exercises
the controller order and failure rules with test doubles. It records the
orchestration contract and reports `execution_tier: simulation`. The sealed
fixture run exercised both VMs and the local trusted proxy. Neither path called
a model provider.

The current deterministic proxy returns patch text; no shell-capable model
process edits a lane worktree yet. Each lane writes a hash-only preflight receipt
covering scope, patch identity, statement fingerprints, and the selected policy
hash. That is not a local kernel proof. The controller applies each patch to the
canonical tree and runs the configured Lean build before committing it; the
separate clean verifier rebuild remains the only success authority.

## Local setup

AutoFV requires Python 3.12. Use the repository virtual environment and `uv`;
do not install packages into the system Python.

```bash
uv venv --python 3.12 .venv
UV_CACHE_DIR=/private/tmp/autofv-uv-cache uv sync
```

Sealed runs currently require:

- Lima and two prepared VMs: the stopped `autofv-agent-template` and the
  separate `autofv-verifier`;
- Docker Engine 29.7.2 and gVisor `runsc` release `20260817.0` in the template;
- the exact image digest recorded in
  [`docker/autofv/toolchain-lock.json`](../docker/autofv/toolchain-lock.json)
  already loaded in both VMs;
- a trusted fixed proxy reachable at one literal IPv4 address.

The repository does not yet automate VM/template provisioning. The launcher
fails closed if the template is running, mounted to the host, forwards an SSH
agent, contains extra Docker resources or images, or differs from the locked
kernel/runtime/image inventory.

Run the fast local contracts:

```bash
.venv/bin/python -m unittest -v \
  tests.test_cli_snapshot \
  tests.test_probe_graph \
  tests.test_contract_and_acceptance \
  tests.test_parallel_lanes \
  tests.test_restart_budget \
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

- the stopped `autofv-agent-template` and separate `autofv-verifier` Lima
  instances;
- the pinned image and `runsc-hardened` runtime in the template;
- `AUTOFV_PROXY_BASE` in the trusted host process;
- a run-scoped `AUTOFV_RUN_TOKEN` in the trusted host process;
- a proxy that implements the locked `POST /v1/autofv/infer` contract and
  signs usage receipts with the pinned key.

`AUTOFV_PROXY_BASE` must be an `http` or `https` base URL with one literal IPv4
address and no path, query, fragment, or embedded credentials. The run token is
an opaque client token issued for one experiment. Provider API keys stay in the
external proxy, and VM access uses separate credentials. The launcher puts the
raw token only in its trusted relay, records its SHA-256 identity in checkpoints
and receipts, and rejects a token change during the run. The external proxy
uses the token to select the fixed run/account context and adds the provider
credential itself.

The agent container has one internal Docker network and can reach only the
relay's fixed address and port. The relay accepts only the locked POST path,
strips caller authorization and upstream selection, and can reach only the
configured proxy address. Host and forwarding firewall rules reject DNS,
literal public IPv4, IPv6, link-local/metadata, and other routes.

Verification creates a fresh Docker volume in `autofv-verifier`, runs the
pinned image with `--network none`, and removes the volume when the build ends.
Both launchers use `--pull never`; the verifier does not reuse the agent volume
or caches. Its distinct worker identity is what `clean verifier` means in
results and receipts.

The provider credential belongs in the proxy service. Do not put it in this
repository, either VM, the container, or either environment variable above.
The current repository does not include a real proxy deployment or provider
billing trace, so this command is still an integration target. The signing key
pinned today belongs to the local fixture. A real proxy needs a separate
signing key and a corresponding lock update.

The CLI prints the result JSON. The controller also writes `result.json`,
`evidence/l0.json`, proxy policy/error evidence, checkpoints, an `export/`
tree, and `disposal.json` in a host temporary run directory. Find the newest
fixture directory and inspect it with:

```bash
run_dir=$(ls -td "${TMPDIR%/}"/fixture-diamond-run-0001-* | head -1)
.venv/bin/python -m json.tool "$run_dir/result.json"
.venv/bin/python -m json.tool "$run_dir/evidence/l0.json"
.venv/bin/python -m json.tool "$run_dir/export/manifest.json"
.venv/bin/python -m json.tool "$run_dir/disposal.json"
```

A stable output directory has not been added to the CLI yet. The current L0
receipt binds the result and accepted proxy receipt hashes. The remaining Phase
1 plan expands the evidence index and verifier report.

Restart is currently a Python controller seam, not a CLI flag:

```python
from autofv.experiment import run_experiment

result = run_experiment(target, run_config, resume_from=run_dir)
```

`resume_from` must name the existing host run directory. Its checkpoint binds
the target snapshot, manifest, toolchain, image, control bundle,
`native_decide` policy, run configuration, proxy route, client-token hash, and
run identity. If the previous VM was disposed, resume verifies the export and
recreates the accepted and working state in a fresh clone and volume.

## What the result fields mean today

| Field | Meaning in the current diamond tracer |
| --- | --- |
| `outcome` | `success` after a matching verifier `PASS`, `budget_exhausted` for a wall/cost stop, or `failure` for another reduced error |
| `execution_tier` | `sealed_runsc` for the real worker path; `simulation` when tests replace external boundaries |
| `cost_classification` | `synthetic_fixture` for the current locked proxy fixture |
| `targets_verified_final` | Fixture-specific value: `1` on success |
| `internal_specs_accepted` | Fixture-specific value: `2` on success |
| `internal_proofs_accepted` | Fixture-specific value: `2` on success |
| `proxy_requests` | Number of accepted signed receipts |
| `cost_usd` | Sum of `cost.amount` from accepted receipts; synthetic for fixture receipts |
| `wall_seconds` and `finalization_reserve_seconds` | Monotonic controller time charged to the run and the portion held back for writing its final records |
| `receipt_rejections` | Request identity, sequence, rejection reason, and hash of a rejected receipt payload; never the raw rejected receipt |
| proxy identity hashes | Bind the locked route, firewall policy, run-scoped client token, and disposable worker inventory without recording the raw token |
| `lanes` and `lane_intervals` | Private path assignments and monotonic timing evidence for the proof lanes |
| `candidate_receipts` | Scope/fingerprint/policy preflight identity and the serial checkpoint outcome; it is not a clean-verifier report |
| `accepted_sequence` | The only ordered transitions that advanced the canonical commit; stale candidates are marked `accepted_reverified` |
| hash fields | Identities of the snapshot, probes, policy, image, control bundle, accepted tree, and verifier report |
| `events` | Ordered controller transitions, not a provider or VM execution trace by itself |

The accepted-count fields are derived from frozen contracts, accepted internal
nodes, and the final verifier result. The surrounding tracer still supports
only the Phase 1 diamond.

## Where to change things

| Change | File | Notes |
| --- | --- | --- |
| Model name, wall-clock limit, cost ceiling | [`tests/fixtures/diamond/run.json`](../tests/fixtures/diamond/run.json) | Per-run input. `max_cost_usd` stops on authenticated receipt totals; `max_wall_seconds` stops new model and gate work while reserving finalization time. |
| Target function, supplied specification, verifier command | [`tests/fixtures/diamond/autofv.json`](../tests/fixtures/diamond/autofv.json) | Per-target input. The verifier command is an argv array, not shell text. |
| Image digest, tool versions, fixed proxy route, receipt schema, verifier identity, control-bundle allowlist | [`docker/autofv/toolchain-lock.json`](../docker/autofv/toolchain-lock.json) | Trust contract. Update its hashes and contract tests with every change. |
| Proxy address and run token | `AUTOFV_PROXY_BASE` and `AUTOFV_RUN_TOKEN` in the trusted host environment | The address selects one literal-IP proxy endpoint. The token must be unique to the experiment and accepted by that proxy; neither value belongs in target files. |
| `native_decide` rule | `native_decide_policy` in the toolchain lock and `evaluate_native_decide_policy(...)` in [`experiment.py`](experiment.py) | For the current vertical slice we allow `native_decide` under `allow_audited`. Future count caps or named-spec allowlists belong in this policy criterion and seam, not in separate gate defaults. |
| Probe byte, node, and edge limits; dependency scheduling | [`probes.py`](probes.py) | Current limits are 16 MiB, 10,000 nodes, and 100,000 edges. |
| Proof readiness, lane overlap, candidate replay, serial checkpointing | [`experiment.py`](experiment.py) | Uses the probe term graph and Python's standard thread pool. There is no separate scheduler module. |
| Agent template/run VM names, UID, CPU, memory, PID, firewall, relay, export, and disposal | [`worker.py`](worker.py) | Current agent containers use 2 CPUs, 2 GiB, 256 PIDs, and two 64 MiB temporary filesystems. Real runs report `sealed_runsc`. |
| Candidate scope and acceptance checks | `accept_candidate(...)` in [`worker.py`](worker.py) | It checks one-file scope, base and patch hashes, patch application, forbidden source markers, and the configured build. A failed post-apply check reverses and restages the patch before returning. |
| Canonical statement and trust-base implementations | [`../harness/gates/StmtCanon.lean`](../harness/gates/StmtCanon.lean) and [`../harness/gates/g2_trust_base.py`](../harness/gates/g2_trust_base.py) | These gates exist in the earlier runner and are locked into the control bundle. The new tracer does not call them yet. |
| Clean verifier command and report binding | [`verifier.py`](verifier.py) | A matching report must name a worker distinct from the agent VM. The accepted archive hash is checked before extraction into a fresh no-network volume. |

Canonical statement, complete `native_decide`, and trust-base recomputation on
the clean verifier are still planned work. The current candidate receipt names
only the checks it runs.

## Tests worth reading

| Test | What it checks |
| --- | --- |
| [`tests/test_cli_snapshot.py`](../tests/test_cli_snapshot.py) | Input schemas, toolchain lock, control bundle, policy, and prepared target. Worker preparation is replaced in the native-policy unit test. |
| [`tests/test_model_proxy_fixture.py`](../tests/test_model_proxy_fixture.py) | Deterministic proxy route, signed fixture receipts, tamper rejection, and a separate `runsc` route smoke test |
| [`tests/test_linux_isolation.py`](../tests/test_linux_isolation.py) | Actual disposable Lima lifecycle, `runsc` inspection, four-class egress denial, fixed-proxy capability denial, signed accounting, retained-state scans, export, disposal, and fresh-clone resume |
| [`tests/test_parallel_lanes.py`](../tests/test_parallel_lanes.py) | Barrier-backed leaf overlap, private paths, scope and policy rejection, stale re-verification, replay idempotency, and top-proof readiness |
| [`tests/test_restart_budget.py`](../tests/test_restart_budget.py) | Atomic checkpoint selection, working/accepted recovery, graph-state replay, wall/cost exhaustion, exact fixture totals, and rejected-receipt evidence |
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

The remaining Phase 1 plan adds complete gate receipts, durable verifier
artifacts, every-exit results, and the final full run. A stable user-selected
run directory is still outside the CLI.
