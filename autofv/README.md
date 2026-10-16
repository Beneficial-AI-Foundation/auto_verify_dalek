# AutoFV implementation reference

AutoFV is intended to run bounded agent experiments on user-provided Lean
repositories with prepared top-level specifications. See the [root README](../README.md)
and [usage guide](USAGE.md) for that product goal and an explicit account of what
is not implemented yet. Dalek is the current test case, not the intended input
restriction.

This page documents the existing controller, operator setup and retained evidence.
The [development recipe](DEVELOPMENT-RUN.md) preserves the current prepared
benchmark launch procedure; it is not the normal user interface we intend to ship.

## Current integration limits

| Boundary | Implementation evidence |
| --- | --- |
| Target discovery | `run_probes` in [probes.py](probes.py) invokes Rust/Aeneas extraction. `parse_probe_bytes` freezes targets already listed in `autofv.json`; there is no direct `probe-lean count` integration or auto-generated run manifest. |
| First-use bootstrap | `_create_worker` in [worker_runtime.py](worker_runtime.py) fails if the stopped template is missing. It clones/starts the disposable worker, not a Linux template from scratch. |
| Verifier startup | `_check_quiet_verifier_vm` in [verifier.py](verifier.py) requires an existing running verifier with 2 CPUs/8 GiB. Verification creates an isolated volume, not a new verifier VM. |
| Multiple roots | `run_generic_role_path` in [generic_role_runtime.py](generic_role_runtime.py) rejects any target count other than one. A parsed full-mode flag does not remove this check. |
| Project-specific preparation | [prepare_dalek.py](prepare_dalek.py) hardcodes Dalek paths and its small root. [fvs_packet.py](fvs_packet.py) binds Rust input to the `curve25519-dalek/src` subtree. These are obstacles to the general FVS repo path. |
| Private references | Prepared runs in [experiment.py](experiment.py) require an external verifier reference. The ordinary supplied-spec workflow still needs to be separated from this benchmark requirement. |
| Internet-enabled agents | The CLI/config have no such switch. [worker_proxy.py](worker_proxy.py) and [worker_runtime.py](worker_runtime.py) enforce fixed egress; role tools also lack general web access. The verifier stays on a no-network runtime. |

These limits must be addressed in implementation, not hidden behind more setup
instructions for the end user.

## Autonomous prepared FVS workflow

The `autofv-fvs-sol-sonnet/v3` profile identifies the changed workflow:

**Specification author → fresh semantic PASS → freeze → autonomous prover → independent verifier.**

FVS roles use the original wall/cost allowance, tool deadlines and downstream
reserves instead of tactic-line, turn or review-round quotas. A failed local
proof check returns to the same receipted conversation; replay reconstructs the
same feedback without reissuing completed requests. Fresh review is required for
changed specifications. Model proof-review and pure PASS-acknowledgement calls
are no longer part of the prepared FVS path.

Local compilation is not acceptance. Frozen statement/source scope, holes and
axioms, pinned clean verification, accounting and isolation still gate accepted
state. Helper acceptance does not establish root verification or L4 recovery.
The verifier backend is unchanged. Cached Lean checks remain the feedback tool;
Lean LSP integration, with call timeouts and restart handling, is still pending.
The legacy non-FVS workflow is unchanged.

## Status

Live provider-backed helper attempts through `f639f45` reached specification
PASS and locally compiling proof candidates, but were rejected by controller
submission requirements before independent helper verification. No provider-backed
helper spec/proof pair, root verification or successful smoke audit has been
established. The autonomous v3 workflow is offline-tested, not live-qualified;
older approvals and profile bindings do not authorize it. Development records
are retained by the operator, not checked into this repository; receipt
observations are not invoices.

The historical fixture launcher completed one full sealed diamond under `runsc` and passed
on the separate verifier VM. The two leaf requests overlapped, all three source
changes were accepted serially, and the final result reached complete L4. That
fixture run made no provider call; this repository has no retained real-provider
run with a clean-verifier success claim.

| Area | Current evidence |
| --- | --- |
| Disposable worker boundary | Nine Linux system tests clone a stopped template, inspect the actual Docker/`runsc` boundary, deny general egress, export state, delete the run VM, and restore onto a fresh clone |
| Fixed proxy and accounting boundary | Four Linux system tests reject seven caller-controlled capabilities, accept eight signed fixture receipts, exercise a real timeout, and scan retained surfaces |
| Local upstream boundary | macOS Seatbelt limits the Lima host agent to the exact VM sockets, its loopback SSH port, and the fixed proxy port; the egress matrix proves this layer separately from the worker and container rules |
| Pinned probe output | Captured from the toolchain image and checked byte-for-byte |
| Result and evidence contract | Fourteen local tests cover complete L4, receipt/file mismatch, missing or symlinked evidence, typed pre-worker failures, finalization failure, and append-only attempt records |
| Retained end-to-end diamond fixture | `success`, `sealed_runsc`, complete L4, one sorry removed, eight signed fixture receipts, `$0.022350` synthetic cost, and a distinct clean-verifier `PASS` |
| Prepared Dalek and role paths | Local tests cover deterministic preparation, restartable role lanes, one accepted helper's scoped clean verification, and the distinct terminal verifier; test-double outcomes are not sealed-provider results |
| Provider model calls and accounting | Live helper attempts retain provider receipts and failure records; the latest observation is above. A provider-backed accepted pair or clean-verifier success has not been established. |

The retained `$0.022350` result is fixture data: eight handwritten receipts for
2,235 invented tokens at `$0.000010` per token. The fixture uses
`fixture-model-v1`; no API key, provider response, or billing record takes part
in that test. The values live in
[`tests/fixtures/model-proxy/diamond-responses.json`](../tests/fixtures/model-proxy/diamond-responses.json)
and are repeated as expectations in the proxy fixture test.

Completed usage is accepted only after the controller validates a signed proxy
receipt for the current run, request, response, model, route and sequence.
Outstanding reservations and unresolved dispatched requests are tracked
separately; terminal activity cannot establish a provider charge. The trusted
host includes a fixed-route provider service
([`provider_service.py`](provider_service.py)) that dispatches through
[`provider_transport.py`](provider_transport.py) and signs accounting receipts.
The fixture receipt path and provider-authenticated path have different cost
classifications. Provider selection, credentials, billing, and spending
authorization remain deployment inputs; the existing fixture run proves none
of those external facts.

The `cryptography` Python package verifies the receipt's Ed25519 signature.
The repository contains only the public verification key. The signing key
stays in the trusted proxy. This signature protects the accounting record; it
is unrelated to the curve25519-dalek code being verified by the experiment.

The successful fixture run recorded `execution_tier: sealed_runsc` and
`cost_classification: synthetic_fixture`. It created separate worktrees, caches,
and result paths for the two leaves, overlapped their proxy calls, then accepted
the left, stale right, and stale top patches one at a time. Stale patches were
applied and rebuilt against the latest accepted tree. It processed eight
receipts and ended with `clean_verifier:PASS`, zero remaining sorries, and no
missing evidence. Earlier attempts remain in host temporary directories. They
failed closed while exposing an evidence-write race, an incomplete verifier
runtime, offline probe assumptions, and missing clean-verifier inputs; none was
scored as successful.
The controller writes canonical, hash-checked checkpoints around model, probe,
build, apply, verifier, and result-export transitions. At the end of an attempt,
it exports the accepted Git tree, repository bundle, working patch, untracked
files, verifier evidence, and checkpoints to the host run directory. It checks
their hashes and scans retained state before deleting the disposable VM. It then
writes the disposal receipt, result, and L0 index; scans those two final files;
and links that scan from the append-only attempt record. An unfinished resume
validates the export before recreating the project in a new disposable VM and
volume.

`max_wall_seconds` bounds shared controller work and reserves time for
finalization. Fresh-helper runs also carry an original preparation epoch via
`--budget-started-epoch-ns`; earlier operational work counts against the same
limit. Model dispatch reserves a conservative cost ceiling before sending a
request, then reconciles authenticated usage. Unresolved dispatched requests
remain liabilities rather than becoming free because the connection failed.
Read the accounting fields alongside `cost_usd`; budget usage and invoice totals
are not interchangeable. A budget limit stops new work and retains partial
counts and the failure outcome.
The controller retains typed non-success records for probe, worker-preparation
and input failures where result persistence is possible. Invalid target/run
contracts can produce unscored attempts before worker allocation; command-line
syntax and filesystem failures can precede those records. Non-success outcomes
return a nonzero CLI status.

## Phase 1 fixture run

```text
trusted host
  autofv run
    ├── clone the stopped autofv-agent-template VM into autofv-agent-run
    ├── start its Lima host agent under the local macOS Seatbelt policy
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
The verifier receives only the accepted repository bundle and its own trusted
reference, never the agent volume or caches.

The local tracer test in
[`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) exercises
the controller order and failure rules with test doubles. It records the
orchestration contract and reports `execution_tier: simulation`. The full
diamond test in the same file exercised the disposable VM, pinned `runsc`
container, local trusted proxy, and separate verifier VM. Neither path called a
model provider.

The Phase 1 deterministic proxy returns patch text; the newer
[`agent_lane.py`](agent_lane.py) and [`generic_role_runtime.py`](generic_role_runtime.py)
paths execute bounded tool-using roles in private lanes. Each lane writes a
hash-only candidate preflight receipt
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
  separate, already running `autofv-verifier`;
- Docker Engine 29.7.2 and gVisor `runsc` release `20260817.0` in both VMs;
- the exact image digest recorded in
  [`docker/autofv/toolchain-lock.json`](../docker/autofv/toolchain-lock.json)
  already loaded in both VMs;
- a trusted fixed proxy reachable at one literal IPv4 address.

The repository does not yet automate VM/template provisioning. The launcher
fails closed if the template is running, mounted to the host, forwards an SSH
agent, contains extra Docker resources or images, or differs from the locked
kernel/runtime/image inventory. The clean verifier also checks its exact Docker
version and `runsc` path, version, and arguments before reading the bundle.

Run this focused host-only subset (not the entire regression suite):

```bash
.venv/bin/python -B - <<'PY'
import unittest
from tests import host_regression
host_regression.install_guard()
names = [
    'tests.test_cli_snapshot', 'tests.test_agent_lane', 'tests.test_fvs_offline',
]
result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromNames(names))
raise SystemExit(not result.wasSuccessful() or bool(host_regression.blocked))
PY
```

The native-policy launch test replaces worker preparation, graph execution,
and result persistence. It checks policy binding without contacting Lima; it
is not VM or full-run evidence.

A broader 220-test host-guarded check during the 2026-10-15 documentation audit
reported three failures and one error: a placeholder `/config` in
`tests.test_preflight_cli`, two outdated file-read expectations in
`tests.test_fvs_operational_path`, and an unmocked Lima call in
`tests.test_probe_graph`. The guard blocked the external command. These checks
still need follow-up; the focused command above is not a full-suite green claim.
Do not remove the guard or run test discovery to work around them.

Run the real boundary and full vertical-slice checks only when the prepared VMs
are available:

```bash
.venv/bin/python -m unittest tests.test_linux_isolation
.venv/bin/python -m unittest \
  tests.test_phase1_diamond.Phase1DiamondTests.test_one_full_sealed_concurrent_diamond
```

Show the CLI without starting a worker:

```bash
.venv/bin/python -m autofv.experiment --help
.venv/bin/python -m autofv.prepare_dalek --help
```

### Prepared and provider paths

[`prepare_dalek.py`](prepare_dalek.py) accepts a pinned solved source, target
report, probe identities, and `--mode full|small`; it emits a reproducibly built
redacted target and a separate preparation manifest. These inputs must be
supplied explicitly, outside the prepared target. `autofv inspect REPO
--output REPORT` writes a target report but not probe identities or a hidden
verifier reference.

`autofv preflight` **starts a worker VM**; it is not an offline dry run. FVS
preflight additionally needs all preparation/public-Rust flags, and
`--check-model-accessibility` can make paid requests. Its outputs include
`preflight-result.json` and sealed/provider evidence.

The current small-helper route uses `autofv run REPO --config RUN_JSON
--env-file PRIVATE_ENV --fresh-pair-preflight --execution-mode proof-only`,
plus the preparation/cache/public-Rust/reference flags shown in the
[development recipe](DEVELOPMENT-RUN.md#4-launch-one-approved-small-helper-attempt).
It performs pair accessibility and sealed checks on the same worker within the
shared budget, without a separately supplied `--selection-record` or an extra
preliminary experiment. A fresh run token is still required.

Without `--fresh-pair-preflight`, the provider route requires both `--env-file`
and `--selection-record`. That canonical record must match the pinned provider
binding; model selection alone does not authorize requests or spending.
Same-worker helper selections cannot be reused in another invocation.

Prepared runs additionally require `--preparation-manifest`,
`--preparation-evidence` (with `probe-rust.json` and `probe-aeneas.json`),
`--preparation-cache`, `--verifier-reference`, and `--execution-mode full` or
`proof-only`. The `proof-only` mode needs one prepared small target. Full mode
also remains subject to the generic scheduler's single-root restriction; it is
not an implemented arbitrary multi-root campaign. The generic role path uses private lanes for scouting, dependency planning, specification
review/repair, and proofs; a helper's accepted patch must receive a separate
`SCOPED_PASS` bound to its dependency closure before a dependent is released.
The current scoped audit still imports/builds the project's full module set;
an unrelated unfinished module can block a helper. Only the terminal clean
verifier can pass the root. Local scoped-verifier tests use doubles and
fixtures; the live attempts described above have not accepted a helper pair.

## Fixture experiment command

This is the synthetic diamond fixture, not the Dalek provider recipe:

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
configured proxy address. Rules on the disposable Linux worker reject DNS,
literal public IPv4, IPv6, link-local/metadata, and other routes. On macOS,
Seatbelt provides a separate default-deny layer around the Lima host agent. Its
receipt is stored in `evidence/upstream-policy.json`. The egress test temporarily
removes the worker's output jump to prove the outer layer, restores it, then
tests the worker and container layers. A cloud deployment still needs the
equivalent host firewall and VPC policy; the macOS profile is local only.
The allowed-route probe deliberately sends an invalid body and expects HTTP
400, so it proves reachability without creating a signed model receipt or
synthetic charge.

Verification creates a fresh Docker volume in `autofv-verifier`, runs the
pinned image with `--network none`, and removes the volume when the build ends.
Both launchers use `--pull never` and force Cargo offline. The verifier does not
reuse the agent volume or caches. It regenerates the `probe-aeneas` bridge from
fresh Rust output, imports the project's Lean modules for full and scoped
audits, and checks its own pinned runtime identity. Its distinct worker
identity is what `clean verifier` means in results and receipts.

The provider credential belongs in the proxy service. Do not put it in this
repository, either VM, the container, or either environment variable above.
The fixture command uses the locked synthetic proxy, not the new local
provider service. The provider path requires a private environment file and sealed preflight
authorization. The fresh-helper path constructs its run-bound selection during
that preflight; the other provider path takes an explicit selection record.
Live calls and accounting have been observed, but clean-verifier success has
not. Keep provider keys and the receipt signing key outside the repository and
worker.

The CLI prints result JSON and normally persists `result.json` and
`evidence/l0.json` in a host run directory. Argument or persistence failures can
occur before those artifacts exist; inspect retained files rather than assuming
that exit alone proves finalization. An allocated sealed run
also writes checkpoints, proxy and egress evidence, an `export/` tree,
`disposal.json`, `evidence/final-result-scan.json`, and
`evidence/verifier.json` when verification ran. Read `run_root` in the printed
result, then inspect it with:

```bash
run_dir=/absolute/path/from/printed/run_root
.venv/bin/python -m json.tool "$run_dir/result.json"
.venv/bin/python -m json.tool "$run_dir/evidence/l0.json"
.venv/bin/python -m json.tool "$run_dir/evidence/egress.json"
.venv/bin/python -m json.tool "$run_dir/evidence/verifier.json"
.venv/bin/python -m json.tool "$run_dir/evidence/final-result-scan.json"
.venv/bin/python -m json.tool "$run_dir/export/manifest.json"
.venv/bin/python -m json.tool "$run_dir/disposal.json"
```

Use `--output-root /absolute/path/outside/target` to choose the parent of new
attempt directories; without it they go under the system temporary directory.
Each new attempt appends one record to `AUTOFV_ATTEMPT_LEDGER`; the variable must be
an absolute path. Without it, AutoFV uses `autofv-attempts.jsonl` in the system
temporary directory. Existing result/L0 files and records for the same
`attempt_id` cannot be replaced with different content through the result
writer.

The L0 index names input, image, runtime, tool, probe, mount, network, model
receipt, patch, scan, build, replay, verifier, export, and disposal evidence.
Each item records its run event, SHA-256, byte size, media type, and retained
file location. File bytes must match the trusted receipt or source value, and
runtime receipts must also match their schema, run ID, and self-hash. A missing
or mismatched item leaves `scored` false. A recovered specification claim
appears only when every L0 item exists and the bound verifier report reaches L4.
Network evidence is complete only when the receipt binds the container and
worker firewall checks to a separate upstream default-deny policy; the fixed
proxy policy by itself is not enough.

Restart is a Python controller seam, not a CLI flag. It is not supported for
fresh-pair helper handoffs; a consumed attempt is not retry permission:

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

| Field | Meaning (fixture counts are labelled) |
| --- | --- |
| `outcome` | One of `success`, `budget_exhausted`, `verification_failed`, `infrastructure_failed`, `invalid_target`, `invalid_config`, or `contract_inconclusive`; `termination_reason` carries the narrower cause |
| `attempt_id`, `run_root`, `attempt_ledger` | Immutable attempt identity, artifact directory, and append-only ledger path |
| `execution_tier` | `sealed_runsc` for the real worker path; `simulation` when tests replace external boundaries |
| `cost_classification` | `synthetic_fixture` for the locked fixture; `provider_authenticated` for the configured provider service |
| `sets` | Explicit target `T`, supplied-spec `S`, empty Phase 1 withheld set `W`, and recovered internal-spec identities |
| `targets_verified_final` | Fixture-specific value: `1` on success |
| `internal_specs_accepted` | Fixture-specific value: `2` on success |
| `internal_proofs_accepted` | Fixture-specific value: `2` on success |
| `proxy_requests` | Number of accepted signed receipts |
| `model_attempts`, `model_retries`, `prompt_sha256` | Attempt counts and content identities derived from retained model exchanges and rejected receipts |
| `cost_usd` | Retained run cost/budget usage, synthetic for fixture runs; inspect `accounting` and unresolved liabilities before treating it as observed provider spend. It is not an invoice. |
| `accounting_complete`, `accounting_bounded`, `unresolved_provider_requests`, `unknown_provider_spend` | Distinguish complete receipt accounting, bounded uncertainty and unresolved dispatched requests; cleanup does not settle unknown upstream charges. |
| `helper_verification`, `termination_detail` | Scoped helper evidence and detailed failure cause. A secondary final-audit error does not replace the first role or proof failure. |
| `wall_seconds` and `finalization_reserve_seconds` | Monotonic controller time charged to the run and the portion held back for writing its final records |
| `receipt_rejections` | Request identity, sequence, rejection reason, and hash of a rejected receipt payload; never the raw rejected receipt |
| proxy identity hashes | Bind the locked route, firewall policy, run-scoped client token, and disposable worker inventory without recording the raw token |
| `lanes` and `lane_intervals` | Private path assignments and monotonic timing evidence for the proof lanes |
| `candidate_receipts` | Scope/fingerprint/policy preflight identity and the serial checkpoint outcome; it is not a clean-verifier report |
| `accepted_sequence` | The only ordered transitions that advanced the canonical commit; stale candidates are marked `accepted_reverified` |
| hash fields | Identities of the snapshot, probes, policy, image, control bundle, accepted tree, and verifier report |
| `sorry_counts`, `check_outcomes` | Clean-verifier counts before and after repair, plus its named gate outcomes |
| `evidence_level`, `scored`, `missing_evidence` | Highest reproduced L0-L4 level and any absent L0 items; incomplete L0 is unscored |
| `claim` | A scoped recovered-specification claim only at complete L4; otherwise its status is `withheld` |
| `native_decide_uses`, `compiler_assumptions`, `exclusions` | Exact selected-policy evidence and the stronger security claims this experiment does not make |
| `l0_receipt` | Content link for `evidence/l0.json`, including path, SHA-256, size, and media type |
| `events` | Ordered controller transitions, not a provider or VM execution trace by itself |

The accepted-count fields are derived from frozen contracts, accepted internal
nodes, and the final verifier result. The generic role path also supports
prepared single-root runs; a helper's `SCOPED_PASS` is not a terminal root
verdict or a complete L4 claim.

## Where to change things

| Change | File | Notes |
| --- | --- | --- |
| Run budgets and FVS source packet | [`contracts.py`](contracts.py), [`fvs_packet.py`](fvs_packet.py) | Per-run v2 JSON must be canonical and match the prepared target. Budget/condition changes need approval; pending reservations also constrain dispatch. The diamond run.json is only a v1 fixture. |
| FVS role models, output limits and routes | [`fvs_profile.py`](fvs_profile.py) | Fixed Sol/Sonnet profile, fresh reviewers and no provider fallback. Changing the profile is a reviewed condition change, not an arbitrary model flag. |
| Target function, supplied specification, verifier command | [`tests/fixtures/diamond/autofv.json`](../tests/fixtures/diamond/autofv.json) | Per-target input. The verifier command is an argv array, not shell text. |
| Image digest, tool versions, fixed proxy route, receipt schema, verifier identity, control-bundle allowlist | [`docker/autofv/toolchain-lock.json`](../docker/autofv/toolchain-lock.json) | Trust contract. Update its hashes and contract tests with every change. |
| Proxy address and run token | `AUTOFV_PROXY_BASE` and `AUTOFV_RUN_TOKEN` in the trusted host environment | The address selects one literal-IP proxy endpoint. The token must be unique to the experiment and accepted by that proxy; neither value belongs in target files. |
| Input validation, proxy receipts, and the `native_decide` rule | [`contracts.py`](contracts.py) | For the current vertical slice we allow `native_decide` under `allow_audited`. Future count caps or named-spec allowlists belong in this policy criterion and seam, not in separate gate defaults. |
| Probe byte, node, and edge limits; dependency scheduling | [`probes.py`](probes.py) | Current limits are 16 MiB, 10,000 nodes, and 100,000 edges. |
| Proof readiness, lane overlap, candidate replay, and contract repair | [`diamond.py`](diamond.py), [`graph_scheduler.py`](graph_scheduler.py), [`generic_role_runtime.py`](generic_role_runtime.py) | Diamond fixture and generic role paths share serial candidate acceptance; the prepared path checks helpers separately before releasing dependents. |
| Model requests and authenticated cost accounting | [`model.py`](model.py), [`provider_service.py`](provider_service.py), [`provider_config.py`](provider_config.py) | Fixture receipts remain synthetic; provider configuration/transport signs and reconciles authenticated usage. |
| Wall/cost budgets, checkpoints, and restart recovery | [`run_state.py`](run_state.py) | Owns durable state transitions; [`experiment.py`](experiment.py) remains the CLI and stable composition entry point. |
| Result fields and the attempt ledger | [`results.py`](results.py) | Builds and immutably writes each canonical result/L0 pair and refuses attempt replacement. |
| L0 sources, levels, and claims | [`evidence.py`](evidence.py) | Binds retained evidence bytes to trusted receipts and withholds recovery below complete L4. |
| Worker preparation, probe runs, proof lanes, and candidate acceptance | [`worker.py`](worker.py) | Stable entry point for the controller's worker calls. |
| Lima, Docker, `runsc`, local Seatbelt policy, resource labels, and container limits | [`worker_runtime.py`](worker_runtime.py), [`candidate_lane.py`](candidate_lane.py) | Locked base limits and phase-specific check/warmup overrides; do not infer all role resources from the fixture's base container. Real runs report `sealed_runsc`. |
| Fixed relay, client identity, proxy policy, and egress checks | [`worker_proxy.py`](worker_proxy.py) | Owns the only model-network path visible to the agent worker and records separate upstream, worker, and container denial results. |
| Retained-state scan, export, disposal, and resume restoration | [`worker_artifacts.py`](worker_artifacts.py) | Verifies retained bytes before deleting or rebuilding the disposable worker. |
| Candidate scope and acceptance checks | `accept_candidate(...)` in [`worker.py`](worker.py) | It checks one-file scope, base and patch hashes, patch application, forbidden source markers, and the configured build. A failed post-apply check reverses and restages the patch before returning. |
| Canonical statement and trust-base implementations | [`../harness/gates/StmtCanon.lean`](../harness/gates/StmtCanon.lean) and [`../harness/gates/g2_trust_base.py`](../harness/gates/g2_trust_base.py) | These gates exist in the earlier runner and are locked into the control bundle. The new tracer does not call them yet. |
| Hostile verifier bundle intake and report reduction | [`verifier_bundle.py`](verifier_bundle.py) | Rejects unsafe or mismatched bundle members before any clean-worker checks run. |
| Clean verifier VM execution and report binding | [`verifier.py`](verifier.py), [`terminal_run.py`](terminal_run.py) | Checks the pinned runtime and exact accepted commit in a fresh no-network volume; a partial helper audit binds the dependency closure but still imports all project modules and cannot pass the root. |

Canonical statements, `native_decide` use, and the trust base are recomputed on
the clean verifier. The candidate receipt remains a preflight record and cannot
authorize success.

## Tests worth reading

| Test | What it checks |
| --- | --- |
| [`tests/test_cli_snapshot.py`](../tests/test_cli_snapshot.py) | Input schemas, toolchain lock, control bundle, policy, and prepared target. Worker preparation is replaced in the native-policy unit test. |
| [`tests/test_model_proxy_fixture.py`](../tests/test_model_proxy_fixture.py) | Deterministic proxy route, signed fixture receipts, tamper rejection, and a separate `runsc` route smoke test |
| [`tests/test_linux_isolation.py`](../tests/test_linux_isolation.py) | Actual disposable Lima lifecycle, `runsc` inspection, four-class egress denial, fixed-proxy capability denial, signed accounting, retained-state scans, export, disposal, and fresh-clone resume |
| [`tests/test_parallel_lanes.py`](../tests/test_parallel_lanes.py) | Barrier-backed leaf overlap, private paths, scope and policy rejection, stale re-verification, replay idempotency, and top-proof readiness |
| [`tests/test_restart_budget.py`](../tests/test_restart_budget.py) | Atomic checkpoint selection, working/accepted recovery, graph-state replay, wall/cost exhaustion, exact fixture totals, and rejected-receipt evidence |
| [`tests/test_phase1_diamond.py`](../tests/test_phase1_diamond.py) | Controller flow with test doubles, concurrent evidence-write regression, worker/verifier command construction, and the full sealed two-worker diamond |
| [`tests/test_probe_graph.py`](../tests/test_probe_graph.py) | Probe schema and closure mutations, deterministic graph direction and scheduling, raw-byte retention, and pre-model failure results |
| [`tests/test_prepare_dalek.py`](../tests/test_prepare_dalek.py), [`tests/test_generic_role_e2e.py`](../tests/test_generic_role_e2e.py) | Deterministic preparation and role-path restart/scheduling with test doubles; not a provider-backed VM run |
| [`tests/test_preflight_cli.py`](../tests/test_preflight_cli.py), [`tests/test_clean_verifier.py`](../tests/test_clean_verifier.py) | Preflight CLI/binding and scoped helper/terminal verifier checks; local mocks do not establish a provider-backed run |
| [`tests/test_results_evidence.py`](../tests/test_results_evidence.py) | Complete L0/L4 claims, receipt/file binding, missing evidence, typed failures, and append-only attempt records |
| [`tests/test_image_contract.py`](../tests/test_image_contract.py) | Pinned image contents and runtime contract |
| [`harness/gates/tests/test_g1.py`](../harness/gates/tests/test_g1.py) | Canonical Lean statement fingerprinting |

The older runner under `harness/` remains useful reference code. Its behavior
is documented in [`docs/HARNESS-DETAIL.md`](../docs/HARNESS-DETAIL.md). It is
not the sealed AutoFV execution path.

## Rules for updating this guide

- State whether a check used test doubles, a local fixture service, a real VM,
  or a provider call.
- Call fixture usage and cost synthetic.
- Never add a proxy signing key, provider credential, hidden reference, or
  complete future-response program to the target or worker volume.
- Do not call a run successful until the accepted tree passes on the separate
  clean verifier and every bound identity matches.

The fixture has local sealed-run evidence with synthetic usage. Live provider
helper attempts have retained accounting and failure evidence, but an accepted
Dalek pair, a provider-backed full-run success and cloud host/VPC enforcement
remain unestablished.
