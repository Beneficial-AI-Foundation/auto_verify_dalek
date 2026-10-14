# Validation record: isolated spike and production integration

Date: 2026-10-14. Environment: isolated Linux cloud checkout, Python 3.12.14,
uv 0.12.23, Node v24.19.0. Branch:
`ada/pi-durable-openai-subscription`.

The original Durable spike was based on
`946bd3c73e2a417e3a2f432b9e0faa59511d062e` and retained at
`3b7010c280aaf58a0c2d324ba960bb715e673210`. The later production integration is
being validated on top of that commit. **That base SHA is not the integrated
release.** Record the final delivered commit with `git rev-parse HEAD` and use
that SHA for reproduction. Counts below identify suites and must not be summed
as though overlapping coverage were independent experiments. Final implementation
code tested here: `a40ae5854ebceb8988ba554b9548c7f4baf30c00`; the following
documentation-only commit does not change tested executable source.

## Distinct implementations

- This experiment directory uses Pi Durable `Harness` and its own one-role
  admission journal. It remains isolated from the AutoFV CLI role loop.
- `autofv/pi_runtime` is the production one-generation transport. The ordinary
  AutoFV CLI selects it via `autofv-run/v3` and `--runtime-record`, beneath the
  existing LangGraph controller and DeepAgents roles. It calls the public typed
  `ModelRuntime.stream`, without a nested Durable Harness.
- Read [PI_RUNTIME.md](../../autofv/PI_RUNTIME.md) for frozen installation,
  complete CLI input/record shapes, local setup, resume, and live gate limits.

## Completed installation and offline evidence

The following results were obtained in the implementation checkout. They do
not describe an actual authenticated subscription, real model, VM, or proof run.

| Check | Observed result | What it establishes |
| --- | --- | --- |
| Fresh Linux `uv sync --frozen` | Passed | Pinned Python installation resolves on Linux; all 57 package versions unchanged |
| `jiter==0.17.0` lock artifact adjustment | Linux wheel entries added, macOS entries retained | Artifact completeness only; no version upgrade |
| Production `npm ci --ignore-scripts` | Installed from exact lock, 118 package entries | Pinned registry dependency availability; lifecycle scripts disabled |
| Isolated spike `npm ci --ignore-scripts` | Installed from exact lock, 121 package entries | Separate Durable dependency installation; lifecycle scripts disabled |
| Production `node --test test/*.test.mjs` | 17 passed | Synthetic protocol, policy, continuation, credential/store, and safe setup boundary behavior |
| Production `node --test test-sdk/*.test.mjs` | 8 passed | Actual pinned SDK imports and intercepted native request/stream behavior |
| Python supervisor `tests.test_pi_process` | 15 passed with the optional wheel test enabled | Bounded IPC, process controls, resource packaging, and installed artifact lookup |
| Profile/role targeted regression | 238 passed, including 26 new tests | Distinct Pi identity and v1/v2 compatibility in the selected suites |
| Spike `node --test test/*.test.mjs` | 33 passed | Existing synthetic Durable boundary tests |
| Spike `node --test test-sdk/*.test.mjs` | 6 passed | Actual SDK/Durable execution with intercepted requests and synthetic credentials |
| Original Python archive/control-bundle checks | 24 passed | Existing archive and candidate-control boundary tests |
| `tests.test_pi_cli_e2e` | 4 passed | Actual public CLI/SDK/IPC with synthetic external effects; replay and uncertainty boundaries |
| `tests.test_pi_deadline` | 7 passed | Shorter original grant bounds full/proof-only work, external callbacks, cleanup, and recovery |
| `tests/host_regression.py` | 785 run: 774 passed, 11 skipped, 0 failures; 15 guest/image methods separately excluded | Final frozen-source host aggregate; zero blocked guest/network attempts |
| `tests.test_pi_qualification` | 23 passed in the combined qualification/backend/supervisor run | Public prepare/qualify/probe/grant, actual intercepted SDK plus OS kill/reap, and synthetic external VM/probe boundaries |

All npm resolved entries use `registry.npmjs.org` and lockfile SHA-512
integrities. Package lifecycle scripts, including those declared by
`@google/genai` and `protobufjs`, were not run. Real-SDK fixtures were updated to
include the pinned SDK's required synthetic OAuth `clientId` and `scopes`.
No real credential was read to construct those fixtures.

The supported deployment is the pinned checkout/editable CLI. The existing full
controller wheel omits repository-level harness/Docker/toolchain resources;
standalone full-CLI operation outside a checkout is not supported or validated.
The packaging evidence below concerns the bridge resources only.

The wheel was built with the pinned `uv_build==0.12.7`. Final inspection found 84
entries, including production runtime modules, schemas, `package.json`, and
`package-lock.json`, and `qualification.mjs`, without `node_modules`, OAuth,
provisioning files, or `store-signing-key.pem`. The
optional supervisor check used:

```sh
AUTOFV_PI_TEST_WHEEL=/tmp/autofv-pi-final-wheel/autofv-0.1.0-py3-none-any.whl \
  .venv/bin/python -m unittest -v tests.test_pi_process
```

That temporary wheel path is specific to the implementation environment;
reproduce by building the same final commit and using the resulting wheel path.
Do not copy a cloud temporary pathname into a local runtime record.
The final wheel was also extracted outside the source tree under `/tmp`; its
runtime passed the metadata diagnostic and all 8 actual-SDK intercepted tests.
This verifies the bridge-resource package boundary, not the unsupported
standalone full-controller deployment.

The signed managed-store/v2 boundary now verifies persisted credential-envelope
integrity and the provisioned lineage across restart; unsigned v1 stores are
rejected. This is not an independent provider account-ID attestation. Runtime
identity covers actual installed Node dependency bytes, trusted controller Python
code, packaged bridge files, and available checkout Python manifest/lock bytes.
A 4 MiB client raw-response cap is enforced before SDK SSE parsing; it is not a
server output-token or subscription quota cap.

## Public-CLI slice and aggregate validation

The integration's explicit test entry point is:

```sh
.venv/bin/python -m unittest -v tests.test_pi_cli_e2e
.venv/bin/python tests/host_regression.py
```

The focused CLI suite passed all 4 tests. It performed 18 synthetic native
generations for the successful role sequence; terminal resume and completed
model replay made no extra request, and tampered continuation was rejected. A
missing terminal-usage case retained one uncertain invocation with no retry and
null cost. An actual first-SIGINT interruption during a hung intercepted SDK
fetch killed/reaped the process before terminal audit, with one uncertain
invocation and no tool callback/retry. The retained result's complete subscription
accounting was validated against its saved model receipts. Removing the unittest
qualification bootstrap rejected the unqualified synthetic runtime before
process spawn. The focused CLI/deadline command passed 11 tests in 29.507
seconds. The final host aggregate ran 785 tests in 87.047 seconds: 774 passed,
11 skipped, no failures, and zero blocked guest/network attempts. The 11 skips
were 10 unavailable Lean checks and the optional wheel-environment check; that
wheel check was independently passed in the 15-test supervisor run (2.844
seconds). A further 15 live guest/image methods were explicitly excluded and
remain unexercised, not passed. The CLI fixture runs the real public parser/controller, DeepAgents, fixed relay/service, IPC, installed SDK,
continuation, and accounting. Preparation, VM/compiler/verifier effects,
entitlement, and a test-scoped qualification bootstrap are synthetic. Its
helper/terminal outcomes are simulation evidence, unscored, with subscription
cost `null`. The test-only SDK network interceptor is not a production bypass.
The trusted Node sidecar is not separately OS-network confined. Candidate
runsc/fixed-relay isolation and pinned trusted-host code are the implemented
trust boundary; qualification must report
`sidecar_os_network_confinement: false`. Fixed-egress checks are trusted-code
policy plus independent synthetic network guards; they do not add a Node OS sandbox or weaken the existing
candidate-worker restrictions.

## Supported qualification commands

`python -m autofv.pi_qualification` now exposes real `prepare`, `qualify`,
`probe`, and `grant` commands; all help/parser forms were inspected and executed
without starting their operations. The documented local flow no longer asks an
operator to invent passed qualification artifacts. Its focused offline suite
passed 23 tests with public positive/denial paths, changed approval/config
identity rejection, exact-SDK/intercepted request policy checks, real private
IPC, and real OS process cancellation. The actual sealed wrapper's VM boundary
was explicitly mocked. The combined qualification/backend/supervisor command
reported 51 tests with one expected optional wheel-environment skip; the wheel
check was separately run successfully as recorded above. Generated qualification
artifacts were validated by the unpatched production validator, with external
VM/preflight boundaries mocked. Its actual VM/live-probe actions remain
unperformed here.

The proof grant now binds `config_sha256`. Its signed durable allocation binds
one approved grant to the original run/source/config/root; copying a record
does not mint a second budget. First-run same-worker preflight is implemented
on the already prepared Pi-bound worker; resume reloads the retained paths.
These implementation checks do not imply actual local VM qualification.

The cancellation canary exercises the supervised Node generation boundary with
synthetic/intercepted SDK data. It does not execute a real Python/Lean role
callback or prove remote cancellation. Actual local qualification and a live
one-request probe require the separate approvals listed in the handoff guide.

## Historical blockers now superseded

The original spike validation had no installed Pi packages, `langgraph`, or
`deepagents`; its actual-SDK suite was then unrun. Those dependency and SDK-test
blockers are resolved by the approved frozen installations and results above.
The stale review-token assertion expected 8192 while the frozen base profile
specified 16384; the implementation corrects the assertion without changing
the profile's token limit. No server token limit is inferred for Pi from that
API-profile value.

`node qualify.mjs` remains an **offline spike metadata diagnostic**. The example
profile is deliberately expired and unapproved. Installed packages no longer
need to be reported missing, but model entitlement, live approval, sealed
isolation, and callback cancellation are still not established by this command.
It does not initialize a model runtime or sign in.

## Not performed or established

- No actual OAuth sign-in, real credential inspection, account identity
  attestation, live provider request, or exact-model entitlement check.
- No cloud/local VM provisioning or actual Pi sealed-isolation, unexpected-egress,
  or callback-process-cancellation qualification.
- No actual Lean proof, clean-verifier acceptance, subscription proof experiment,
  scored result, comparative success-rate claim, or provider billing receipt.
- No proof that local process cancellation stops upstream generation/quota.
- No TypeScript full-`Models` static conformance claim for the narrowed JavaScript
  Durable facade.

Synthetic credentials, model output, usage, grants, and qualifications remain
test fixtures. Signed controller usage attestations are not OpenAI billing
receipts. Unknown subscription cost is `null`, never zero or catalog pricing.
A public retained audit and a private resumable continuation have different
evidence/access requirements. The offline pass does not authorize the next
live gate; follow the explicit handoff guide and obtain the relevant fresh
approval first.
