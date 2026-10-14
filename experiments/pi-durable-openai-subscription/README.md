# Pi Durable + managed OpenAI subscription: bounded SDK spike

This opt-in spike is stacked on `946bd3c73e2a417e3a2f432b9e0faa59511d062e`.
This **Durable Harness spike is not wired into the `autofv` CLI**, is not a
qualified experiment backend, and supplies no proof-success or scored-run
evidence. A separate production integration now lives in `autofv/pi_runtime`
and uses public `ModelRuntime.stream` beneath the existing DeepAgents loop;
it does not use this Harness. See the [local integration/testing handoff](../../autofv/PI_RUNTIME.md)
for its actual CLI, frozen installs, resume, and pending local sealed/live gates.
Its supported local qualification producers are the separate
`python -m autofv.pi_qualification prepare|qualify|probe|grant` commands;
this directory's `qualify.mjs` remains metadata-only. The existing OpenRouter
FVS profile, mixed OpenAI/Claude roles, budgets, receipts, and verifier pipeline
are unchanged. No success-rate improvement is established.

## What is implemented

- `openRoleHarness` uses public `ModelRuntime.create`, a guarded host-owned
  `CredentialStore`, and `Harness.open(..., { models, registry, settings }, ...)`.
  It does not launch a Pi coding-agent session or discover home/project tools,
  context, plugins, MCP, shell environments, or CLI resources.
- A separate `autofv-pi-openai-only-spike/v1` profile explicitly names a model
  for every role. It is not equivalent to the current Claude-reviewed FVS pair.
  Each role opens a fresh ownerless conversation, never a fork of another role.
- The registry contains exactly the five existing callback schemas. Callback
  implementations must call the existing trusted controller's validated
  `invoke_lane_tool` boundary. The wrapper does not pass Durable's tool API,
  runtime, registry, environment, or credentials to callbacks. Callbacks receive
  only validated arguments plus an explicit abort signal/original deadline.
  Late callbacks are refused; cancellation quarantines the run. Read-only roles
  cannot invoke edit/Lean callbacks. Submission terminates the role; it is not
  acceptance, proof review, scoped verification, or terminal verification.
- Generation and provider retries, automatic/background compaction, deferred
  polling, and parallel tools are disabled. No delegation tool, extra extension,
  hook, execution environment, or arbitrary task API is exposed.
- A private SQLite admission journal persists the original grant and one
  reservation before each dispatch. A duplicate, uncertain request, quota/auth
  failure, timeout, or interrupted reservation stops further dispatch. Reopening
  cannot renew the original clock. Recovered Durable work is refused before
  any call that enables scheduling; manual reconciliation is required. This
  conservative spike also refuses opening any nonempty admission journal after
  clean completion, avoiding a fresh-conversation/session idempotency bypass.
  An atomic one-time role/Harness claim prevents concurrent empty-journal opens;
  that claim survives failed setup and clean close. One journal currently serves
  one role handle, not an entire multi-role experiment. The eventual controller
  adapter must preserve the shared run budget across roles without creating
  independent replacement grants.
- Usage reports preserve token counts, including reasoning as a subset of output.
  Subscription cost is `null`/unknown. They are not signed provider billing
  receipts. Pi's internal catalog-price estimates and error-protocol zero
  placeholders are not reported as subscription charges or free usage.
- SDK errors are reduced to fixed codes before Durable sees them. Mutable SDK
  partials are deliberately not forwarded. Terminal output is projected onto
  known fields and deep-copied; raw errors, causes, headers and arbitrary SDK
  metadata are not written to the admission journal or forwarded to Durable.

The `Models` facade is a deliberately narrowed runtime seam: `getModel` and
`streamSimple` work; other operations deny. It is not a claim of full static
implementation of the broad Pi `Models` interface.

## Offline checks

Node 24 is required for the built-in SQLite journal; the Pi SDK itself requires
Node >=22.19. No dependency installation is needed for the policy tests:

```sh
cd experiments/pi-durable-openai-subscription
node --test test/*.test.mjs
node qualify.mjs
```

`qualify.mjs [profile.json]` only reads the profile and installed package metadata.
It does not initialize a model runtime, inspect credentials, refresh a catalog,
or send requests. The checked-in example is deliberately expired and unapproved.
Its model names are proposed identifiers, not proven subscription entitlements.

The exact intended dependency set is `@earendil-works/pi-{ai,coding-agent,durable}`
and `@earendil-works/chord`, all 1.2.0. Chord is also a Pi transitive dependency;
it is explicit here because the bridge uses its public context API. Source
declarations and interfaces were inspected at upstream commit
`7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6`. Source package versions alone do not
prove published registry artifacts match that commit. The generated `package-lock.json` now records the approved exact registry
installation. Reproduce it separately with `npm ci --ignore-scripts`; never
install packages as a side effect of qualification or model dispatch.

After the authorized frozen installation, the separate SDK test command is:

```sh
node --test test-sdk/*.test.mjs
```

Those tests use real SDK imports and real Durable execution with synthetic
credentials/responses. All `fetch` calls are intercepted: no real authentication
or model request is required. The source-level tests and real-SDK tests are
separate evidence classes. The real-SDK suite has now been executed offline;
see [VALIDATION.md](VALIDATION.md) for the dated result and remaining limits.

## Authentication and budgeting decisions

The supported modern provider is `openai`; `openai-codex` is legacy. Credentials
stay entirely inside the trusted controller's managed store. The bridge checks
only the public credential type tag; Pi owns OAuth resolution/refresh. It never
exports a token or passes one into an API-key field itself.

Crucially, `env: {}` does **not** disable Pi ambient API-key resolution. The store
guard throws on absent/non-OAuth credentials at every locked read and mutation,
instead of returning `undefined`, which could enable fallback. It refuses other
providers and caller-supplied keys, headers, environment, or request transforms.
Reads use the public `modify` lock with an unchanged-on-undefined callback,
because some stores execute command-backed API keys inside their raw `read()`.
No model/account rotation is implemented. A dedicated store must not be changed
to a different account while a run is active; account/entitlement provisioning
remains a trusted-controller setup requirement. The production transport has a
separate user-operated `setup.mjs` using the public SDK login API. It is not
invoked by this spike, and login alone does not establish account identity or
model entitlement.

Pi 1.2.0 does not publicly export its default `AuthStorage` class. A supported
host-supplied `CredentialStore` is required; this spike intentionally does not
import internal storage code, implement a replacement OAuth login flow, or read
an existing authentication file. No login/setup command runs in this code.

ChatGPT subscription Responses rejects `max_output_tokens`. The pinned Pi code
therefore omits it even if `maxTokens` is supplied. The existing 16k server-side
output ceiling cannot be inherited. A live grant is refused unless a separately
approved profile explicitly accepts:

1. No server-enforced output-token ceiling (`serverOutputCap: null`).
2. Unknown per-run subscription cost, without treating it as zero.
3. An original absolute deadline, finite invocation count and per-request timeout.
4. Best-effort abort: stopping locally does not prove upstream generation/usage
   stopped. A timeout leaves a quarantined liability and never retries.
5. Exact-model entitlement validation and a recorded live approval identifier.
6. Separate sealed-isolation and callback-process-cancellation qualification
   evidence hashes. Both are unset in the example, so live use remains blocked.

These fields record controller authorization/evidence references; editing a JSON file does not
itself grant permission. The live entry rejects synthetic grants. Tests exercise
synthetic approval records only against intercepted execution.

A local abort race cannot terminate an uncooperative Lean process or revoke a
late filesystem edit. The trusted controller must validate the referenced
isolation/callback evidence and implement process/transport cancellation before
issuing a live grant; no such live evidence is generated by this spike. Raw
Harness cancellation is explicitly admitted with a non-cancelled cleanup
context, because merely cancelling a caller's SDK context only stops its wait.

OAuth refresh is separate from model retries. Pi may finish refresh persistence
after cancellation to avoid losing a rotated credential, with an internal
15-second timeout. The controller deadline does not establish remote cancellation.

## Remaining for this Durable spike or any live experiment

1. Preserve the approved exact dependency lock and passed offline SDK evidence.
   Re-run `npm ci --ignore-scripts` and the tests when reproducing this spike.
2. Supply a supported managed, dedicated host credential store and separately
   authorize sign-in. Validate exact model entitlement without reading/exporting
   credential values. This spike does not provide that setup adapter; the
   separate production setup script and its identity limitations are documented
   in the integration guide.
3. Approve the new role arrangement and bounded subscription policy. Neither the
   example profile nor the existing API experiment approval covers this profile.
4. If promoting Durable itself, add an explicit alternative role-runtime adapter
   replacing DeepAgents for that role, using the existing role-job,
   source/statement-binding, candidate validation, journal, and callback protocols.
   The copied schemas are checked against `autofv.agent_lane._TOOL_SCHEMAS`;
   matching schemas alone do not establish transport/protocol compatibility.
   The production ModelRuntime transport already has a Python/Node adapter, but
   that does not integrate this separate Durable role loop.
5. Bind the admission journal and grant to the existing trusted run root, original
   clock and approval record. Keep auth, journal and controller memory outside
   every model-visible filesystem, durable document, transcript, and artifact.
   Private journal permissions alone are not a sandbox or an authentication MAC.
6. Verify sealed OS/network isolation, no hidden context/resources, source binding,
   fresh reviewers, recovery failure behavior, and distinct scoped plus terminal
   verification. Reuse existing AutoFV enforcement rather than replace it.
7. Only after separate authorization, perform one bounded real request and then
   the ordinary public-CLI acceptance path. No live or scored qualification is
   performed by the offline suite.

## Public evidence

- [Managed ModelRuntime options and Models implementation](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/coding-agent/src/core/model-runtime.ts)
- [CredentialStore contract](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/ai/src/auth/types.ts)
- [Stored credential ownership and ambient fallback](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/ai/src/auth/resolve.ts)
- [Durable Harness settings and interfaces](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/durable/src/harness/types.ts)
- [Upstream test demonstrating recovery resend](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/durable/test/harness-generation-recovery.test.ts#L74-L121)
- [Pi omits unsupported subscription output caps](https://github.com/earendil-works/pi/blob/7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6/packages/ai/src/api/openai-responses.ts#L328-L341)
- [OpenAI subscription preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)
