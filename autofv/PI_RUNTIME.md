# Pi/OpenAI subscription transport: local testing and qualification

This is the handoff for the opt-in **production transport integration**, not a
claim that a live subscription experiment has been qualified. Start with the
offline sections. Stop at each permission gate; implementation and dependency
installation approval does not authorize sign-in, a live model probe, VM
operations, or a proof experiment.

The integration is:

```text
autofv run → AutoFV LangGraph controller → DeepAgents role loop
  → authenticated fixed worker relay/provider service
  → supervised Python/Node IPC → public Pi ModelRuntime.stream
  → OpenAI Responses
```

AutoFV retains its source/statement gates, five scoped role tools, fresh
reviewers, durable journals, canonical-tree acceptance, separate helper
`SCOPED_PASS`, and terminal clean verifier. Pi supplies one model generation per
admission and never executes tools. **There is no Pi Durable Harness nested
inside DeepAgents.** The older
[Durable experiment](../experiments/pi-durable-openai-subscription/README.md)
remains a separate, one-role spike.

## 1. Readiness and the remaining gates

Implemented entry points are `autofv run --runtime-record`, `autofv doctor
--runtime-record`, and `autofv run --resume-from`. The separate public module
`python -m autofv.pi_qualification` provides `prepare`, `qualify`, `probe`, and
`grant`; section 8 gives the actual commands. The frozen Pi profile is
`autofv-fvs-pi-openai/v1`, selected by `autofv-run/v3`, with `gpt-6.1-sol`,
requested `xhigh` reasoning, and required tool choice for every role. Reviewers
are fresh OpenAI conversations. This does not establish parity with the API
profile's OpenAI/Claude reviewer arrangement or any success-rate improvement.

**The code paths and offline tests do not make the live backend qualified.**
Production admission requires signed, exact-runtime evidence for sealed
isolation, cancellation, and live entitlement, plus same-worker preflight
verification. The supported producers derive artifacts from their checks;
unit-test fixtures do not satisfy this. Actual Pi local VM checks, real model
entitlement, and a live public-CLI proof slice have not been performed in the
cloud implementation/offline work.

The supported OAuth setup provisions a dedicated store, but the public SDK
credential does not independently report the selected account ID. Its
`account_binding_sha256` binds a random store lineage and the local integrity
public key, not a
provider-attested account identity. The user must select/confirm the intended
account in the supported local login; independent account-ID verification
remains a disclosed limitation. Login alone does not establish entitlement.

Use the Pi `probe` command for the separately approved one-generation check.
The existing `autofv preflight --check-model-accessibility` is for the API path;
it is not a subscription probe. Do not manufacture `status: passed` qualification
JSON, use synthetic keys/approvals, copy the API grant, change hashes until
validation accepts them, or bypass admission to get a response. Giving a local
assistant this guide does not authorize sign-in, VM checks, probing, or proof
work. Resolve any failed engineering check and obtain the applicable fresh
approval before progressing.

## 2. Reproduce the checkout and frozen installations

Repository: `Beneficial-AI-Foundation/auto_verify_dalek`.
Branch: `ada/pi-durable-openai-subscription`.
The integration was developed on base commit
`3b7010c280aaf58a0c2d324ba960bb715e673210`. That base alone contains the isolated
spike, not the later integration changes described here. Use the **final integration
commit from the delivery handoff**, and record its identity; do not mistake the
base SHA or a moving branch name for a reproducible release. The implementation
code's final offline validation ran at
`a40ae5854ebceb8988ba554b9548c7f4baf30c00`; the subsequent documentation-only
commit is supplied in the handoff.

```sh
git clone --branch ada/pi-durable-openai-subscription \
  https://github.com/Beneficial-AI-Foundation/auto_verify_dalek.git
cd auto_verify_dalek
# Set to the final integration commit supplied with the handoff, then pin it:
: "${EXPECTED_COMMIT:?Set EXPECTED_COMMIT to the delivered integration commit}"
git checkout --detach "$EXPECTED_COMMIT"
test "$(git rev-parse HEAD)" = "$EXPECTED_COMMIT"
git status --short
git rev-parse HEAD
```

The tested tool versions are **Python 3.12.14, uv 0.12.23, and Node v24.19.0**.
Use the same versions for reproduction. The Python project permits 3.12 only;
Node 24 is also needed for the isolated spike's built-in SQLite usage. Install
tools from their official distributions only under applicable installation
approval. Do not install or update anything during a model run.

```sh
python3.12 --version
uv --version
node --version
uv sync --frozen --python 3.12.14
.venv/bin/python --version
(cd autofv/pi_runtime && npm ci --ignore-scripts)
# Separate install for the isolated Durable spike; not needed by production:
(cd experiments/pi-durable-openai-subscription && npm ci --ignore-scripts)
```

All 57 locked Python package versions are unchanged. The narrow `uv.lock`
artifact update adds the missing Linux wheels for the existing `jiter==0.17.0`
pin and preserves the macOS artifacts. A fresh Linux `uv sync --frozen`
installation passed. This is not a Python dependency upgrade. Do not run
`uv lock --upgrade`, unconstrained `pip install`, or `npm update` to reproduce it.

Production pins `@earendil-works/pi-ai` and
`@earendil-works/pi-coding-agent` to 1.2.0, with the 1.2.0 Pi/chord overrides.
The separate spike additionally directly pins Pi Durable and chord 1.2.0.
Both npm locks are checked in. `npm ci --ignore-scripts` is intentional:
dependency lifecycle scripts, including those declared by `@google/genai` and
`protobufjs`, must remain disabled. Production has no Durable dependency in
its manifest. Registry resolution/source inspection does not establish live
provider behavior.

The supported local deployment is the **pinned checkout with its editable
`.venv` CLI** created by `uv sync --frozen`. The full controller still depends on
repository-level harness/Docker/toolchain resources that the existing wheel
does not package. A standalone wheel-installed full CLI outside a checkout is
**not supported or qualified** by this work.

The editable CLI can be addressed from another working directory without
relying on the shell's current path:

```sh
AUTOFV_CHECKOUT="$PWD"  # Set while at the pinned checkout root.
(cd /tmp && "$AUTOFV_CHECKOUT/.venv/bin/autofv" --help)
# Use the same absolute executable for doctor/run, with all input paths absolute.
```

The **bridge resources** are separately packaged as `autofv/pi_runtime`, resolved
through `importlib.resources`. A wheel carries `.mjs` files, tool schemas,
manifest, and lockfile; it does not carry `node_modules`, OAuth/provisioning
files, store-signing-key files, or private journals. For a bridge-resource-only packaging check in a
separate approved wheel environment, locate that environment's runtime and
install its exact Node lock there, rather than relying on a source checkout:

```sh
# Use the Python of the wheel environment, not a source checkout's Python.
RUNTIME_DIR="$(python -c 'from autofv.pi_process import runtime_path; print(runtime_path())')"
(cd "$RUNTIME_DIR" && npm ci --ignore-scripts)
```

To rebuild and check the optional installed-wheel boundary from the final
checkout (still offline with respect to authentication/inference):

```sh
uv build --wheel --out-dir "$PWD/dist"
AUTOFV_PI_TEST_WHEEL="$PWD/dist/autofv-0.1.0-py3-none-any.whl" \
  .venv/bin/python -m unittest -v tests.test_pi_process
```

The wheel-resource test and an actual wheel-environment `npm ci` are distinct;
record which you performed. A source-tree pass alone does not verify dependency
resolution from the installed package's directory. Neither test establishes
standalone full-controller CLI support.

Recompute runtime metadata on the actual host. A different Node binary, bridge,
lockfile, or platform requires a different approved identity; the Linux test
identity must not be copied into a macOS record.

## 3. Run the offline checks first

From the repository root, after the frozen installations:

```sh
# Production transport policy/store tests; then actual pinned SDK with intercepted I/O.
(cd autofv/pi_runtime && node --test test/*.test.mjs)
(cd autofv/pi_runtime && node --test test-sdk/*.test.mjs)

# Focused Python profile, supervisor, accounting, replay, and public-CLI coverage.
.venv/bin/python -m unittest -v \
  tests.test_runtime_profile tests.test_pi_process tests.test_pi_backend \
  tests.test_subscription_receipts tests.test_pi_recovery \
  tests.test_subscription_results tests.test_pi_stage_evidence \
  tests.test_pi_role_runtime tests.test_pi_cli_e2e tests.test_pi_deadline \
  tests.test_pi_qualification

# Broad supported host-only regression; do not replace with ungated discovery.
.venv/bin/python tests/host_regression.py

# Separate Durable-spike checks; these do not test the production role loop.
(cd experiments/pi-durable-openai-subscription && node --test test/*.test.mjs)
(cd experiments/pi-durable-openai-subscription && node qualify.mjs)
(cd experiments/pi-durable-openai-subscription && node --test test-sdk/*.test.mjs)
```

`tests/host_regression.py` refuses non-loopback Python network activity and
unmocked guest/build commands and lists excluded guest/image methods explicitly.
The real-SDK Node tests and CLI fixture separately intercept the actual SDK's
network requests. A Python socket guard alone is not a Node network sandbox.
The Node sidecar is trusted host code, like the existing Python provider
service. It is not a separately OS-network-confined process. The boundary
protects the candidate worker with runsc/fixed relay and limits the sidecar by
pinned code, a minimal environment, and SDK endpoint policy. Qualification must
state `sidecar_os_network_confinement: false`; an allowlisted fetch wrapper or
intercepted SDK test is not a claim that a hostile trusted Node process cannot
open a socket. The design's fixed-egress requirement is addressed by that trusted-code
policy and independent deny/intercept tests, not by adding an OS sandbox around
Node. The existing candidate-worker restrictions remain unchanged.

No command above needs real credentials or a model call. If one tries to reach
an external provider, stop and investigate rather than supplying credentials.

The public-CLI fixture uses the real LangGraph/DeepAgents roles, production
relay/service, actual Python/Node IPC, pinned SDK encoding/stream parsing,
native continuation, journal, and usage attestations. It substitutes synthetic
HTTP responses and the external preparation, compiler/VM, qualification, and
verifier boundaries. A simulated `SCOPED_PASS` and terminal `PASS` validate
controller behavior only. They are not Lean proof or sealed-run evidence.

See the [dated validation record](../experiments/pi-durable-openai-subscription/VALIDATION.md)
for actually completed commands and counts. Reproduction commands are not
claims that every optional stage has already passed.

### Metadata without credentials or a runtime record

```sh
NODE_ABSOLUTE="$(.venv/bin/python -c 'from pathlib import Path; import shutil; print(Path(shutil.which("node")).resolve())')"
export NODE_ABSOLUTE
.venv/bin/python - <<'PY'
import json, os
from autofv.pi_process import runtime_diagnostic
print(json.dumps(runtime_diagnostic(os.environ['NODE_ABSOLUTE']), indent=2))
PY
```

This reads package metadata and hashes the Node executable, packaged bridge,
actual installed Node dependency-file bytes, trusted AutoFV Python code, Node
lockfile, and available checkout Python manifest/lock bytes. It does not initialize a model, open credentials, sign in,
refresh a catalog, or test entitlement. The lower-level Node command
`node autofv/pi_runtime/transport.mjs --diagnostic` reports protocol/packages
only. Save these non-secret metadata results with local test evidence.

Once a structurally valid runtime record exists, the public diagnostic is:

```sh
.venv/bin/autofv doctor --runtime-record /absolute/private/runtime-record.json
```

`metadata_match` means only that installed runtime metadata matches. Inspect
`authentication_checked: false`, `entitlement_checked: false`,
`live_qualified: false`, and `blockers`. An expired original grant is reported;
a zero command exit status is not permission or readiness to run.

## 4. User-operated OAuth setup: a separate permission gate

**Stop and ask for fresh approval before starting OAuth or saving a credential.**
Do not run this in the cloud handoff, read an existing Pi/Codex auth file, import
private SDK `AuthStorage`, ask the user to paste tokens into chat, or extract
an OAuth token into an API-key field.

After the user approves a separate sign-in and dedicated local credential
store, the user can run the supported interactive script on their trusted host:

```sh
# Parent directory may exist; the final store directory MUST NOT exist.
umask 077
mkdir -p "$HOME/.local/share/autofv"
node autofv/pi_runtime/setup.mjs \
  --new-store "$HOME/.local/share/autofv/pi-subscription-store"
```

For the supported editable checkout, use that checkout's script. A separately
installed bridge-resource setup script can also be addressed by its absolute
runtime path, but that does not make the full wheel-installed controller supported. The script requires a real TTY and the typed confirmation `SIGN IN`.
It calls the public `ModelRuntime.login('openai', 'oauth', ...)` flow, prints the
official sign-in URL, and lets the user choose the intended account in their
browser. Complete any supported prompt in that local flow. It makes no model
request and refuses to overwrite/adopt an existing directory.

The resulting directory is mode 0700; `credential.json`,
`store-signing-key.pem`, and `provisioning.json` are mode 0600. Only the last is
non-credential provisioning metadata. Never paste, log, upload, or commit the
credential or private signing-key files. Keep the entire directory outside the candidate
source, worker, verifier mounts, shared worktrees, public result evidence, and
source-control repository. Protect backups with the same restriction.

The runtime permits only OAuth credentials for provider `openai`; missing,
API-key, command-backed, substituted-provider, and externally changed stores
fail closed. SDK-owned locked refresh may persist rotated credentials. The
signed managed-store/v2 envelope preserves integrity and lineage checks across
process restarts, alongside in-process change detection. Unsigned legacy
v1 stores are refused. These checks do not independently prove who owns the
provider account.
If the intended account cannot be verified through supported means, stop the
live qualification. Successful login does not establish model entitlement.

## 5. Run/v3 configuration and trusted runtime record

The exact validators are [contracts.py](contracts.py),
[runtime_profile.py](runtime_profile.py), and [pi_backend.py](pi_backend.py).
Both the run config and runtime record require **canonical JSON plus one
newline**, not pretty-printed JSON. Extra/missing fields fail validation.

The run/v3 shape is:

```json
{
  "schema": "autofv-run/v3",
  "model": "gpt-6.1-sol",
  "role_profile": "autofv-fvs-pi-openai/v1",
  "source_packet": "REPLACE_WITH_THE_COMPLETE_VALIDATED_SOURCE_PACKET_OBJECT",
  "max_wall_seconds": 600,
  "max_cost_usd": null,
  "max_invocations": 24,
  "helper_reserves": {
    "first_specification": 300,
    "distinct_verification": 120,
    "terminal_audit": 60,
    "finalization": 10
  }
}
```

This is a schema illustration, **not a runnable grant**: `source_packet` must be
the actual object. The example limits are not approved limits. Use the values
in a fresh, explicit subscription approval. The source packet must bind the
exact prepared target, original public Rust checkout/revision, complete relevant
source, grounding/style, and hashes. Do not use the CLI test packet or hidden
verifier reference as model input. Optional `helper_reserves` has exactly
`first_specification`, `distinct_verification`, `terminal_audit`, `finalization`;
all must be positive, strictly decreasing, and below `max_wall_seconds`.
They must also leave useful work time inside any shorter actual grant. The
illustrative 600-second proof-only config above therefore supplies explicit
reserves. Without them, proof-only retains the existing large stage defaults
(including 2100 seconds for first specification). Full mode does not inherit
those proof-only stage defaults: it uses the ordinary finalization reserve
unless explicit helper reserves are supplied. A shorter grant tightens
controller/Lean/callback/recovery and cleanup budgets too, not just model
admission; it never expands a reserve or resets the original deadline.

To serialize an already reviewed object without changing its contents:

```sh
.venv/bin/python - <<'PY'
from pathlib import Path
from autofv.contracts import _read_json, canonical_json_bytes
source = Path('/absolute/private/reviewed-run-draft.json')
target = Path('/absolute/private/run.json')
target.write_bytes(canonical_json_bytes(_read_json(source, 'reviewed draft')) + b'\n')
PY
```

If you already have a validated prepared FVS run/v2 config, the following
**offline draft conversion** preserves its exact source packet and sets
explicit reviewed Pi limits/reserves. It changes profile/accounting identity, so its old API approval does
not carry over. Set the limits to the separately reviewed Pi limits; do not
infer subscription permission from successful validation.

```sh
# These are local file paths and reviewed integers, never credentials.
export EXISTING_FVS_CONFIG=/absolute/reviewed/prepared-run-v2.json
export PI_CONFIG=/absolute/private/pi-run-draft.json
export PI_WALL_SECONDS=600 PI_MAX_INVOCATIONS=24  # Illustrative, not approval.
export PI_SPEC_RESERVE=300 PI_VERIFY_RESERVE=120 PI_AUDIT_RESERVE=60 PI_FINAL_RESERVE=10
.venv/bin/python - <<'PYCONFIG'
import os
from pathlib import Path
from autofv.contracts import canonical_json_bytes, validate_run_config
from autofv.runtime_profile import PI_MODEL, PI_PROFILE_ID
_, old = validate_run_config(os.environ['EXISTING_FVS_CONFIG'])
if old['schema'] != 'autofv-run/v2':
    raise SystemExit('Expected a reviewed prepared FVS run/v2 config')
config = {**old, 'schema': 'autofv-run/v3', 'model': PI_MODEL,
          'role_profile': PI_PROFILE_ID, 'max_cost_usd': None,
          'max_wall_seconds': int(os.environ['PI_WALL_SECONDS']),
          'max_invocations': int(os.environ['PI_MAX_INVOCATIONS']),
          'helper_reserves': {
              name: int(os.environ[variable]) for name, variable in (
                  ('first_specification', 'PI_SPEC_RESERVE'),
                  ('distinct_verification', 'PI_VERIFY_RESERVE'),
                  ('terminal_audit', 'PI_AUDIT_RESERVE'),
                  ('finalization', 'PI_FINAL_RESERVE'))}}
path = Path(os.environ['PI_CONFIG'])
with path.open('xb') as output:
    output.write(canonical_json_bytes(config) + b'\n')
validate_run_config(path)
print('Validated draft only; no grant, worker, authentication, or model request.')
PYCONFIG
```

The production runtime record has exactly these fields (schematic placeholders
are deliberately not valid hashes or evidence):

```json
{
  "schema": "autofv-pi-runtime-record/v1",
  "role_profile": "REPLACE_WITH_EXACT_runtime_profile.profile()_OBJECT",
  "runtime_identity": {
    "schema": "autofv-pi-runtime-identity/v1",
    "protocol_version": 1,
    "node_sha256": "ACTUAL_NODE_SHA256",
    "bridge_sha256": "ACTUAL_BRIDGE_SHA256",
    "package_lock_sha256": "ACTUAL_PACKAGE_LOCK_SHA256",
    "packages": {
      "@earendil-works/pi-ai": "1.2.0",
      "@earendil-works/pi-coding-agent": "1.2.0"
    }
  },
  "grant": {
    "schema": "autofv-pi-run-grant/v1",
    "approval_id": "ACTUAL_EXPLICIT_SUBSCRIPTION_APPROVAL_REFERENCE",
    "account_binding_sha256": "APPROVED_PROVISIONED_STORE_LINEAGE_SHA256",
    "config_sha256": "ACTUAL_CANONICAL_RUN_CONFIG_SHA256",
    "original_started_epoch_ms": "ACTUAL_ORIGINAL_START_INTEGER",
    "original_deadline_epoch_ms": "ACTUAL_ORIGINAL_ABSOLUTE_DEADLINE_INTEGER",
    "max_invocations": 24,
    "acknowledgements": {
      "no_server_output_cap": true,
      "unknown_subscription_cost": true,
      "best_effort_remote_abort": true
    },
    "qualification": {
      "isolation_sha256": "ACTUAL_SIGNED_SEALED_QUALIFICATION_FILE_SHA256",
      "callback_cancellation_sha256": "ACTUAL_SIGNED_CALLBACK_QUALIFICATION_FILE_SHA256",
      "entitlement_sha256": "ACTUAL_SIGNED_LIVE_ENTITLEMENT_FILE_SHA256"
    }
  },
  "node_executable": "/absolute/verified/node",
  "credential_store_path": "/absolute/private/pi-subscription-store/credential.json",
  "receipt_signing_key_path": "/absolute/private/controller-attestation-key",
  "preflight_path": "/absolute/retained/preflight-result.json",
  "suite_artifact_path": "/absolute/retained/suite-artifact.json",
  "qualification_paths": {
    "isolation_sha256": "/absolute/retained/pi-isolation-qualification.json",
    "callback_cancellation_sha256": "/absolute/retained/pi-callback-qualification.json",
    "entitlement_sha256": "/absolute/retained/pi-entitlement-qualification.json"
  }
}
```

Requirements beyond the shape:

- Obtain `role_profile` from `runtime_profile.profile()` and `runtime_identity`
  from the actual host's `runtime_diagnostic`; never choose arbitrary roles,
  models, endpoints, tool schemas, headers, provider overrides, or options.
- All paths are absolute. The runtime record must be a regular non-symlink file.
  Use private permissions for it even though it contains references, not OAuth
  bytes. The credential directory and signing key must be controller-owned,
  private, and outside the candidate source. The attestation key is exactly
  32 raw Ed25519 seed bytes; it is a controller key, not an OpenAI credential.
  Use the qualification authority's securely provisioned key, not a test seed.
- The grant's `config_sha256` binds the exact canonical run configuration;
  even a changed source packet or reserve cannot reuse an old approval. Its
  invocation limit must equal the run config, be positive, and not exceed 1024. Its positive start/deadline integers must be ordered and their
  interval must not exceed the configured wall seconds. Preserve both on resume.
- Qualification files must have the actual referenced file hashes and valid
  signatures under the configured attestation authority. They must bind the
  exact runtime, role profile, and account lineage. Expected evidence classes
  are `sealed_runtime` for isolation/callbacks and `live_entitlement` for
  entitlement. A signed assertion alone is not a replacement for performing
  and retaining the underlying qualification.
- `AUTOFV_RUN_TOKEN` is still required by the trusted fixed relay. Provision it
  through the existing trusted deployment flow; never put it in the config,
  candidate files, command logs, or public evidence. `--runtime-record` replaces
  API provider configuration; it does not remove the sealed worker/relay needs.

Do not hand-author this record. The supported `grant` command in section 8
writes canonical JSON after it verifies the actual produced qualification
artifacts and the separately approved limits. It does not fill in missing
authority. Its preflight paths are reserved for the run's own retained
same-worker checks, not copied API or test fixtures.

## 6. Prepared inputs and eventual public run

**Do not execute this section until the required local checks have passed and
the user separately authorizes the VM operations and bounded proof experiment.**
The command is the implemented parser's complete prepared-input shape, not a
claim that the live prerequisites have been met.

Have these reviewed, mutually consistent inputs on the trusted host:

1. A redacted prepared target directory containing `autofv.json`.
2. The external preparation manifest and a preparation-evidence directory
   containing the exact `probe-rust.json` and `probe-aeneas.json` files.
3. The matching dependency-cache archive (the file passed to
   `--preparation-cache`, not a replacement package download).
4. The pinned public `curve25519-dalek/src` checkout for `--public-rust-root`.
   This is host-ingested model-visible public source, not the hidden reference.
5. The external hidden verifier-reference file, never included in the source
   packet or candidate filesystem.
6. The canonical run/v3 config and authentic runtime record above.
7. A stopped, prepared `autofv-agent-template` and separate `autofv-verifier`
   with the exact locked image/runtime inventory and fixed relay deployment.
   See [local sealed prerequisites](README.md#local-setup). Provisioning is not
   automated here and is not authorized by an offline test request.

`autofv inspect` supplies a target report only. The existing preparation entry
point is `python -m autofv.prepare_dalek --source ... --target-report ...
--probe-identities ... --mode full|small --output ... --manifest ...`; it does
not invent missing probe identity, source packet, or verifier reference inputs.
Check `--help` and the preparation tests when reproducing the approved input
pipeline. Do not substitute the synthetic fixture for a real prepared target.

```sh
.venv/bin/autofv run /absolute/prepared/target \
  --config /absolute/private/run.json \
  --runtime-record /absolute/private/runtime-record.json \
  --output-root /absolute/retained/pi-runs \
  --preparation-manifest /absolute/prepared/preparation-manifest.json \
  --preparation-evidence /absolute/prepared/probe-evidence \
  --preparation-cache /absolute/prepared/dependencies.tar \
  --public-rust-root /absolute/pinned-public/curve25519-dalek/src \
  --verifier-reference /absolute/private/verifier-reference.json \
  --execution-mode proof-only
```

`proof-only` requires one prepared small target. Use `full` only with its
corresponding reviewed prepared inputs and approval. The runtime record cannot
be combined with `--env-file`, `--selection-record`, or
`--fresh-pair-preflight`. The separate API `$10`/wall-clock authorization is not
subscription authority. Do not add `--budget-started-epoch-ns` to reset a grant;
the record owns the original clock.

The modern SDK provider/API is `openai` / `openai-responses`, with inference
endpoint `https://api.openai.com/v1/responses`. `openai-codex` is not the selected
provider. SDK OAuth refresh uses the separately allowlisted OpenAI auth route.
No alternate account/model or paid API fallback is permitted.

## 7. Resume, uncertainty, accounting, and retained evidence

A resume uses the same command and same inputs, with:

```sh
  --resume-from /absolute/retained/original-run-directory
```

This option selects the retained run/checkpoint directory; it does not grant a
new invocation budget or wall period. All roles share one authenticated
run-wide grant, one active generation at a time, and the original absolute
clock. Queueing, process restarts, host sleep, and time away still consume that
clock; helper/verifier/finalization reserves remain in force.

A signed allocation ledger beside the private attestation key binds each
approval to one run/config/source snapshot and its original retained directory.
Copying the runtime record, creating a different run directory, or deleting a
per-run journal cannot legitimately create another allowance. Preserve the
bootstrap's `run-allocations` state alongside the run's private journal; do not
move the run/authority paths or delete allocation records to make a resume pass.

Completed, authenticated exchanges replay from retained state without a new
Pi generation. Missing/tampered private continuation, changed profile/runtime,
a mismatched history, an uncertain dispatched request, auth/quota failure, or
broken IPC is a stop condition. A timeout/local kill cannot establish whether
the provider generated output or consumed quota. **Do not automatically resend,
start a replacement run to evade the stop, clear journals, or rotate accounts.**
Retain the failure and request an explicitly authorized reconciliation plan.

Subscription reporting is intentionally different from API billing:

- `cost_usd` and `max_cost_usd` are `null`; classification is
  `subscription_cost_unknown`. Unknown is never `$0` or a catalog-price estimate.
- A controller-signed usage attestation authenticates observed request/response,
  role/runtime identity, usage, and continuation digest. It is not an OpenAI
  billing receipt or proof of free usage.
- Normalized input is Pi `input + cacheRead + cacheWrite`; output is Pi `output`.
  Reasoning tokens, when reported, are a subset of output and are not added twice.
  Requested `xhigh` and observed effort are separate fields; absent provider
  reporting does not prove an independently observed effort level.
- A complete dispatch ledger can have `dispatch_accounting_complete: true`
  while `monetary_cost_known: false`. Unresolved dispatches prevent a clean
  completed-run claim. Missing failed-request usage is unknown, not zero.
- There is **no server-enforced output-token cap** for this subscription path.
  The 4 MiB client raw-response cap (before SDK SSE parsing), local
  frame/context bounds, and finite invocation/deadline policy do not cap remote
  output/quota. Abort is best effort upstream; OAuth refresh persistence
  can have a separate bounded lifecycle.

The private `provider-private` journal contains native continuation material,
including opaque reasoning signatures that can themselves contain summary text.
Keep it private and available for authenticated resume. Ordinary public evidence
contains signed usage, profile/runtime identities, and continuation hashes, not
those native bytes. Public retained audit can validate that evidence without
OAuth credentials/private continuation; that does **not** make a public export
sufficient to resume. Do not upload a complete private run directory as a bug
report. Share only reviewed, sanitized public evidence.

## 8. Supported local qualification, bounded probe, and grant

These commands are implemented in [pi_qualification.py](pi_qualification.py).
They are **local, separately permission-gated actions**, not commands to run as
part of the cloud/offline handoff. Review the returned JSON and retain the exact
paths it supplies. Do not infer paths inside its approval-hashed directories.
Each command has `--help`; reading help starts no operation.

### A. Prepare local metadata and attestation authority

After the user-operated OAuth setup in section 4, obtain approval to create the
private local controller attestation key/bootstrap as part of that setup. Then:

```sh
.venv/bin/python -m autofv.pi_qualification prepare \
  --node "$NODE_ABSOLUTE" \
  --provisioning "$HOME/.local/share/autofv/pi-subscription-store/provisioning.json" \
  --output "$HOME/.local/share/autofv/pi-qualification"
```

The output directory must be new. `prepare` reads only non-credential
provisioning metadata and installed runtime metadata; it makes no model request
or sign-in. It creates a private 32-byte `attestation.key` and signed
`bootstrap.json`. Keep this directory outside every candidate/source directory
and never publish the key. The returned `bootstrap` is the path used below.
Preparing a signing key is not proof that any qualification passed.

### B. Qualify the existing local sealed boundary

**Stop and obtain separate approval for the local VM/sealed checks.** Select a
fixed original absolute deadline in epoch milliseconds within the approved
window, and a reference identifying that specific approval. Save those exact
values. Do not recompute a later deadline or invent a replacement approval ID
when repeating a command.

```sh
.venv/bin/python -m autofv.pi_qualification qualify \
  --bootstrap /absolute/private/pi-qualification/bootstrap.json \
  --repo /absolute/prepared/target \
  --approval-id "$SEALED_APPROVAL_ID" \
  --deadline-epoch-ms "$SEALED_DEADLINE_MS" \
  --approve-local-sealed-checks
```

This starts the existing local sealed worker, runs its fixed prerequisite suite,
checks that credential/key/private-continuation-canary paths are not visible in
worker and candidate mounts, and checks the fixed Node fetch policy. A real
supervised cancellation canary must stop and reap the local process group.
The checks make zero model requests and run no Lean proof. The Node sidecar
remains trusted host code; reports explicitly retain
`sidecar_os_network_confinement: false`. The canary exercises the Node generation/abort boundary with an intercepted
SDK response, not a real Python/Lean lane callback. It is not observation that
an upstream provider stopped or a qualification of every possible callback.

Only a successful command emits actual signed `isolation` and
`callback_cancellation` artifact paths. Preserve their referenced retained
reports, runtime identity, and bootstrap together. A failed or missing check
must be diagnosed; do not replace it with a handwritten pass artifact.

The existing broader environment tests are still useful **under their own VM
approval**, but are separate from the Pi producer:

```sh
.venv/bin/python -m unittest -v tests.test_linux_isolation
.venv/bin/python -m unittest -v \
  tests.test_phase1_diamond.Phase1DiamondTests.test_one_full_sealed_concurrent_diamond
```

The second uses fixture responses and proves no live subscription or Pi proof
success. No actual VM qualification was run in the cloud implementation work.

### C. One-generation entitlement probe

**Stop and ask for fresh approval for one live subscription model request.**
The approval must identify the exact OpenAI-only profile, one invocation,
original absolute deadline, unknown subscription cost/quota use, no
server-enforced output-token cap, and best-effort remote abort. The original
probe window must be at most **120 seconds**, the pinned per-request timeout;
choose the approved deadline before invoking the command. The probe is
not proof work and executes no model-selected tool callback.

```sh
.venv/bin/python -m autofv.pi_qualification probe \
  --bootstrap /absolute/private/pi-qualification/bootstrap.json \
  --approval-id "$PROBE_APPROVAL_ID" \
  --deadline-epoch-ms "$PROBE_DEADLINE_MS" \
  --approve-one-live-request \
  --ack-no-server-output-cap \
  --ack-unknown-subscription-cost \
  --ack-best-effort-remote-abort
```

The three flags record acknowledgements actually given by the user; setting
flags is not permission. Probe admission permanently consumes its one-invocation
allowance before opening the SDK process/authentication path. Every failure
thereafter leaves the approval uncertain and prevents a resend. A completed
identical probe can replay its retained signed result with zero new requests;
a retry must use the same original ID/deadline. Never change the ID to evade an
uncertain outcome, rotate accounts, or fall back to API billing.

On success the command returns the `entitlement` artifact and a signed report
with observed usage, provider response identity when supplied, requested versus
observed effort/model, and `cost_usd: null`. It also retains private native
continuation bytes. This is a controller observation, not a provider billing
receipt or independent account-ID attestation. `live_qualified: false` remains
honest: a successful probe alone does not qualify the proof pipeline.

### D. Create a separate proof-experiment grant

Prepare and review the actual run/v3 config and all inputs from sections 5–6.
**Obtain a separate experiment approval** naming the prepared target, invocation
limit, wall/deadline, runtime/profile, VM use, and all three subscription
limitations. Use a distinct approval ID; the one-call probe grant cannot be
reused for a proof experiment.

```sh
.venv/bin/python -m autofv.pi_qualification grant \
  --bootstrap /absolute/private/pi-qualification/bootstrap.json \
  --config /absolute/private/run.json \
  --isolation "$ISOLATION_FILE" \
  --callback-cancellation "$CALLBACK_CANCELLATION_FILE" \
  --entitlement "$ENTITLEMENT_FILE" \
  --approval-id "$EXPERIMENT_APPROVAL_ID" \
  --deadline-epoch-ms "$EXPERIMENT_DEADLINE_MS" \
  --approve-experiment \
  --ack-no-server-output-cap \
  --ack-unknown-subscription-cost \
  --ack-best-effort-remote-abort
```

Set the three artifact variables to the exact successful `qualify`/`probe`
outputs, not test fixtures. The command verifies their signatures and retained
report hashes, creates the canonical runtime record, and returns its
`runtime_record` path. It makes no model request. Its original start is fixed
on the first grant invocation; the deadline interval cannot exceed the run
config's wall limit. Run preparation/preflight and subsequent resume consume
that same clock. Re-running `grant` cannot renew the start, change the inputs,
or expand the limit under the same approval.

Use the returned runtime record in `autofv doctor`, then in the full public
run command in section 6. Doctor is still metadata-only. On first run,
`authorize_prepared` creates the actual sealed preflight on the already prepared,
Pi-bound worker at the record's generated preflight/suite paths. It validates
and reloads those same retained artifacts on resume. This consumes the original
experiment clock and precedes model dispatch; a standalone qualification
report cannot substitute for it.

Report these independently: offline transport tests, actual sealed checks,
user-selected account/identity limitations, model entitlement, helper
`SCOPED_PASS`, terminal verification, and any scored result. Successful setup,
qualification, or one model response is not a successful proof experiment.

## 9. Handoff checklist for a local assistant/operator

- Record final Git SHA, clean/dirty state, tool versions, both relevant lock
  hashes, and actual host runtime metadata.
- Reproduce frozen installs and offline suites; save exact command output,
  failures, skips, and unexercised methods. Do not convert missing evidence into
  a green status.
- Keep the current API v1/v2 route and approved base-branch work separate.
- Use the supported local qualification/probe/grant commands, retain their
  real evidence, and disclose the independent account-identity limitation before
  asking the user to run a proof command.
- Stop for fresh permission at OAuth, credential storage, VM execution, live
  probe, and proof-experiment boundaries. No cloud live action is implied.
- Preserve original grant, signed journal, private continuation, and failure
  state; never compensate for uncertainty with another generation.
- Deliver public sanitized evidence and an honest result classification. Preserve
  private restart state locally without exposing it to the model or verifier.
