# Prepared experiment: the current Dalek test case

This is the existing operator-assisted development procedure, not the intended
user interface for arbitrary repositories. The [usage guide](USAGE.md) describes
the repo-first goal, missing automation and current limits. Keep the Dalek-specific
inputs here rather than treating them as permanent requirements for all users.

AutoFV runs from this controller checkout and takes a separate target directory.
You do not copy the controller into `dalek-clean-small` or `dalek-clean`.
The target is copied into an isolated worker; accepted changes and evidence are
exported to a run directory rather than applied to your original checkout.

**Current status:** this is an operator-assisted research CLI. Live provider
runs have reached specification review and proof attempts, but the current
Dalek helper experiment has not produced an accepted spec/proof pair. A cloned
target alone is not a complete runnable experiment. VM provisioning, preparation
artifacts and the target-specific FVS run configuration still require setup.

[Controller and evidence reference](README.md)

## 1. Install the controller, not the target

From a checkout of the branch containing `autofv/`, with Python 3.12 and `uv`:

```bash
uv sync --frozen
.venv/bin/autofv --help
.venv/bin/autofv run --help
```

The installed command is `autofv`; `.venv/bin/python -m autofv.experiment` is
an equivalent entry point. The only top-level commands are `inspect`, `run`
and `preflight`. There is no `autofv init`, VM installer or CLI resume command.

The current local worker backend uses macOS/Lima: a stopped
`autofv-agent-template`, a separate already running `autofv-verifier`, and the pinned
Docker/`runsc` image and runtime in both. See [local setup](README.md#local-setup)
and the [toolchain lock](../docker/autofv/toolchain-lock.json).
The CLI creates and disposes `autofv-agent-run`; do not create that VM manually.
Changing the target path does not provision this infrastructure.

## 2. Identify your target and its preparation bundle

Directory names do not select a mode. `dalek-clean-small` must actually be a
prepared small target; renaming a full checkout does not make it one.
The normal Rust-only `curve25519-dalek` repository is not an AutoFV target:
AutoFV expects the prepared Aeneas/Lean project, including its Lake files,
pinned dependencies and root `autofv.json`.

Keep these paths separate:

| Path | What must be there |
| --- | --- |
| `TARGET` | Your unchanged prepared Lean checkout, such as `/work/dalek-clean-small`, with `autofv.json` declaring the exact root function/spec pairs and verifier argv. |
| `RUN_CONFIG` | A run JSON outside the target. For FVS, `autofv-run/v2` contains the budget, pinned role profile and complete source packet for this preparation. |
| `PREPARATION` | The matching preparation manifest. It binds the prepared file inventory, selected roots, original source identity and probe identities. |
| `PROBES` | A directory containing the retained `probe-rust.json` and `probe-aeneas.json` named by that preparation. |
| `CACHE` | The matching dependency-cache archive, including the pinned Lean dependencies/build artifacts. A scored cache must exclude related solution proofs and recoverable solution history. |
| `PUBLIC_RUST` | The pinned public `curve25519-dalek/src` subtree in the source checkout identified by the manifest. FVS authenticates its revision, origin and named Rust bytes; it does not expose the entire checkout to the model. |
| `REFERENCE` | A trusted private verifier reference, outside the target, for the separate verifier. Never include it in the source packet, worker or model context. |
| `PROVIDER_ENV` | A private provider environment file, outside the target and version control, owned by you with mode `0600`. |
| `RUNS` | An existing output parent outside the target. Use a new child directory for each separately authorized attempt. |

These artifacts must describe the same preparation. Do not reuse another
checkout's run config, manifest, probes, cache or verifier reference merely
because the repository names look similar. An old clean-small checkout can
also be incompatible with the controller's current pinned Lean/image version.

### Where the files come from

An already prepared target should be accompanied by its operator's preparation
bundle. If all you have is the Git clone, obtain that bundle before launching.
There is no public command that generates all missing files from that clone.

`python -m autofv.prepare_dalek --help` describes the separate preparation tool.
It takes `--source`, `--target-report`, `--probe-identities`, `--mode small|full`,
`--output` and `--manifest`. It reads a pinned solved source, redacts and builds
an output project, and writes the preparation manifest. It is an operator step,
not the agent's source of reference solutions; it does not provision VMs or
produce the complete provider/config/cache/private-reference bundle.

`autofv inspect "$TARGET" --output /outside/target/report.json` invokes the
installed `probe-rust` and `probe-aeneas` executables on the host. It writes a
target report, not a preparation bundle; its temporary raw probe outputs are
not exported. It is not a pure JSON check, and the probe tools must already be
installed. The report's parent directory must exist and be outside the target.

### Run configuration and credentials

The fixture [run.json](../tests/fixtures/diamond/run.json) is a synthetic
`autofv-run/v1` example. Do not use it to launch the current Dalek FVS workflow.
FVS means the bounded specification/proof roles with fresh specification and
proof reviewers. Its current profile is `autofv-fvs-sol-sonnet/v2`:
`openai/gpt-6.1-sol` for author/prover roles and
`anthropic/claude-sonnet-5.5` for reviewers, through pinned OpenRouter routes.
This profile is fixed in [fvs_profile.py](fvs_profile.py), not an arbitrary
`--model` option or a ChatGPT subscription backend.

A v2 config has exactly `schema`, `model`, `role_profile`, `max_wall_seconds`,
`max_cost_usd` and `source_packet`, plus optional `helper_reserves`. The packet
contains complete approved Rust/Lean/type/interpretation/intent sources, style
and grounding data, with checked identities and hashes. Operators construct it
using [fvs_packet.py](fvs_packet.py); the current CLI has no packet-generation
wizard. Serialize a v2 config with `canonical_json_bytes(config) + b"\n"`
from [contracts.py](contracts.py). Pretty-printing it back to disk changes its
required canonical representation. Editing a budget or packet is a new run
condition, not permission to spend.

Use [`.env.example`](../.env.example) as the field list for `PROVIDER_ENV`.
Fill it through your trusted setup, not by sourcing it into the shell or
printing it. The FVS profile currently requires these non-secret values:

| Field | Pinned value |
| --- | --- |
| `AUTOFV_PROVIDER_ENDPOINT` | `https://openrouter.ai/api/v1/chat/completions` |
| `AUTOFV_PROVIDER_MODEL` | `openai/gpt-6.1-sol` |
| `AUTOFV_PROVIDER_INPUT_USD_PER_MILLION` | `2.000000` |
| `AUTOFV_PROVIDER_CACHED_INPUT_USD_PER_MILLION` | `0.100000` |
| `AUTOFV_PROVIDER_OUTPUT_USD_PER_MILLION` | `10.000000` |

The remaining fields are your provider API key and
`AUTOFV_RECEIPT_SIGNING_KEY_B64` (a base64-encoded 32-byte Ed25519 private seed).
Both stay in the trusted provider service, outside the worker. Do not substitute
an SSH key or publish a filled environment file. These are code-pinned pricing
inputs, not a promise of current provider availability or prices; live checks
reject unsupported routes or drift.

## 3. Check the JSON contracts without launching

Set absolute paths, then run this from the controller checkout:

```bash
TARGET=/absolute/path/to/dalek-clean-small
RUN_CONFIG=/absolute/path/to/run-inputs/run.json
.venv/bin/python - "$TARGET" "$RUN_CONFIG" <<'PY'
import sys
from autofv.contracts import validate_target, validate_run_config
validate_target(sys.argv[1])
validate_run_config(sys.argv[2])
print("JSON contracts valid; infrastructure and live access are not checked.")
PY
```

This reads the two JSON contracts without starting a VM or calling a provider.
It does not check the full preparation, prove a target or authorize spending.
`--help` is also safe. **`autofv preflight` is not an offline dry run:** it
starts a worker VM and runs sealed checks; its FVS `--check-model-accessibility` option
can make paid calls. The helper workflow below includes its own preflight on
the same worker, so do not run a separate preflight as an extra first step.

## 4. Launch one approved small-helper attempt

This is the current bounded FVS path for a prepared **small** target. Despite
the name `proof-only`, this path can generate and review a missing helper
specification before proving it. It does not mean “skip specification review,”
“prove every sorry,” or “the root theorem is verified.”

First agree on the exact inputs, account, budget and one-attempt scope. The
fresh-helper path rejects totals above **USD10 / 5400 seconds**. These are caps,
not a recommended spend or an authorization. The approved config may use lower
limits. The original clock must include operational preparation, accessibility
checks, roles, verification, audit and cleanup; never reset it to recover time.

Fill these paths from the bundle in section 2. `RUNS` must already exist:

```bash
AUTOFV="$PWD/.venv/bin/autofv"
TARGET=/absolute/path/to/dalek-clean-small
RUN_CONFIG=/absolute/path/to/run-inputs/run.json
PREPARATION=/absolute/path/to/run-inputs/preparation.manifest.json
PROBES=/absolute/path/to/run-inputs/raw-probes
CACHE=/absolute/path/to/run-inputs/dependency-cache.tar.zst
PUBLIC_RUST=/absolute/path/to/pinned-source/curve25519-dalek/src
REFERENCE=/absolute/path/to/private/verifier-reference.json
PROVIDER_ENV=/absolute/path/to/private/providers.env
RUNS=/absolute/path/to/runs
```

The following command **starts a worker VM and can spend money**. Run it only after
approval. On macOS, `caffeinate` keeps the host awake while the CLI runs; it does
not prevent lid-close or manual sleep. This example starts T0 immediately before
launch. If operational preparation began earlier, record T0 before that work
and pass that same value instead.

```bash
(
  set -eu
  set +x  # Never trace a run token.
  test -z "${AUTOFV_RUN_TOKEN+x}"  # Refuse an inherited token.
  T0_NS="$(.venv/bin/python -c 'import time; print(time.time_ns())')"
  OUT="$RUNS/helper-$T0_NS"
  mkdir "$OUT"
  printf '%s\n' "$T0_NS" > "$OUT/original-T0-ns.txt"
  export AUTOFV_RUN_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  export LEAN_NUM_THREADS=1
  caffeinate -i -s "$AUTOFV" run "$TARGET" \
    --config "$RUN_CONFIG" --output-root "$OUT" \
    --env-file "$PROVIDER_ENV" --fresh-pair-preflight \
    --execution-mode proof-only --budget-started-epoch-ns "$T0_NS" \
    --preparation-manifest "$PREPARATION" \
    --preparation-evidence "$PROBES" --preparation-cache "$CACHE" \
    --public-rust-root "$PUBLIC_RUST" --verifier-reference "$REFERENCE"
)
```

The token exists only in this subshell and its children; it is not your provider
API key. Keep it out of files and logs. For this path, do **not** also supply
`--selection-record`: the controller creates a run-bound selection after the
same-worker checks. Do not replay that selection in another run.

Every fresh invocation can allocate another attempt. The public CLI does not
provide the development operator's approval-record/one-shot wrapper or a
`--resume` flag. Keep your approval record and an outer wall-clock supervisor
when the operating procedure requires them. A failed command is not permission
to run it again; remaining budget does not authorize a second attempt.

## 5. What changes for dalek-clean or a full run?

The parser accepts `--execution-mode full`, but the generic scheduler still
requires exactly one selected root. A multi-root target is therefore not
supported merely by changing this flag or replacing the small checkout with a
full checkout. The fresh-helper option is additionally restricted to prepared
small/proof-only runs.

The non-helper provider path takes both `--env-file` and `--selection-record`,
omits `--fresh-pair-preflight` and `--budget-started-epoch-ns`, and still needs
matching preparation/cache/reference inputs. That does not bypass the scheduler
restriction. A retained model-selection record is not spending authorization.

Multi-root execution and generic repo preparation need implementation and tests.
For this benchmark, obtain one accepted helper pair and its retained audit
before proposing a larger experiment. A provider-backed full-run success has
not been established.

## 6. Read the outcome before using any patch

The CLI prints result JSON and exits nonzero for non-success outcomes. Use its
`run_root` to find the child attempt directory under `OUT`; `OUT` itself is only
the parent. Input/argument errors can occur before a complete result exists.

```bash
run_dir=/absolute/path/from/result/run_root
.venv/bin/python -m json.tool "$run_dir/result.json"
.venv/bin/python -m json.tool "$run_dir/disposal.json"
```

Check these separately:

- `outcome`, `termination_reason` and `termination_detail`: the first role/proof
  failure may precede a secondary final-audit error.
- `internal_specs_accepted`, `internal_proofs_accepted`, `helper_verification`
  and `targets_verified_final`: a reviewer PASS, frozen statement or successful
  local Lean check is not independent acceptance or root verification.
- `accounting`, `accounting_complete`, `unresolved_provider_requests` and
  `unknown_provider_spend`: distinguish completed receipt observations from
  reserved/uncertain liabilities. `cost_usd` is not an invoice.
- `disposal.json`, `export/manifest.json`, checkpoints and verifier evidence
  where present: a process exit alone does not prove cleanup or verification.

Inspect the accepted/exported tree and its bound verifier reports before
bringing changes into your own repository. Do not apply a working or rejected
candidate patch as if it were accepted. Missing verifier evidence is not PASS.

## What remains to make this easy

In the last attempt, the prover had the numeric value equality available but
still needed to prove that the computation actually returns that value. The
next proof task is to investigate the generic Aeneas weakest-precondition API
without weakening the statement or verification requirements. This is a proof
blocker, not a failure to launch the CLI. A further paid attempt needs its own
approval.
The onboarding gaps are separate: provision the pinned workers, package a
complete per-target run bundle, and expose configuration/selection setup without
requiring operator-written glue. Documentation makes these requirements visible;
it does not implement those missing conveniences.
