# AutoFV usage

AutoFV's intended workflow is to run an experiment on a repository you provide,
with its top-level Lean specifications already prepared. Dalek is a test case;
you should not need to adopt its directory layout or construct its benchmark
artifacts to use the eventual CLI.

**The complete repo-first workflow is not implemented yet.** This page separates
that goal from the commands and requirements that exist today. For the current
operator-assisted test case, see [the development recipe](DEVELOPMENT-RUN.md).

## The intended workflow

After installing AutoFV and Lima and configuring model access and a budget:

1. Give AutoFV the path to a supported Lean project. Its top-level specs must
   already exist; the experiment may still need internal helper specs/proofs.
2. AutoFV reads the project/toolchain metadata, provisions its runtime and
   prepares an isolated copy. Repository build scripts and probe extraction
   that require a build should execute inside that isolation.
3. AutoFV uses the pinned probe output to discover the top-level function/spec
   pairs and their dependencies. It records the selection and freezes the
   supplied statements before agent work.
4. The agent works inside the disposable sandbox under the chosen network and
   spending policy. Supplied top-level specs are not silently weakened to get
   a passing proof.
5. A separate verifier checks the accepted tree against those frozen specs and
   the declared trust policy. AutoFV exports patches, results, accounting and
   cleanup evidence; your original checkout remains unchanged.

The CLI should create the internal manifests, probe records, source packets
and caches itself. Requiring users to assemble them is a current implementation
gap, not the intended interface. Model credentials and budget consent remain
user choices; they are not sandbox-provisioning chores.

This does not automatically translate arbitrary Rust crates into Lean or invent
missing top-level requirements. Unsupported toolchains, build systems or
ambiguous spec selection must be reported explicitly. Other crates can be
supported once their prepared Lean projects fit the discovery/build contracts.

## Top-level specification discovery

The requested `probe-lean count` integration is **not present in AutoFV**.
The probe-lean source snapshots inspected for this branch register `extract`,
`viewify` and `check-axioms`, not `count`; no host `probe-lean` executable was
available to validate a different command. The exact version/command/schema
must be settled when wiring this feature, rather than documenting an invented
invocation as working.

What exists in AutoFV today:

- `autofv inspect` invokes `probe-rust extract` and `probe-aeneas extract`.
- It computes candidate graph roots from Lean implementations in the merged
  Rust/Aeneas graph, and reports roots with a `primary-spec` association.
- `autofv run` reads the explicit function/spec pairs in root `autofv.json`
  and checks them against the probe graph. It does not generate that manifest
  automatically from the inspection report.
- This path requires Rust/Aeneas probe evidence; it is not a generic standalone
  Lean-project discovery path. The older `harness/lean_top*.py` research scripts
  are not a replacement for integrating discovery into the CLI.

Discovery needs declaration identities, spec mappings and dependency data,
not only a numeric count. “Graph root,” “public Rust API” and “the user's intended
top-level specification” are not interchangeable. Missing or ambiguous mappings
must not silently become a guessed target set.

## Install and inspect the current command surface

The current local backend requires macOS/Lima; its upstream egress policy uses
macOS Seatbelt. Installing Lima on another OS does not establish support.
From this controller checkout, development installation also requires Python
3.12 and `uv` in addition to the runtime prerequisites below:

```bash
uv sync --frozen
.venv/bin/autofv --help
.venv/bin/autofv inspect --help
.venv/bin/autofv run --help
.venv/bin/autofv preflight --help
```

Help commands do not start VMs or call a provider. There are currently three
commands: `inspect`, `run`, `preflight`. There is no automatic setup/init command,
network-policy option or CLI resume flag.

### inspect

For an existing project supported by the installed Rust/Aeneas probes:

```bash
.venv/bin/autofv inspect /absolute/path/to/project \
  --output /absolute/path/outside/project/target-report.json
```

The output parent must already exist and must be outside the target. This
writes a candidate-target report, not a complete run configuration or preparation
bundle. Its temporary raw probe outputs are not exported.

**This command invokes probe tools on the host.** It is not currently the
sandboxed, arbitrary-repository discovery step described in the intended
workflow. Do not treat it as a safe way to execute an untrusted project's build
scripts on your machine. It was not run on a new target during this docs audit.

### run

The current parser requires `REPO` and `--config`; a repository path alone is
insufficient. The target must contain root `autofv.json` with explicit targets
and a verifier argv. The run config selects the implemented runtime/model
contract and budget. A familiar directory name does not satisfy these checks.

The current provider-backed FVS path additionally requires a prepared manifest,
raw probe evidence, dependency cache, matching public source packet, private
provider setup and an external verifier reference. These requirements belong
to the existing experimental path; they must not become mandatory hand-built
inputs for the normal repo-first product.

The bounded generic role scheduler currently rejects more than one selected
root. `--execution-mode full` is a parsed option, **not** a multi-root support
switch. A repository with many prepared top-level specs is therefore not yet a
supported all-target experiment merely because the probes can list them.

Use [the development recipe](DEVELOPMENT-RUN.md) only when its exact prerequisites
and separately approved scope are satisfied. The recipe is not a generic command
for a new repository. Every fresh invocation can allocate a new paid attempt;
a failed run does not authorize an automatic retry.

### preflight

`autofv preflight` starts a worker VM and performs sealed checks. Its FVS
`--check-model-accessibility` option can make paid requests. It is not an
offline dry run, and it does not install missing VMs or manufacture missing
preparation artifacts. The bounded fresh-helper route includes its own
same-worker preflight; it does not need an extra preliminary experiment.

## What the CLI handles versus what still needs setup

| Responsibility | Today | Intended repo-first behavior |
| --- | --- | --- |
| Install host virtualization | User installs Lima. | Same, apart from installing AutoFV itself. |
| Prepare Linux runtime, image and tools | Operator provisions the pinned worker template and verifier. | CLI bootstraps and validates them. |
| Start a disposable worker | CLI clones/starts `autofv-agent-run` from the stopped template. | CLI-owned; never a manual per-run task. |
| Set up sandbox boundaries | CLI enforces Docker/gVisor, resource limits, filesystem restrictions and fixed egress. | CLI-owned under an explicit run policy. |
| Provision/start the verifier VM | A separate verifier must already be running with the required resources. | CLI ensures an independent verifier is ready. |
| Discover and freeze targets | Explicit target manifest plus probe validation; inspection is separate. | CLI derives and records targets from the prepared specs. |
| Prepare run inputs | Operator supplies several matching artifacts; current FVS ingestion is Dalek-bound. | CLI creates internal artifacts for supported projects. |
| Execute multiple top-level targets | Generic scheduler requires one selected root. | Run the discovered target set with honest per-target results. |
| Export and dispose | CLI exports evidence and deletes the owned run VM; cleanup failures are reported. | Same responsibility; preserve failures, not only successes. |

**Installing Lima alone does not satisfy today's prerequisites.** No user should
manually create `autofv-agent-run`; that part is already automated. The missing
work is first-use bootstrap and generic repository ingestion, not moving
per-run sandbox management onto the user.

An external trusted verifier reference is required by the current prepared
benchmark path. It should remain a benchmark-specific input, not a requirement
for the normal case where the user's top-level specs are already supplied. That normal mode
needs to verify the unchanged statements and their proof/trust closure without
requiring an existing solution checkout. This separation is not implemented.

## Network policies

Today the agent worker has restricted egress through the fixed model proxy.
That permits model requests, not general web access. The independent verifier
runs with `--network none`. There is no CLI or run-config option to enable
arbitrary internet access; disabling one firewall rule is not a supported mode.

The intended distinction for future experiments is:

| Policy concept (not a current CLI option) | Purpose |
| --- | --- |
| Restricted benchmark | Keep known solutions inaccessible. This remains the policy for the Dalek benchmark. |
| Internet-enabled project | Explicitly permit approved web/dependency access inside the sandbox for projects where that is acceptable. |

Implementing the second policy needs both network enforcement and appropriate
agent tool access; opening egress alone does not add a web tool to the bounded
role interface. The policy and retrieved inputs must be reflected in the run's
provenance/evidence. Dependency downloads during controlled setup are also
separate from giving the agent general internet access.

Internet access must not expose the host checkout, credentials, SSH agent,
runtime sockets or private verifier inputs. Keep the VM/filesystem boundary,
resource limits, frozen-spec checks and independent verification. The verifier
should remain offline against recorded dependencies. Results from the two
policies have different solution-exposure assumptions and must say so.

## Reading a current result

The CLI prints result JSON and uses a nonzero exit status for non-success.
Use `run_root` to find the attempt directory. Argument or persistence failures
can occur before a complete result exists.

```bash
run_dir=/absolute/path/from/result/run_root
.venv/bin/python -m json.tool "$run_dir/result.json"
.venv/bin/python -m json.tool "$run_dir/disposal.json"
```

Check `outcome` and `termination_detail`, accepted spec/proof counts,
`helper_verification`, `targets_verified_final`, verifier reports and exported
evidence. A reviewer PASS or successful local Lean check is not independent
acceptance. A secondary final-audit error may follow a more useful first failure.

Read accounting and unresolved-request fields alongside `cost_usd`: receipt
observations, reservations and invoices are different things. A process exit
does not by itself prove cleanup. Do not apply a rejected working patch as if
it were part of the accepted tree.

## Implementation work still required

The next product work is probe-driven repo ingestion, first-use Lima/runtime
bootstrap, automatic internal artifact preparation and removal of Dalek-specific
assumptions. Multi-root execution and an explicitly declared internet-enabled
policy also need implementation and tests. The existing sandbox, role loop,
accounting and verifier code provide useful building blocks; they do not yet
compose into the promised one-command experience on a new repository.

The current helper proof blocker and regression-test issues remain separate
from those onboarding gaps. See [the implementation reference](README.md).
