# AutoFV

AutoFV is a CLI for bounded agent-driven Lean specification and proof
experiments. The intended input is a user-provided repository whose top-level
specifications are already prepared. AutoFV should discover those targets,
freeze their statements, create the sandbox, run the agents, independently
verify accepted changes and export a reproducible result.

**That repo-first workflow is not complete in this branch.** The current CLI
runs operator-prepared experiments on an already provisioned machine. Installing
Lima and pointing it at an arbitrary Lean repository is not sufficient yet.
The current local backend is macOS/Lima with a macOS Seatbelt egress policy.
Dalek is our development test case, not the intended product boundary.

- [Usage: intended workflow and what works today](autofv/USAGE.md)
- [Implementation and evidence reference](autofv/README.md)
- [Current prepared experiment recipe](autofv/DEVELOPMENT-RUN.md)
- [Dalek benchmark snapshot and provenance](docs/DALEK-BENCHMARK.md)

## The intended user experience

Apart from installing AutoFV and Lima, the user should provide:

- a supported Lean project with top-level specs already written;
- model access and an explicit experiment budget;
- the network policy appropriate for the experiment.

AutoFV should handle the rest: provision its Linux runtime and tools, inspect
the repository with the pinned probes, discover and record the target/spec
identities, prepare caches and isolated workspaces, execute the experiment,
verify results and clean up. Users should not have to handcraft probe reports,
source packets, preparation manifests or VM templates for the normal workflow.
Those are currently exposed implementation details that still need automation.

“Any repository” means a project supported by the probe, Lean toolchain and
build adapter. It does not mean an arbitrary Rust crate with no Lean translation
or specifications. Missing or ambiguous top-level specs should produce an
explicit diagnostic rather than silently selecting a different target.

## What the implementation actually supports

| Capability | Current state |
| --- | --- |
| Repository path as input | Yes, but `run` also requires a run config and root `autofv.json` with explicit targets. |
| Automatic top-level spec discovery | Partial. `inspect` builds a candidate-root report from `probe-rust` and `probe-aeneas`; `run` does not automatically turn it into a target manifest. There is no `probe-lean count` integration. |
| Fresh sandbox for each attempt | Yes: clone/start an existing stopped template, create the Docker/gVisor sandbox and enforce its boundaries. Users do not manually create the run VM. |
| First-use setup from Lima alone | No. The template, pinned image/runtime and separate running verifier must already exist. |
| Agent specification/proof loop | Implemented for supported graphs. The generic role scheduler currently requires **one selected root**, not all roots in an arbitrary repository. |
| Multiple top-level specs / arbitrary crates | Not an end-to-end supported workflow yet. The current prepared FVS route also contains Dalek-specific preparation and Rust-source assumptions. |
| Verification and artifact export | Implemented. The separate verifier uses a fresh no-network volume; accepted changes, failures, accounting and disposal evidence are retained. A local build or reviewer PASS is not acceptance. |
| General internet access for agents | Not implemented. The current worker permits the fixed model-proxy route, not arbitrary internet access. There is no network-policy toggle. |
| Successful live-provider example | Live experiments have run, but the current Dalek helper experiment has not produced an accepted spec/proof pair. The successful sealed diamond fixture uses synthetic model responses. |

The `--execution-mode full` flag exists, but it does **not** remove the
single-root scheduler restriction or make arbitrary multi-target projects work.

## Try the current CLI without starting an experiment

Development installation requires Python 3.12 and `uv`:

```bash
uv sync --frozen
.venv/bin/autofv --help
.venv/bin/autofv run --help
```

These help commands do not start a VM or contact a provider. There is no
first-use VM installer, `autofv init`, internet-enable flag or CLI resume flag.
`autofv preflight` is an operational command that starts a worker VM; it is not a
harmless dry run.

For an already provisioned development environment, the
[current experiment recipe](autofv/DEVELOPMENT-RUN.md) documents the actual
required inputs and launch flags. That recipe is not the desired onboarding
contract for ordinary users.

## Network access is an experiment choice

The current Dalek benchmark must remain restricted because internet access
could expose known solutions. Future projects may permit internet access from
inside the sandbox, for example to retrieve documentation or dependencies.
That is a feasible extension, but not an existing option.

An internet-enabled policy must change the declared egress/tool permissions
and result evidence, not remove the VM, filesystem isolation, credential
separation or verification checks. The independent verifier should remain
offline. Restricted-benchmark and internet-enabled results must report their
different assumptions. See [network policies](autofv/USAGE.md#network-policies).

## Work needed to deliver the repo-first CLI

1. Connect probe-based top-level spec discovery directly to `run`; generate the
   internal target manifest and freeze exact declaration/statement identities.
2. Automate first-use worker and verifier provisioning, including the matching
   Lean/probe toolchain and dependency preparation. Lima should be the host
   infrastructure prerequisite, not a request to build VMs by hand.
3. Internalize run artifacts and remove Dalek-specific assumptions from the
   normal prepared-spec path. A hidden solved reference must not be a universal
   requirement for proving the user's supplied specs.
4. Support multiple selected roots and validate the complete workflow on another
   repository, not just the Dalek fixture.
5. Add an explicit internet-enabled experiment policy without weakening the
   restricted benchmark or independent verification.

These are implementation tasks, not features that a README update can make
available. The separate current proof blocker and outstanding regression-test
issues are described in the [implementation reference](autofv/README.md).

## Repository contents

`autofv/` contains the controller; `tests/` contains its contracts and fixtures;
`docker/autofv/` pins the runtime. The Lean/Rust files at this repository's root
are a [Dalek benchmark snapshot](docs/DALEK-BENCHMARK.md), not the required layout
for every future target. The older `harness/` tools are research code, not a
substitute for the sealed CLI.

See the [documentation index](docs/README.md) for design history and experiment
methodology. Older Dalek preparation documents describe the development
benchmark; they are not the intended general-purpose user interface.
