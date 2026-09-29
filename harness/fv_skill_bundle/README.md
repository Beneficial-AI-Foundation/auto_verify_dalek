# FVS for the headless to_bytes experiment

Run the existing baseline with `bash harness/run_to_bytes_b.sh`.
Enable this skill with `bash harness/run_to_bytes_b.sh --fv-skills`.
Preview without calling a model with
`python3 harness/prove_to_bytes_b.py --fv-skills`.

Only `fv-harness:lean-verify` is installed into a fresh run's Claude configuration
and loaded by `--plugin-dir`. Its instructions and reference files are mounted
read-only. Account skill sync and bundled skills are disabled. The existing
toolset gains only Skill permissions for this command; no agents, MCP servers,
hooks, or network tools are added. Project `.claude` and `.agents` directories
are hidden in the sandbox for this mode.

This is a **local headless adaptation**, not the unmodified upstream command.
Upstream lean-verify requires interactive model selection, researcher/executor
subagents, user compilation feedback, cache downloads, and project memory. This
adapter instead uses the existing model and session, direct sequential builds,
conversation-only notes, and the unchanged harness gates. It does not implement
the upstream mechanical style checker. Reference tactic suggestions must be
checked against the project's pinned Aeneas version (`progress` versus `step`).

The three references are unmodified MIT-licensed files from
https://github.com/Beneficial-AI-Foundation/formal-verification-skills at the
commit in `upstream.json`. They include general Dalek examples, so enabling
them changes the experiment's supplied reference material. Compare results as
a separate treatment, not as the original B baseline.

`experiment.json` records the selected skill, upstream commit, adapter identity,
and SHA-256 of every bundle file. The run ledger's isolation record also stores
the effective settings hash. Raw transcripts retain the Skill calls and results.
Round provenance records whether the selected Skill call succeeded. A fresh
session that never loads it, or invokes a different skill, cannot be accepted.
No network installation occurs at experiment startup. Updating vendored
references requires explicitly updating their hashes in `upstream.json`.
