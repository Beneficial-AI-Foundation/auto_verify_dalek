---
name: lean-verify
description: Prove an existing Aeneas Lean specification using pinned FVS tactics and proof strategies in the isolated harness.
argument-hint: "<spec-file-path>"
---

This is the local, headless adaptation of FVS lean-verify, not its interactive
researcher/executor workflow. Use the current model and session. The harness
supplies the target, editable file list, frozen statement and time budget.

1. Read the target in $ARGUMENTS and its existing verified dependencies.
2. Read these bundled references using Read, starting with their quick-reference
   sections, then the sections relevant to the current goal:
   - ${CLAUDE_PLUGIN_ROOT}/skills/lean-verify/references/tactic-usage.md
   - ${CLAUDE_PLUGIN_ROOT}/skills/lean-verify/references/proof-strategies.md
   - ${CLAUDE_PLUGIN_ROOT}/skills/lean-verify/references/lean-spec-conventions.md
   They are upstream reference material, not permission to change the harness
   contract. Check tactic availability in this project's pinned Aeneas version;
   preserve its existing `@[progress]` conventions when `step` is unavailable.
3. Identify the current goal and choose a short proof plan. Work on one goal at
   a time. Prove small helper lemmas in the allowed file and compile each before
   using it. Preserve theorem names, statements, imports required by the target,
   generated functions, toolchain and dependencies.
4. Apply Aeneas forward reasoning, simplify scalar/array expressions, and choose
   automation appropriate to the goal. Before expensive automation, isolate the
   necessary hypotheses in a helper lemma. If compilation stalls or exhausts
   resources, split the proof or reduce the context; do not raise resource limits.
5. Run `lake build <target-module>` after each small edit and inspect diagnostics.
   Run builds sequentially; do not leave background builds competing. Replace
   upstream requests for human compilation feedback with your own build results.
6. Finish with `lake build`. Report VERIFIED only after a successful build and
   no remaining target or helper `sorry`; otherwise report STUCK with the exact
   remaining goal and latest diagnostic. The harness decides final acceptance.

This adapter does not dispatch subagents, select other models, install packages,
download caches, invoke MCP servers, or write `.formalising/` memory. Keep notes
in the conversation. Use only the tools and editable paths provided by the
harness. Do not regenerate or weaken the target specification. Do not copy
unverified reference examples as though they had passed this project's build.
