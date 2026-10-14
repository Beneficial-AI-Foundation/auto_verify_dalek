# Validation record

Date: 2026-10-14. Base: `946bd3c73e2a417e3a2f432b9e0faa59511d062e`.
Environment: isolated cloud checkout, Node v24.19.0, Python 3.12.14.

## Passed

- `node --test test/*.test.mjs`: 33 synthetic boundary tests.
- `node qualify.mjs`: offline report identifies unapproved profile, unverified
  entitlement/isolation/callback lifecycle, unsupported server output cap,
  unknown cost/cancellation, and missing installed SDKs.
- `node --check bridge.mjs` and `node --check test-sdk/integration.test.mjs`.
- Exact equality of `tool-schemas.json` with the five schemas in the unchanged
  `autofv.agent_lane._TOOL_SCHEMAS`.
- `python3 -m unittest -q tests.test_archive_boundaries
  tests.test_image_contract.ControlBundleBoundaryTests
  tests.test_image_contract.ContentDriftTests`: 24 tests.

## Blocked / not passed

- Real Pi SDK suite: written but **not executed**. Installation approval is
  pending; no Pi packages or new software were installed. Source/API inspection
  is not a substitute for executing the real-SDK tests.
- The README fast Python contract suite cannot import `langgraph`, which is not
  installed in this cloud environment. A broader check also encountered missing
  `deepagents` and unavailable Docker/sudo runtime smoke prerequisites.
- The unchanged base's `test_fvs_context_keeps_complete_sources_without_raising_legacy_bound`
  expects 8192 review tokens while the base profile declares 16384. This existing
  mismatch was observed, not changed as part of the separate SDK spike.
- No TypeScript compiler/static full-`Models` conformance claim. This JavaScript
  facade denies all SDK operations except the selected runtime seam.
- No OAuth sign-in, real credential inspection, provider request, scored run,
  VM provisioning, isolation probe, Lean proof, clean-verifier acceptance, or
  end-to-end `autofv` CLI integration was performed.

## Evidence interpretation

Synthetic credentials, model outputs, usage and approvals are test fixtures.
They do not prove subscription entitlement, remote cancellation, OS isolation,
billed cost or useful-pair success. SDK cost estimates are never promoted to
subscription billing receipts. The current API/FVS route remains unchanged.
