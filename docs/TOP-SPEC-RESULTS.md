# Top-spec proving runs on `dalek-top-spec-only`

Results of `harness/prove_top_spec.py`: one top-level spec theorem of the
agent bundle per run, same agent loop and gates as `harness/driver.py`
(G2 skipped — the bundle has no trust-base manifests). Raw records:
`ledger/top_spec_rounds.jsonl`; transcripts `ledger/transcripts/topspec_*`.

## Bundle state (2026-09-16)

- 57 kept top spec theorems, all `sorry`; 144 sorry declarations in 67 files
  (includes stubs and Math assumptions).
- Math/ minimized to 128 of 447 declarations ([MINIMAL-MATH.md](MINIMAL-MATH.md)).
- Candidates ranked by dependency closure of the statement (in-package
  declarations, from the bundle probe). Smallest first:

| closure | Funs | Math | theorem |
|---|---|---|---|
| 2 | 1 | 0 | `backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq_spec` |
| 2 | 1 | 0 | `montgomery.MontgomeryPoint.as_bytes_spec` |
| 2 | 1 | 0 | `montgomery.MontgomeryPoint.to_bytes_spec` |
| 2 | 1 | 0 | `ristretto.CompressedRistretto.to_bytes_spec` |
| 3 | 1 | 1 | `montgomery.MontgomeryPoint.Insts.Curve25519_dalekTraitsIdentity.identity_spec` |
| 3 | 1 | 0 | `scalar.Scalar.to_bytes_spec` |
| 4 | 1 | 1 | `scalar.Scalar.Insts.CoreConvertFromU{8,16,32,64,128}.from_spec` (5) |
| 7 | 4 | 2 | `backend.serial.u64.field.FieldElement51.Insts.CoreOpsArithSubAssignSharedAFieldElement51.sub_assign_spec` |
| 8 | 4 | 3 | `backend.serial.u64.field.FieldElement51.as_bytes_spec` |

Full list: `python3 harness/prove_top_spec.py --list`.

## Runs

### 2026-09-16 — `assert_receiver_is_total_eq_spec` — accepted

Smoke test of the pipeline on the smallest target (function body is `ok ()`).

| | |
|---|---|
| model | claude-sonnet-5 (haiku-4-5 also billed, claude's internal use) |
| rounds / turns | 1 / 20 |
| wall | 77 s agent, 3.4 s gate build, 3.0 s G1 |
| cost | $0.24 |
| tokens | 4.7k output, 23k cache write, 505k cache read |
| gates | scope, forbidden-attr, build, G1 statement identity, sorry count: all pass; G2 skipped |
| run dir | `ledger/runs/topspec_2026-09-16T015613+0000` |

Proof accepted and copied into the bundle:

```lean
theorem assert_receiver_is_total_eq_spec
    (self : backend.serial.curve_models.AffineNielsPoint) :
    assert_receiver_is_total_eq self ⦃ result => result = () ⦄ := by
  unfold assert_receiver_is_total_eq
  simp [Aeneas.Std.WP.spec, Aeneas.Std.WP.theta, Aeneas.Std.WP.wp_return]
```

An earlier attempt the same day (run dir `topspec_2026-09-16T015419+0000`,
$0.18, proof `simp [assert_receiver_is_total_eq]`) was rejected by the scope
gate for a harness bug, not an agent fault: the bundle ships no
`.gitignore`, so the slot's sealed baseline tracked `.lake/build` and the
rebuilt `.olean` counted as an out-of-scope edit; the rollback then crashed
decoding the binary. Fixed by writing `.gitignore` (`.lake/`) into the slot
before sealing. No ledger record for that attempt.

## Next

First non-trivial experiment: `scalar.Scalar.to_bytes_spec` (closure 3,
structure eta) or `FieldElement51 ... sub_assign_spec` (closure 7, first
with limb arithmetic and Math lemmas).
