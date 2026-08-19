# Evaluation

A green Lean build is necessary, but it is not enough. The agents could weaken
a specification, add an axiom, move a `sorry`, or use an unwanted Lean feature.
The final checker must look for these cases.

## Starting count

[`.verilib/sorry_inventory.json`](../.verilib/sorry_inventory.json) records:

- 347 task `sorry`s: 318 in `Specs` and 29 auxiliary;
- 10 Math source locations treated separately;
- 36 intentional external specifications; and
- 17 declarations in the pinned Aeneas dependency.

For a full run, the 347 task declarations are the work to complete. Existing
Math, external, and dependency assumptions must be reported but are not counted
as work completed by the agents.

## Result levels

| Level | Meaning |
| --- | --- |
| L0 | The run and its inputs were fully recorded. |
| L1 | A clean whole-project build passed. |
| L2 | All declared task holes are closed. For `S2`, every target in `T` also has a specification and proof. |
| L3 | L2 passed with unchanged inputs, no new trusted assumptions, no forbidden shortcuts, and a fresh replay. |
| L4 | L3 plus evidence that generated specifications say the right thing. |
| L5 | Another fresh run reproduced the result, or the observed variation was reported. |

“Automatically formalised” requires L3. “Recovered missing specifications”
requires L4 because proving a weak or meaningless specification is not enough.

## Required checks

The verifier must reject a run if any of these checks fail:

1. **Clean build:** the full declared Lean target builds from clean source.
2. **Task completion:** required `sorry`s are gone and were not moved or hidden.
3. **Top-level completion:** every target in `T` has a specification and proof.
4. **Statement protection:** specifications in `S` are unchanged; accepted
   specifications in `W` do not change during proving.
5. **Trust check:** no new axioms, `sorryAx`, external declarations, or other
   trusted assumptions appear.
6. **Lean shortcut check:** no forbidden `unsafe`, `implemented_by`, `extern`,
   plugin, generated binary, or similar escape is added.
7. **Scope check:** only allowed files and declarations changed.
8. **Fresh replay:** the patch passes again without the agents' caches or
   workspace.

The policy for `native_decide` is still open. If it is allowed, every compiler
assumption it uses must be listed.

## Checking generated specifications

A generated specification may compile but still be useless. For each target in
`W`, check as many of the following as practical:

- compare it with the hidden reference and label it equivalent, stronger,
  weaker, or different;
- show that its preconditions can be satisfied and that it constrains the
  output;
- test whether it rejects simple broken versions of the implementation;
- search for small counterexamples; and
- ask an independent reviewer to judge it without seeing the reference proof.

If no reference exists, say so clearly. Do not claim equivalence.

## What to report

For every attempted run, record:

- exact `T`, `S`, and `W` sizes and IDs;
- number of supplied and recovered specifications proved;
- task `sorry` count before and after;
- outcome of every check above;
- any change to the trusted assumptions;
- model, prompts, attempts, retries, and stop reason;
- wall time, tokens, and cost; and
- fresh replay result.

Failed, timed-out, and rejected runs stay in the total. Do not publish only the
best attempt.

## Claims about small seeds

Models are not deterministic. More input can help, but it can also distract.
One success does not prove that a seed is reliable, and one failure does not
prove that it is impossible.

Before a campaign, choose how many repeated runs a seed must pass. Report the
smallest seed that met that rule and the search used to find it. Do not call it
the true minimum unless every smaller set was actually ruled out.
