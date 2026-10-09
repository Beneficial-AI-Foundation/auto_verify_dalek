You are proving a Lean 4 specification bottom-up.

Top-level target: {TOP_SPEC} in {FILE}.

Procedure:
1. Read the top-level spec. List every spec/lemma it depends on (helper
   specs, lemmas about called functions, Aux definitions). Build the
   dependency tree down to leaves that depend only on verified lemmas or
   definitions.
2. Prove bottom-up: start at the leaves, then move one level up each time.
   Never touch a spec whose dependencies are not yet all proved.
3. After each spec compiles with no `sorry`, run `lake build` on the file
   and confirm the sorry count dropped by exactly the specs you proved.
4. When a spec at level N cannot be proved, STOP and diagnose before
   retrying:
   - Is the spec at level N itself false? Check with a concrete
     counterexample (`decide`, `#eval`, or small `native_decide` scratch
     that you delete afterwards). If false, fix the statement.
   - Is some dependency at level < N too weak? Typical signs: you need a
     bound, equality, or invariant that the lower spec's conclusion does
     not give you, even though the lower function does guarantee it.
     If so, STRENGTHEN the lower spec: tighten its postcondition (or add
     a needed hypothesis), re-prove it, then return to level N.
   - Only if neither applies, retry the proof of level N with a different
     strategy.
5. Every time you change a spec statement, re-check that every spec that
   already used it still compiles. Fix those first before moving on.
6. Repeat until the top-level spec is proved.

Constraints:
- Do not add axioms, `@[implemented_by]`, `@[extern]`, or `native_decide`
  in final code.
- Do not weaken the top-level spec. Weakening is allowed only for
  intermediate specs if the stronger form is genuinely false; say so
  explicitly when you do it.
- Edit only {FILE} (and {AUX_FILE} if a helper spec must change).

Report at the end: the dependency tree, which specs were strengthened and
why, and the final sorry count.
```

## Notes

- Step 4 forces diagnosis (spec false vs. dependency too weak) before a
  blind retry.
- Step 5 guards against a strengthened lower spec breaking already-proved
  upper specs.
