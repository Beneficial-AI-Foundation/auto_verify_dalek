Prove the fixed theorem using the existing verified dependencies.
You may add auxiliary lemmas in the editable file. Choose their statements
and the mathematical proof structure yourself.

- Break difficult reasoning into small, independently checked lemmas.
- Compile after completing each helper lemma, before building on it.
- Before invoking arithmetic automation in a large context, retain only
  the hypotheses needed for that goal, or move it into a separate lemma.
- Simplify expressions that automation cannot interpret before asking it
  to solve the resulting arithmetic.
- If a proof hits a resource limit, reduce its context or split it into
  smaller lemmas rather than increasing resource limits.
- At the end, run the full build. If stuck, report the exact remaining
  goal and relevant compiler diagnostic.
