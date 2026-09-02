




import Lean






open Lean Elab Tactic Meta
















elab "expand " h:ident " with " n:num : tactic => do
  let n := n.getNat
  for i in [:n] do
    let newName := h.getId.appendAfter s!"_{i}"
    evalTactic (← `(tactic| have $(mkIdent newName) := $h $(quote i) (by omega)))
