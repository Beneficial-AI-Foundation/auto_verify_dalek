import Diamond.Left
import Diamond.Right

namespace Diamond

def top (input : Nat) : Nat :=
  left input + right input

theorem top_spec (input : Nat) :
    top input = input * 3 + 1 := by
  sorry

end Diamond
