




import Curve25519Dalek.Math.Edwards.Curve
set_option linter.style.nativeDecide false












namespace Edwards

def basepoint : Point Ed25519 where
  x := 15112221349535400772501151409588531511454012693041857206046113283949847762202
  y := 46316835694926478169428394003475163141307993866256225615783033603165251855960
  on_curve := by decide




theorem basepoint_order_L : L • basepoint = 0 := by
  rw [← binary_nsmul_Ed25519_eq L basepoint]
  native_decide

theorem basepoint_ne_zero : basepoint ≠ 0 := by decide

theorem four_nsmul_basepoint_ne_zero : 4 • basepoint ≠ 0 := by native_decide

end Edwards
