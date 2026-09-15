/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Math.Edwards.Curve
set_option linter.style.nativeDecide false

namespace Edwards

def basepoint : Point Ed25519 where
  x := 15112221349535400772501151409588531511454012693041857206046113283949847762202
  y := 46316835694926478169428394003475163141307993866256225615783033603165251855960
  on_curve := by decide

end Edwards
