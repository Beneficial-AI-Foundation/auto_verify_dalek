




import Lean









open Lean



initialize externallyVerifiedAttr : TagAttribute ←
  registerTagAttribute `externally_verified
    "Marks a theorem as externally verified (sorry is intentional)."
