
import Aeneas
open Aeneas.Std Result
namespace curve25519_dalek



axiom core.fmt.Arguments : Type




structure subtle.Choice where
  val : U8
  valid : val = 0#u8 ∨ val = 1#u8




structure subtle.CtOption (T : Type) where
  value : T
  is_some : subtle.Choice

end curve25519_dalek
