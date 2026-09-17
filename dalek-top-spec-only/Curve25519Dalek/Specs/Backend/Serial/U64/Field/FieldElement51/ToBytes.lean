/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Curve25519Dalek.Tactics
import Curve25519Dalek.ExternallyVerified

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

def bytes_match_limbs (L : Array U64 5#usize) (s : Array U8 32#usize) : Prop :=

  s.val[0]!.val = L.val[0]!.val % 2^8 ∧
  s.val[1]!.val = L.val[0]!.val >>> 8 % 2^8 ∧
  s.val[2]!.val = L.val[0]!.val >>> 16 % 2^8 ∧
  s.val[3]!.val = L.val[0]!.val >>> 24 % 2^8 ∧
  s.val[4]!.val = L.val[0]!.val >>> 32 % 2^8 ∧
  s.val[5]!.val = L.val[0]!.val >>> 40 % 2^8 ∧
  s.val[6]!.val = (L.val[0]!.val >>> 48 ||| L.val[1]!.val <<< 3 % U64.size) % 2^8 ∧

  s.val[7]!.val = L.val[1]!.val >>> 5 % 2^8 ∧
  s.val[8]!.val = L.val[1]!.val >>> 13 % 2^8 ∧
  s.val[9]!.val = L.val[1]!.val >>> 21 % 2^8 ∧
  s.val[10]!.val = L.val[1]!.val >>> 29 % 2^8 ∧
  s.val[11]!.val = L.val[1]!.val >>> 37 % 2^8 ∧
  s.val[12]!.val = (L.val[1]!.val >>> 45 ||| L.val[2]!.val <<< 6 % U64.size) % 2^8 ∧

  s.val[13]!.val = L.val[2]!.val >>> 2 % 2^8 ∧
  s.val[14]!.val = L.val[2]!.val >>> 10 % 2^8 ∧
  s.val[15]!.val = L.val[2]!.val >>> 18 % 2^8 ∧
  s.val[16]!.val = L.val[2]!.val >>> 26 % 2^8 ∧
  s.val[17]!.val = L.val[2]!.val >>> 34 % 2^8 ∧
  s.val[18]!.val = L.val[2]!.val >>> 42 % 2^8 ∧
  s.val[19]!.val = (L.val[2]!.val >>> 50 ||| L.val[3]!.val <<< 1 % U64.size) % 2^8 ∧

  s.val[20]!.val = L.val[3]!.val >>> 7 % 2^8 ∧
  s.val[21]!.val = L.val[3]!.val >>> 15 % 2^8 ∧
  s.val[22]!.val = L.val[3]!.val >>> 23 % 2^8 ∧
  s.val[23]!.val = L.val[3]!.val >>> 31 % 2^8 ∧
  s.val[24]!.val = L.val[3]!.val >>> 39 % 2^8 ∧
  s.val[25]!.val = (L.val[3]!.val >>> 47 ||| L.val[4]!.val <<< 4 % U64.size) % 2^8 ∧

  s.val[26]!.val = L.val[4]!.val >>> 4 % 2^8 ∧
  s.val[27]!.val = L.val[4]!.val >>> 12 % 2^8 ∧
  s.val[28]!.val = L.val[4]!.val >>> 20 % 2^8 ∧
  s.val[29]!.val = L.val[4]!.val >>> 28 % 2^8 ∧
  s.val[30]!.val = L.val[4]!.val >>> 36 % 2^8 ∧
  s.val[31]!.val = L.val[4]!.val >>> 44 % 2^8

end curve25519_dalek.backend.serial.u64.field.FieldElement51
