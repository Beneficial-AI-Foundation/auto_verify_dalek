import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open curve25519_dalek

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

end curve25519_dalek.backend.serial.u64.scalar.Scalar52

namespace curve25519_dalek.backend.serial.u64.scalar.Scalar52

/-- One step of the little-endian byte packing: `o = acc ||| ((b as u64) << n)`. -/
theorem from_bytes_loop_or_step {acc w s o : U64} {b : U8} {n : Nat}
    (hw : w = UScalar.cast .U64 b) (hs : s.val = w.val <<< n % U64.size)
    (ho : o.val = (acc ||| s).val) (hacc : acc.val < 2 ^ n) (hn : n + 8 ≤ 64) :
    o.val = acc.val + 2 ^ n * b.val ∧ o.val < 2 ^ (n + 8) := by
  have hb : b.val < 2 ^ 8 := by scalar_tac
  have hwv : w.val = b.val := by
    rw [hw, UScalar.cast_val_eq]
    exact Nat.mod_eq_of_lt (by simp [UScalarTy.numBits]; omega)
  have hsz : U64.size = 2 ^ 64 := by simp [U64.size, U64.numBits]
  rw [ho, UScalar.val_or, hs, hwv, hsz, Nat.or_shiftLeft_mod_eq_add hacc hb hn]
  exact ⟨rfl, Nat.add_two_pow_mul_lt hacc hb⟩

/-- If the four 64-bit words are the little-endian packings of consecutive 8-byte chunks,
then their radix-`2^64` value is the little-endian value of the 32 bytes. -/
theorem from_bytes_loop_words_sum (bytes : Array U8 32#usize) (r : Array U64 4#usize)
    (h : ∀ j, j < 4 →
      (r.val[j]!).val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * j + k]!).val) :
    ∑ j ∈ Finset.range 4, 2 ^ (64 * j) * (r.val[j]!).val = U8x32_as_Nat bytes := by
  rw [Finset.sum_congr rfl (fun j hj => by rw [h j (Finset.mem_range.1 hj)])]
  unfold U8x32_as_Nat
  simp only [Finset.sum_range_succ, Finset.sum_range_zero, Array.getElem!_Nat_eq,
    Nat.reduceMul, Nat.reduceAdd]
  ring

/-- Combines the result of one loop iteration (word `i` written) with the result of the
recursive call (words `i+1..4`). -/
theorem from_bytes_loop_post (bytes : Array U8 32#usize) (words a r : Array U64 4#usize)
    (i i' : Nat) (o7 : U64) (hi' : i' = i + 1) (hai : a.val[i]! = o7)
    (hane : ∀ j, j ≠ i → a.val[j]! = words.val[j]!)
    (hword : o7.val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * i + k]!).val)
    (hr1 : ∀ j, j < i' → r.val[j]! = a.val[j]!)
    (hr2 : ∀ j, i' ≤ j → j < 4 →
      (r.val[j]!).val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * j + k]!).val) :
    (∀ j, j < i → r.val[j]! = words.val[j]!) ∧
    (∀ j, i ≤ j → j < 4 →
      (r.val[j]!).val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * j + k]!).val) ∧
    (i = 0 →
      ∑ j ∈ Finset.range 4, 2 ^ (64 * j) * (r.val[j]!).val = U8x32_as_Nat bytes) := by
  subst hi'
  have hall : ∀ j, i ≤ j → j < 4 →
      (r.val[j]!).val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * j + k]!).val := by
    intro j hj1 hj2
    by_cases hji : j = i
    · subst hji
      rw [hr1 j (by omega), hai, hword]
    · exact hr2 j (by omega) hj2
  refine ⟨?_, hall, ?_⟩
  · intro j hj
    rw [hr1 j (by omega), hane j (by omega)]
  · intro hi0
    exact from_bytes_loop_words_sum bytes r (fun j hj => hall j (by omega) hj)

/-- `from_bytes_loop bytes words i` fills the words `i..4` with the little-endian packing of
the corresponding 8-byte chunks of `bytes`, leaving words `< i` unchanged. Started at `i = 0`
the resulting words encode `U8x32_as_Nat bytes` in radix `2^64`. -/
@[progress]
theorem from_bytes_loop_spec (bytes : Array U8 32#usize) (words : Array U64 4#usize)
    (i : Usize) :
    from_bytes_loop bytes words i ⦃ r =>
      (∀ j, j < i.val → r.val[j]! = words.val[j]!) ∧
      (∀ j, i.val ≤ j → j < 4 →
        (r.val[j]!).val = ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * j + k]!).val) ∧
      (i.val = 0 →
        ∑ j ∈ Finset.range 4, 2 ^ (64 * j) * (r.val[j]!).val = U8x32_as_Nat bytes) ⦄ := by
  unfold from_bytes_loop
  split
  · have hilt : i.val < 4 := by scalar_tac
    progress as ⟨base, hbase⟩
    progress as ⟨b0, hb0⟩
    progress as ⟨w0, hw0⟩
    progress as ⟨i1, hi1⟩
    progress as ⟨b1, hb1⟩
    progress as ⟨w1, hw1⟩
    progress as ⟨s1, hs1⟩
    progress as ⟨o1, ho1⟩
    progress as ⟨i2, hi2⟩
    progress as ⟨b2, hb2⟩
    progress as ⟨w2, hw2⟩
    progress as ⟨s2, hs2⟩
    progress as ⟨o2, ho2⟩
    progress as ⟨i3, hi3⟩
    progress as ⟨b3, hb3⟩
    progress as ⟨w3, hw3⟩
    progress as ⟨s3, hs3⟩
    progress as ⟨o3, ho3⟩
    progress as ⟨i4, hi4⟩
    progress as ⟨b4, hb4⟩
    progress as ⟨w4, hw4⟩
    progress as ⟨s4, hs4⟩
    progress as ⟨o4, ho4⟩
    progress as ⟨i5, hi5⟩
    progress as ⟨b5, hb5⟩
    progress as ⟨w5, hw5⟩
    progress as ⟨s5, hs5⟩
    progress as ⟨o5, ho5⟩
    progress as ⟨i6, hi6⟩
    progress as ⟨b6, hb6⟩
    progress as ⟨w6, hw6⟩
    progress as ⟨s6, hs6⟩
    progress as ⟨o6, ho6⟩
    progress as ⟨i7, hi7⟩
    progress as ⟨b7, hb7⟩
    progress as ⟨w7, hw7⟩
    progress as ⟨s7, hs7⟩
    progress as ⟨o7, ho7⟩
    progress as ⟨a, ha⟩
    progress as ⟨i', hi'⟩
    have h0 : w0.val = b0.val ∧ w0.val < 2 ^ 8 := by
      have : w0.val = b0.val := by
        rw [hw0, UScalar.cast_val_eq]
        exact Nat.mod_eq_of_lt (by simp [UScalarTy.numBits]; scalar_tac)
      exact ⟨this, by scalar_tac⟩
    obtain ⟨e1, l1⟩ := from_bytes_loop_or_step (n := 8) hw1 hs1 ho1 h0.2 (by norm_num)
    obtain ⟨e2, l2⟩ := from_bytes_loop_or_step (n := 16) hw2 hs2 ho2 l1 (by norm_num)
    obtain ⟨e3, l3⟩ := from_bytes_loop_or_step (n := 24) hw3 hs3 ho3 l2 (by norm_num)
    obtain ⟨e4, l4⟩ := from_bytes_loop_or_step (n := 32) hw4 hs4 ho4 l3 (by norm_num)
    obtain ⟨e5, l5⟩ := from_bytes_loop_or_step (n := 40) hw5 hs5 ho5 l4 (by norm_num)
    obtain ⟨e6, l6⟩ := from_bytes_loop_or_step (n := 48) hw6 hs6 ho6 l5 (by norm_num)
    obtain ⟨e7, l7⟩ := from_bytes_loop_or_step (n := 56) hw7 hs7 ho7 l6 (by norm_num)
    have hk0 : b0.val = (bytes.val[8 * i.val + 0]!).val := by rw [hb0, hbase, Nat.mul_comm]; rfl
    have hk1 : b1.val = (bytes.val[8 * i.val + 1]!).val := by rw [hb1, hi1, hbase, Nat.mul_comm]
    have hk2 : b2.val = (bytes.val[8 * i.val + 2]!).val := by rw [hb2, hi2, hbase, Nat.mul_comm]
    have hk3 : b3.val = (bytes.val[8 * i.val + 3]!).val := by rw [hb3, hi3, hbase, Nat.mul_comm]
    have hk4 : b4.val = (bytes.val[8 * i.val + 4]!).val := by rw [hb4, hi4, hbase, Nat.mul_comm]
    have hk5 : b5.val = (bytes.val[8 * i.val + 5]!).val := by rw [hb5, hi5, hbase, Nat.mul_comm]
    have hk6 : b6.val = (bytes.val[8 * i.val + 6]!).val := by rw [hb6, hi6, hbase, Nat.mul_comm]
    have hk7 : b7.val = (bytes.val[8 * i.val + 7]!).val := by rw [hb7, hi7, hbase, Nat.mul_comm]
    have hword : o7.val =
        ∑ k ∈ Finset.range 8, 2 ^ (8 * k) * (bytes.val[8 * i.val + k]!).val := by
      simp only [Finset.sum_range_succ, Finset.sum_range_zero, ← hk0, ← hk1, ← hk2, ← hk3,
        ← hk4, ← hk5, ← hk6, ← hk7]
      rw [e7, e6, e5, e4, e3, e2, e1, h0.1]
      ring
    have hai : a.val[i.val]! = o7 := by
      rw [ha, Array.set_val_eq]; exact List.getElem!_set _ _ _ (by scalar_tac)
    have hane : ∀ j, j ≠ i.val → a.val[j]! = words.val[j]! := by
      intro j hj
      rw [ha, Array.set_val_eq]; exact List.getElem!_set_ne _ _ _ _ (by simp [Nat.not_eq]; omega)
    have hdec : 4 - i'.val < 4 - i.val := by omega
    progress as ⟨r, hr1, hr2, _⟩
    exact from_bytes_loop_post bytes words a r i.val i'.val o7 (by scalar_tac) hai hane hword hr1 hr2
  · rw [spec_ok]
    refine ⟨fun j _ => rfl, fun j h1 h2 => ?_, fun h => ?_⟩
    · scalar_tac
    · scalar_tac
termination_by 4 - i.val
decreasing_by
  all_goals (simp_wf; assumption)

end curve25519_dalek.backend.serial.u64.scalar.Scalar52
