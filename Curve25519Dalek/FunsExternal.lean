
import Aeneas
import Curve25519Dalek.Types

set_option linter.style.whitespace false

open Aeneas Aeneas.Std Aeneas.Std.WP Result

namespace curve25519_dalek




@[rust_fun "core::result::{core::result::Result<@T, @E>}::map"]
def core.result.Result.map
  {T : Type} {E : Type} {U : Type} {F : Type} (opsfunctionFnOnceFTupleTUInst :
  core.ops.function.FnOnce F T U) :
  core.result.Result T E → F → Result (core.result.Result U E) :=
  fun r f => match r with
    | .Ok t => do let u ← opsfunctionFnOnceFTupleTUInst.call_once f t; ok (.Ok u)
    | .Err e => ok (.Err e)




@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::index_mut"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_mut
  {T : Type} :
  core.ops.range.RangeFull → Slice T → Result ((Slice T) × (Slice T →
    Slice T)) :=
  fun _ s => ok (s, id)


@[simp, progress]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_mut_spec
  {T : Type} (s : Slice T) :
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_mut () s ⦃ p =>
    p.1 = s ∧ p.2 = id ⦄ := by
  sorry



@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::index"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index
  {T : Type} : core.ops.range.RangeFull → Slice T → Result (Slice T) :=
  fun _ s => ok s


@[simp]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_spec
  {T : Type} (s : Slice T) :
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index () s = ok s := by
  sorry



@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_unchecked_mut"]
axiom
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut
  {T : Type} :
  core.ops.range.RangeFull → MutRawPtr (Slice T) → Result (MutRawPtr (Slice
    T))




@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_unchecked"]
axiom
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked
  {T : Type} :
  core.ops.range.RangeFull → ConstRawPtr (Slice T) → Result (ConstRawPtr
    (Slice T))




@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_mut"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_mut
  {T : Type} :
  core.ops.range.RangeFull → Slice T → Result ((Option (Slice T)) ×
    (Option (Slice T) → Slice T)) :=
  fun _ s => ok (some s, fun opt => opt.getD s)


@[simp, progress]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_mut_spec
  {T : Type} (s : Slice T) :
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_mut () s ⦃ p =>
    p.1 = some s ∧ (∀ opt, p.2 opt = opt.getD s) ⦄ := by
  sorry



@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get
  {T : Type} :
  core.ops.range.RangeFull → Slice T → Result (Option (Slice T)) :=
  fun _ s => ok (some s)


@[simp, progress]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec
  {T : Type} (s : Slice T) :
  core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get () s ⦃ opt =>
    opt = some s ⦄ := by
  sorry

def Choice.zero : subtle.Choice := { val := 0#u8, valid := Or.inl rfl }
def Choice.one : subtle.Choice := { val := 1#u8, valid := Or.inr rfl }



instance : DecidableEq subtle.Choice := fun a b =>
  if h : a.val = b.val then isTrue (by cases a; cases b; simp_all)
  else isFalse (by intro heq; apply h; rw [heq])



theorem Choice.val_eq_zero_or_one (c : subtle.Choice) : c.val = 0#u8 ∨ c.val = 1#u8 := by
  sorry

theorem Choice.eq_zero_or_one (c : subtle.Choice) : c = Choice.zero ∨ c = Choice.one := by
  sorry
@[simp] theorem Choice.one_ne_zero : Choice.one ≠ Choice.zero := by decide
@[simp] theorem Choice.zero_ne_one : Choice.zero ≠ Choice.one := by decide

@[simp] theorem Choice.ne_one_iff (c : subtle.Choice) : c ≠ Choice.one ↔ c = Choice.zero := by
  cases Choice.eq_zero_or_one c with
  | inl h => simp [h]
  | inr h => simp [h]

@[simp] theorem Choice.ne_zero_iff (c : subtle.Choice) : c ≠ Choice.zero ↔ c = Choice.one := by
  cases Choice.eq_zero_or_one c with
  | inl h => simp [h]
  | inr h => simp [h]

theorem Choice.eq_zero_of_val (c : subtle.Choice) (h : c.val = 0#u8) : c = Choice.zero := by
  sorry
theorem Choice.eq_one_of_val (c : subtle.Choice) (h : c.val = 1#u8) : c = Choice.one := by
  sorry

lemma Choice.val_eq_one_iff (c : subtle.Choice) :
    c.val = 1#u8 ↔ c = Choice.one := by
  sorry



def subtle.Choice.unwrap_u8 (c : subtle.Choice) : Result U8 :=
  ok c.val





@[rust_fun "subtle::{core::convert::From<bool, subtle::Choice>}::from"]
def Bool.Insts.CoreConvertFromChoice.from (c : subtle.Choice) : Result Bool :=
  ok (c.val = 1#u8)




@[rust_fun
  "subtle::{core::ops::bit::BitAnd<subtle::Choice, subtle::Choice, subtle::Choice>}::bitand"]
def subtle.Choice.Insts.CoreOpsBitBitAndChoiceChoice.bitand
  (a : subtle.Choice) (b : subtle.Choice) : Result subtle.Choice :=
  if a.val = 0#u8 ∨ b.val = 0#u8 then
    ok Choice.zero
  else
    ok Choice.one





@[progress]
theorem subtle.Choice.Insts.CoreOpsBitBitAndChoiceChoice.bitand_spec (a b : subtle.Choice) :
    subtle.Choice.Insts.CoreOpsBitBitAndChoiceChoice.bitand a b ⦃ c =>
    (c = Choice.one ↔ a = Choice.one ∧ b = Choice.one) ⦄ := by
  sorry




@[rust_fun
  "subtle::{core::ops::bit::BitOr<subtle::Choice, subtle::Choice, subtle::Choice>}::bitor"]
def subtle.Choice.Insts.CoreOpsBitBitOrChoiceChoice.bitor (a : subtle.Choice) (b : subtle.Choice) :
    Result subtle.Choice :=
  if a.val = 1#u8 ∨ b.val = 1#u8 then
    ok Choice.one
  else
    ok Choice.zero






@[rust_fun
  "subtle::{core::ops::bit::Not<subtle::Choice, subtle::Choice>}::not"]
def subtle.Choice.Insts.CoreOpsBitNotChoice.not (c : subtle.Choice) : Result subtle.Choice :=
  if c.val = 1#u8 then
    ok Choice.zero
  else
    ok Choice.one


@[progress]
theorem subtle.Choice.Insts.CoreOpsBitNotChoice.not_spec (a : subtle.Choice) :
  subtle.Choice.Insts.CoreOpsBitNotChoice.not a ⦃ b =>
  (a.val = 1#u8 ↔ b = Choice.zero) ⦄ := by
  sorry




@[rust_fun "subtle::{subtle::ConstantTimeEq<u16>}::ct_eq"]
def U16.Insts.SubtleConstantTimeEq.ct_eq (a : U16) (b : U16) : Result subtle.Choice :=
  if a = b then ok Choice.one
  else ok Choice.zero





@[progress]
theorem U16.Insts.SubtleConstantTimeEq.ct_eq_spec (a b : U16) :
  U16.Insts.SubtleConstantTimeEq.ct_eq a b ⦃ c =>
  (c = Choice.one ↔ a = b) ⦄ := by
  sorry




@[rust_fun "subtle::{core::convert::From<subtle::Choice, u8>}::from"]
def subtle.Choice.Insts.CoreConvertFromU8.from (input : U8) : Result subtle.Choice :=
  if h : input = 0#u8 then
    ok { val := input, valid := Or.inl h }
  else if h' : input = 1#u8 then
    ok { val := input, valid := Or.inr h' }
  else
    fail Error.panic




@[rust_fun "subtle::{subtle::ConstantTimeEq<[@T]>}::ct_eq"]
axiom Slice.Insts.SubtleConstantTimeEq.ct_eq
  {T : Type} (ConstantTimeEqInst : subtle.ConstantTimeEq T)
  : Slice T → Slice T → Result subtle.Choice






@[progress]
axiom Slice.Insts.SubtleConstantTimeEq.ct_eq_spec
  {T : Type} (ConstantTimeEqInst : subtle.ConstantTimeEq T) (a b : Slice T)
  (ha : a.length < 2 ^ UScalarTy.Usize.numBits)
  (hb : b.length < 2 ^ UScalarTy.Usize.numBits)
  (h_eq_len : a.length = b.length) :
  Slice.Insts.SubtleConstantTimeEq.ct_eq ConstantTimeEqInst a b ⦃ c =>
  (c = Choice.one ↔ a = b) ⦄




@[rust_fun "subtle::{subtle::ConstantTimeEq<u8>}::ct_eq"]
def U8.Insts.SubtleConstantTimeEq.ct_eq (a : U8) (b : U8) : Result subtle.Choice :=
  if a = b then ok Choice.one
  else ok Choice.zero





@[progress]
theorem U8.Insts.SubtleConstantTimeEq.ct_eq_spec (a b : U8) :
  U8.Insts.SubtleConstantTimeEq.ct_eq a b ⦃ c =>
  (c = Choice.one ↔ a = b) ⦄ := by
  sorry




@[rust_fun "subtle::ConditionallySelectable::conditional_assign"]
def subtle.ConditionallySelectable.conditional_assign.default
  {Self : Type} (ConditionallySelectableInst : subtle.ConditionallySelectable
  Self) :
  Self → Self → subtle.Choice → Result Self :=
  fun a b choice =>
    ConditionallySelectableInst.conditional_select a b choice





@[progress]
theorem subtle.ConditionallySelectable.conditional_assign.default_spec
  {Self : Type} (ConditionallySelectableInst : subtle.ConditionallySelectable Self)
  (a b : Self) (choice : subtle.Choice)
  (h : ∃ res, ConditionallySelectableInst.conditional_select a b choice = ok res) :
  subtle.ConditionallySelectable.conditional_assign.default ConditionallySelectableInst a b choice ⦃ res =>
  ConditionallySelectableInst.conditional_select a b choice = ok res ⦄ := by
  sorry




@[rust_fun "subtle::ConditionallySelectable::conditional_swap"]
def subtle.ConditionallySelectable.conditional_swap.default
  {Self : Type} (ConditionallySelectableInst : subtle.ConditionallySelectable
  Self) :
  Self → Self → subtle.Choice → Result (Self × Self) :=
  fun a b choice => do
    let a_new ← ConditionallySelectableInst.conditional_select a b choice
    let b_new ← ConditionallySelectableInst.conditional_select b a choice
    ok (a_new, b_new)









@[progress]
theorem subtle.ConditionallySelectable.conditional_swap.default_spec
  {Self : Type} (ConditionallySelectableInst : subtle.ConditionallySelectable Self)
  (a b : Self) (choice : subtle.Choice)
  (h_a : ∃ res, ConditionallySelectableInst.conditional_select a b choice = ok res)
  (h_b : ∃ res, ConditionallySelectableInst.conditional_select b a choice = ok res) :
  subtle.ConditionallySelectable.conditional_swap.default ConditionallySelectableInst a b choice ⦃ c =>
    ConditionallySelectableInst.conditional_select a b choice = ok c.1 ∧
    ConditionallySelectableInst.conditional_select b a choice = ok c.2 ⦄ := by
  sorry




@[rust_fun
  "subtle::{subtle::ConditionallySelectable<u64>}::conditional_select"]
def U64.Insts.SubtleConditionallySelectable.conditional_select
  (a : U64) (b : U64) (choice : subtle.Choice) : Result U64 :=
  if choice.val = 1#u8 then ok b
  else ok a


@[progress]
theorem U64.Insts.SubtleConditionallySelectable.conditional_select_spec (a b : U64) (choice : subtle.Choice) :
    U64.Insts.SubtleConditionallySelectable.conditional_select a b choice ⦃ res =>
    res = if choice.val = 1#u8 then b else a ⦄ := by
  sorry




@[rust_fun
  "subtle::{subtle::ConditionallySelectable<u64>}::conditional_assign"]
def U64.Insts.SubtleConditionallySelectable.conditional_assign
  (a : U64) (b : U64) (choice : subtle.Choice) : Result U64 :=
  U64.Insts.SubtleConditionallySelectable.conditional_select a b choice





@[rust_fun "subtle::{subtle::ConditionallySelectable<u64>}::conditional_swap"]
def U64.Insts.SubtleConditionallySelectable.conditional_swap
  (a : U64) (b : U64) (choice : subtle.Choice) : Result (U64 × U64) := do
  let a_new ← U64.Insts.SubtleConditionallySelectable.conditional_select a b choice
  let b_new ← U64.Insts.SubtleConditionallySelectable.conditional_select b a choice
  ok (a_new, b_new)




def subtle.ConditionallyNegatable.Blanket.conditional_negate
  {T : Type} (ConditionallySelectableInst : subtle.ConditionallySelectable T)
  (coreopsarithNeg_TTInst : core.ops.arith.Neg T T)
  (self : T) (choice : subtle.Choice) : Result T := do
  let self_neg ← coreopsarithNeg_TTInst.neg self
  ConditionallySelectableInst.conditional_select self self_neg choice




@[rust_fun "subtle::{subtle::CtOption<@T>}::new"]
def subtle.CtOption.new
  {T : Type} (value : T) (is_some : subtle.Choice) : Result (subtle.CtOption T) :=
  ok { value := value, is_some := is_some }






@[progress]
theorem subtle.CtOption.new_spec {T : Type} (value : T) (is_some : subtle.Choice) :
  subtle.CtOption.new value is_some ⦃ opt =>
  opt.value = value ∧ opt.is_some = is_some ⦄ := by
  sorry








@[rust_fun "zeroize::{zeroize::Zeroize<@Z>}::zeroize"]
def zeroize.Zeroize.Blanket.zeroize
  {Z : Type} (DefaultIsZeroesInst : zeroize.DefaultIsZeroes Z) : Z → Result Z :=
  fun _ => DefaultIsZeroesInst.coredefaultDefaultInst.default




@[rust_fun "zeroize::{zeroize::Zeroize<[@Z; @N]>}::zeroize"]
axiom Array.Insts.ZeroizeZeroize.zeroize
  {Z : Type} {N : Usize} (ZeroizeInst : zeroize.Zeroize Z) :
  Array Z N → Result (Array Z N)





@[rust_fun "subtle::{subtle::ConditionallySelectable<u8>}::conditional_select"]
def U8.Insts.SubtleConditionallySelectable.conditional_select
  (a : U8) (b : U8) (choice : subtle.Choice) : Result U8 :=
  if choice.val = 1#u8 then ok b
  else ok a


@[progress]
theorem U8.Insts.SubtleConditionallySelectable.conditional_select_spec (a b : U8) (choice : subtle.Choice) :
    U8.Insts.SubtleConditionallySelectable.conditional_select a b choice ⦃ res =>
    res = if choice.val = 1#u8 then b else a ⦄ := by
  sorry




@[rust_fun "subtle::{subtle::ConditionallySelectable<u8>}::conditional_assign"]
def U8.Insts.SubtleConditionallySelectable.conditional_assign
  (a : U8) (b : U8) (choice : subtle.Choice) : Result U8 :=
  U8.Insts.SubtleConditionallySelectable.conditional_select a b choice





@[rust_fun "subtle::{subtle::ConditionallySelectable<u8>}::conditional_swap"]
def U8.Insts.SubtleConditionallySelectable.conditional_swap
  (a : U8) (b : U8) (choice : subtle.Choice) : Result (U8 × U8) := do
  let a_new ← U8.Insts.SubtleConditionallySelectable.conditional_select a b choice
  let b_new ← U8.Insts.SubtleConditionallySelectable.conditional_select b a choice
  ok (a_new, b_new)




@[rust_fun "zeroize::{zeroize::Zeroize<alloc::vec::Vec<@Z>>}::zeroize"]
axiom alloc.vec.Vec.Insts.ZeroizeZeroize.zeroize
  {Z : Type} (ZeroizeInst : zeroize.Zeroize Z) :
  alloc.vec.Vec Z → Result (alloc.vec.Vec Z)



axiom backend.serial.curve_models.AffineNielsPoint.Insts.CoreCmpPartialEqAffineNielsPoint.ne
  :
  backend.serial.curve_models.AffineNielsPoint →
    backend.serial.curve_models.AffineNielsPoint → Result Bool



axiom backend.serial.u64.field.FieldElement51.Insts.CoreCmpPartialEqFieldElement51.ne
  :
  backend.serial.u64.field.FieldElement51 →
    backend.serial.u64.field.FieldElement51 → Result Bool



axiom
  backend.serial.u64.field.FieldElement51.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : backend.serial.u64.field.FieldElement51 → Result Unit



axiom scalar.Scalar.Insts.CoreCmpPartialEqScalar.ne
  : scalar.Scalar → scalar.Scalar → Result Bool



axiom scalar.Scalar.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : scalar.Scalar → Result Unit





@[rust_fun
  "subtle::{subtle::ConditionallySelectable<[@T; @N]>}::conditional_select"]
def Array.Insts.SubtleConditionallySelectable.conditional_select
  {T : Type} {N : Usize} (_ConditionallySelectableInst :
  subtle.ConditionallySelectable T)
  (a : Array T N) (b : Array T N) (choice : subtle.Choice) : Result (Array T N) :=
  if choice.val = 1#u8 then ok b
  else ok a


@[progress]
theorem Array.Insts.SubtleConditionallySelectable.conditional_select_spec {T : Type} {N : Usize}
    (inst : subtle.ConditionallySelectable T)
    (a b : Array T N) (choice : subtle.Choice) :
    Array.Insts.SubtleConditionallySelectable.conditional_select inst a b choice ⦃ res =>
    res = if choice.val = 1#u8 then b else a ⦄ := by
  sorry




@[rust_fun
  "subtle::{subtle::ConditionallySelectable<[@T; @N]>}::conditional_assign"]
def Array.Insts.SubtleConditionallySelectable.conditional_assign
  {T : Type} {N : Usize} (ConditionallySelectableInst :
  subtle.ConditionallySelectable T)
  (a : Array T N) (b : Array T N) (choice : subtle.Choice) : Result (Array T N) :=
  Array.Insts.SubtleConditionallySelectable.conditional_select ConditionallySelectableInst a b choice





@[rust_fun
  "subtle::{subtle::ConditionallySelectable<[@T; @N]>}::conditional_swap"]
def Array.Insts.SubtleConditionallySelectable.conditional_swap
  {T : Type} {N : Usize} (ConditionallySelectableInst :
  subtle.ConditionallySelectable T)
  (a : Array T N) (b : Array T N) (choice : subtle.Choice) : Result ((Array T N) × (Array T N)) := do
  let a_new ← Array.Insts.SubtleConditionallySelectable.conditional_select ConditionallySelectableInst a b choice
  let b_new ← Array.Insts.SubtleConditionallySelectable.conditional_select ConditionallySelectableInst b a choice
  ok (a_new, b_new)




private def
  backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
  (a : backend.serial.u64.field.FieldElement51)
  (b : backend.serial.u64.field.FieldElement51) (choice : subtle.Choice) :
  Result backend.serial.u64.field.FieldElement51
  := do
  let i ← Array.index_usize a 0#usize
  let i1 ← Array.index_usize b 0#usize
  let i2 ← U64.Insts.SubtleConditionallySelectable.conditional_select i i1 choice
  let i3 ← Array.index_usize a 1#usize
  let i4 ← Array.index_usize b 1#usize
  let i5 ← U64.Insts.SubtleConditionallySelectable.conditional_select i3 i4 choice
  let i6 ← Array.index_usize a 2#usize
  let i7 ← Array.index_usize b 2#usize
  let i8 ← U64.Insts.SubtleConditionallySelectable.conditional_select i6 i7 choice
  let i9 ← Array.index_usize a 3#usize
  let i10 ← Array.index_usize b 3#usize
  let i11 ←
    U64.Insts.SubtleConditionallySelectable.conditional_select i9 i10 choice
  let i12 ← Array.index_usize a 4#usize
  let i13 ← Array.index_usize b 4#usize
  let i14 ←
    U64.Insts.SubtleConditionallySelectable.conditional_select i12 i13 choice
  ok (Array.make 5#usize [ i2, i5, i8, i11, i14 ])




private def montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a : montgomery.ProjectivePoint) (b : montgomery.ProjectivePoint)
  (choice : subtle.Choice) :
  Result montgomery.ProjectivePoint
  := do
  let fe ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.U b.U choice
  let fe1 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.W b.W choice
  ok { U := fe, W := fe1 }



private def
  backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a b : backend.serial.curve_models.ProjectiveNielsPoint)
  (choice : subtle.Choice) :
  Result backend.serial.curve_models.ProjectiveNielsPoint := do
  let fe ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.Y_plus_X b.Y_plus_X choice
  let fe1 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.Y_minus_X b.Y_minus_X choice
  let fe2 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.Z b.Z choice
  let fe3 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.T2d b.T2d choice
  ok { Y_plus_X := fe, Y_minus_X := fe1, Z := fe2, T2d := fe3 }



private def
  backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a b : backend.serial.curve_models.AffineNielsPoint)
  (choice : subtle.Choice) :
  Result backend.serial.curve_models.AffineNielsPoint := do
  let fe ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.y_plus_x b.y_plus_x choice
  let fe1 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.y_minus_x b.y_minus_x choice
  let fe2 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.xy2d b.xy2d choice
  ok { y_plus_x := fe, y_minus_x := fe1, xy2d := fe2 }



def
  backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : backend.serial.curve_models.ProjectiveNielsPoint)
  (choice : subtle.Choice) :
  Result (backend.serial.curve_models.ProjectiveNielsPoint ×
    backend.serial.curve_models.ProjectiveNielsPoint) := do
  let a_new ← backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : backend.serial.curve_models.ProjectiveNielsPoint) (choice : subtle.Choice)
  (h_a : ∃ res, backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    backend.serial.curve_models.ProjectiveNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry


def
  backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap'
  (a b : backend.serial.curve_models.AffineNielsPoint)
  (choice : subtle.Choice) :
  Result (backend.serial.curve_models.AffineNielsPoint ×
    backend.serial.curve_models.AffineNielsPoint) := do
  let a_new ← backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap'_spec
  (a b : backend.serial.curve_models.AffineNielsPoint) (choice : subtle.Choice)
  (h_a : ∃ res, backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap' a b choice ⦃ c =>
    backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry




def backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : backend.serial.curve_models.AffineNielsPoint)
  (choice : subtle.Choice) :
  Result (backend.serial.curve_models.AffineNielsPoint ×
    backend.serial.curve_models.AffineNielsPoint) :=
  backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap' a b choice







@[progress]
theorem backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : backend.serial.curve_models.AffineNielsPoint) (choice : subtle.Choice)
  (h_a : ∃ res, backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    backend.serial.curve_models.AffineNielsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry


private def
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a b : edwards.affine.AffinePoint)
  (choice : subtle.Choice) :
  Result edwards.affine.AffinePoint := do
  let fe ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.x b.x choice
  let fe1 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.y b.y choice
  ok { x := fe, y := fe1 }


def
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap'
  (a b : edwards.affine.AffinePoint)
  (choice : subtle.Choice) :
  Result (edwards.affine.AffinePoint × edwards.affine.AffinePoint) := do
  let a_new ← edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap'_spec
  (a b : edwards.affine.AffinePoint) (choice : subtle.Choice)
  (h_a : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap' a b choice ⦃ c =>
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry

def
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign'
  (a b : edwards.affine.AffinePoint)
  (choice : subtle.Choice) :
  Result edwards.affine.AffinePoint :=
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign'_spec
  (a b : edwards.affine.AffinePoint) (choice : subtle.Choice)
  (h : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign' a b choice ⦃ res =>
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry



private def scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select_loop'
  (a : scalar.Scalar) (b : scalar.Scalar) (choice : subtle.Choice)
  (bytes : Array Std.U8 32#usize) (iter : core.ops.range.Range Std.Usize) :
  Result (Array Std.U8 32#usize)
  := do
  let (o, iter1) ←
    core.iter.range.IteratorRange.next core.iter.range.StepUsize iter
  match o with
  | none => ok bytes
  | some i =>
    let i1 ← Array.index_usize a.bytes i
    let i2 ← Array.index_usize b.bytes i
    let i3 ←
      U8.Insts.SubtleConditionallySelectable.conditional_select i1 i2 choice
    let a1 ← Array.update bytes i i3
    scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select_loop'
      a b choice a1 iter1
partial_fixpoint




private def scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select'
  (a : scalar.Scalar) (b : scalar.Scalar) (choice : subtle.Choice) :
  Result scalar.Scalar
  := do
  let bytes := Array.repeat 32#usize 0#u8
  let iter ←
    core.iter.traits.collect.IntoIterator.Blanket.into_iter
      (core.iter.traits.iterator.IteratorRange core.iter.range.StepUsize)
      { start := 0#usize, «end» := 32#usize }
  let bytes1 ←
    scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select_loop'
      a b choice bytes iter
  ok { bytes := bytes1 }






def scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : scalar.Scalar)
  (choice : subtle.Choice) :
  Result (scalar.Scalar × scalar.Scalar) := do
  let a_new ← scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : scalar.Scalar) (choice : subtle.Choice)
  (h_a : ∃ res, scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry





def scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_assign
  (a b : scalar.Scalar)
  (choice : subtle.Choice) :
  Result scalar.Scalar :=
  scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : scalar.Scalar) (choice : subtle.Choice)
  (h : ∃ res, scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    scalar.Scalar.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry



private def edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a : edwards.EdwardsPoint) (b : edwards.EdwardsPoint)
  (choice : subtle.Choice) :
  Result edwards.EdwardsPoint
  := do
  let fe ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.X b.X choice
  let fe1 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.Y b.Y choice
  let fe2 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.Z b.Z choice
  let fe3 ←
    backend.serial.u64.field.ConditionallySelectableFieldElement51.conditional_select'
      a.T b.T choice
  ok { X := fe, Y := fe1, Z := fe2, T := fe3 }






def edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : edwards.EdwardsPoint)
  (choice : subtle.Choice) :
  Result (edwards.EdwardsPoint × edwards.EdwardsPoint) := do
  let a_new ← edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : edwards.EdwardsPoint) (choice : subtle.Choice)
  (h_a : ∃ res, edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry





def edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_assign
  (a b : edwards.EdwardsPoint)
  (choice : subtle.Choice) :
  Result edwards.EdwardsPoint :=
  edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : edwards.EdwardsPoint) (choice : subtle.Choice)
  (h : ∃ res, edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry





def montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : montgomery.ProjectivePoint) (choice : subtle.Choice)
  : Result (montgomery.ProjectivePoint × montgomery.ProjectivePoint) :=
  if choice.val = 1#u8 then ok (b, a) else ok (a, b)































@[reducible, rust_trait_impl "subtle::ConditionallySelectable<u8>"]
private def subtle.ConditionallySelectableU8' : subtle.ConditionallySelectable U8 := {
  coremarkerCopyInst := core.marker.CopyU8
  conditional_select := U8.Insts.SubtleConditionallySelectable.conditional_select
  conditional_assign := U8.Insts.SubtleConditionallySelectable.conditional_assign
  conditional_swap := U8.Insts.SubtleConditionallySelectable.conditional_swap
}




private def montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a : montgomery.MontgomeryPoint) (b : montgomery.MontgomeryPoint)
  (choice : subtle.Choice) :
  Result montgomery.MontgomeryPoint
  := do
  let a1 ←
    Array.Insts.SubtleConditionallySelectable.conditional_select
      subtle.ConditionallySelectableU8' a b choice
  ok a1






def montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a : montgomery.MontgomeryPoint) (b : montgomery.MontgomeryPoint)
  (choice : subtle.Choice) :
  Result (montgomery.MontgomeryPoint × montgomery.MontgomeryPoint) := do
  let a_new ← montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : montgomery.MontgomeryPoint) (choice : subtle.Choice) :
  montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ res =>
    res = (if choice.val = 1#u8 then (b, a) else (a, b)) ⦄ := by
  sorry





def montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_assign
  (a : montgomery.MontgomeryPoint) (b : montgomery.MontgomeryPoint)
  (choice : subtle.Choice) :
  Result montgomery.MontgomeryPoint :=
  montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : montgomery.MontgomeryPoint) (choice : subtle.Choice)
  (h : ∃ res, montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    montgomery.MontgomeryPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry


axiom montgomery.MontgomeryPoint.Insts.CoreCmpPartialEqMontgomeryPoint.ne
  : montgomery.MontgomeryPoint → montgomery.MontgomeryPoint → Result Bool






def montgomery.MontgomeryPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq
  (_self : montgomery.MontgomeryPoint) : Result Unit :=
  ok ()






@[progress]
theorem montgomery.MontgomeryPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq_spec
  (self : montgomery.MontgomeryPoint) :
  montgomery.MontgomeryPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq self ⦃ _ => True ⦄ := by
  sorry





def montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_assign
  (a : montgomery.ProjectivePoint) (b : montgomery.ProjectivePoint)
  (choice : subtle.Choice) :
  Result montgomery.ProjectivePoint :=
  montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : montgomery.ProjectivePoint) (choice : subtle.Choice)
  (h : ∃ res, montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    montgomery.ProjectivePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry





def edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : edwards.affine.AffinePoint)
  (choice : subtle.Choice) :
  Result (edwards.affine.AffinePoint × edwards.affine.AffinePoint) :=
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap' a b choice







@[progress]
theorem edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : edwards.affine.AffinePoint) (choice : subtle.Choice)
  (h_a : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry





def edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign
  (a b : edwards.affine.AffinePoint)
  (choice : subtle.Choice) :
  Result edwards.affine.AffinePoint :=
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign' a b choice







@[progress]
theorem edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : edwards.affine.AffinePoint) (choice : subtle.Choice)
  (h : ∃ res, edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    edwards.affine.AffinePoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry


axiom edwards.affine.AffinePoint.Insts.CoreCmpPartialEqAffinePoint.ne
  : edwards.affine.AffinePoint → edwards.affine.AffinePoint → Result Bool



axiom edwards.affine.AffinePoint.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : edwards.affine.AffinePoint → Result Unit



axiom edwards.CompressedEdwardsY.Insts.CoreCmpPartialEqCompressedEdwardsY.ne
  : edwards.CompressedEdwardsY → edwards.CompressedEdwardsY → Result Bool



axiom edwards.EdwardsPoint.Insts.CoreCmpPartialEqEdwardsPoint.ne
  : edwards.EdwardsPoint → edwards.EdwardsPoint → Result Bool



axiom edwards.EdwardsPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : edwards.EdwardsPoint → Result Unit



axiom
  ristretto.CompressedRistretto.Insts.CoreCmpPartialEqCompressedRistretto.ne
  :
  ristretto.CompressedRistretto → ristretto.CompressedRistretto → Result
    Bool



axiom ristretto.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.ne
  : ristretto.RistrettoPoint → ristretto.RistrettoPoint → Result Bool



axiom ristretto.RistrettoPoint.Insts.CoreCmpEq.assert_receiver_is_total_eq
  : ristretto.RistrettoPoint → Result Unit





private def ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select'
  (a : ristretto.RistrettoPoint) (b : ristretto.RistrettoPoint)
  (choice : subtle.Choice) :
  Result ristretto.RistrettoPoint
  := do
  let ep ←
    edwards.EdwardsPoint.Insts.SubtleConditionallySelectable.conditional_select'
      a b choice
  ok ep






def ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_swap
  (a b : ristretto.RistrettoPoint)
  (choice : subtle.Choice) :
  Result (ristretto.RistrettoPoint × ristretto.RistrettoPoint) := do
  let a_new ← ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice
  let b_new ← ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice
  ok (a_new, b_new)







@[progress]
theorem ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_swap_spec
  (a b : ristretto.RistrettoPoint) (choice : subtle.Choice)
  (h_a : ∃ res, ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res)
  (h_b : ∃ res, ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok res) :
  ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_swap a b choice ⦃ c =>
    ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok c.1 ∧
    ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' b a choice = ok c.2 ⦄ := by
  sorry





def ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_assign
  (a b : ristretto.RistrettoPoint)
  (choice : subtle.Choice) :
  Result ristretto.RistrettoPoint :=
  ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice







@[progress]
theorem ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_assign_spec
  (a b : ristretto.RistrettoPoint) (choice : subtle.Choice)
  (h : ∃ res, ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res) :
  ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_assign a b choice ⦃ res =>
    ristretto.RistrettoPoint.Insts.SubtleConditionallySelectable.conditional_select' a b choice = ok res ⦄ := by
  sorry
end curve25519_dalek
