






import Lean
import Lean.Data.Json

open Lean

namespace Utils.Lib.Types



structure DocstringInfo where
  rustName : Option String := none
  source : Option String := none
  lineStart : Option Nat := none
  lineEnd : Option Nat := none
  deriving Repr, Inhabited


structure FunctionRecord where

  leanName : Name

  rustName : Option String := none

  source : Option String := none

  lineRange : Option (Nat × Nat) := none

  dependencies : Array Name := #[]

  isRelevant : Bool := false

  isExtractionArtifact : Bool := false

  isHidden : Bool := false

  isIgnored : Bool := false

  isSpecified : Bool := false

  isVerified : Bool := false

  isFullyVerified : Bool := false

  isExternallyVerified : Bool := false

  specFilePath : Option String := none

  specDocstring : Option String := none

  specStatement : Option String := none
  deriving Repr, Inhabited








structure FunctionOutput where
  lean_name : String
  rust_name : Option String := none
  source : Option String := none
  lines : Option String := none
  dependencies : Array String := #[]
  is_relevant : Bool := false
  is_extraction_artifact : Bool := false
  is_hidden : Bool := false
  is_ignored : Bool := false
  specified : Bool := false
  verified : Bool := false
  fully_verified : Bool := false
  externally_verified : Bool := false
  spec_file : Option String := none
  spec_docstring : Option String := none
  spec_statement : Option String := none
  deriving ToJson, FromJson, Repr


def FunctionRecord.toOutput (rec : FunctionRecord) : FunctionOutput :=
  let lines := match rec.lineRange with
    | some (s, e) => some s!"L{s}-L{e}"
    | none => none
  { lean_name := rec.leanName.toString
    rust_name := rec.rustName
    source := rec.source
    lines := lines
    dependencies := rec.dependencies.map (·.toString)
    is_relevant := rec.isRelevant
    is_extraction_artifact := rec.isExtractionArtifact
    is_hidden := rec.isHidden
    is_ignored := rec.isIgnored
    specified := rec.isSpecified
    verified := rec.isVerified
    fully_verified := rec.isFullyVerified
    externally_verified := rec.isExternallyVerified
    spec_file := rec.specFilePath
    spec_docstring := rec.specDocstring
    spec_statement := rec.specStatement }


structure FunctionListOutput where
  functions : Array FunctionOutput
  deriving ToJson, FromJson, Repr


def renderFunctionListOutput (output : FunctionListOutput) : String :=
  (toJson output).pretty








structure FunctionInput where
  lean_name : String
  deriving FromJson, ToJson, Repr


structure FunctionListInput where
  functions : Array FunctionInput
  deriving FromJson, ToJson, Repr


def parseInput (s : String) : Except String FunctionListInput :=
  match Json.parse s with
  | .error e => .error s!"JSON parse error: {e}"
  | .ok json =>
    match fromJson? json with
    | .error e => .error s!"JSON decode error: {e}"
    | .ok input => .ok input

end Utils.Lib.Types
