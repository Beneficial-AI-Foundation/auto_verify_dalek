





import Lean
import Utils.Lib.Types

open Lean

namespace Utils.Lib.Docstring

open Utils.Lib.Types


def extractRustName (doc : String) : Option String :=

  let parts := doc.splitOn "["
  if h : parts.length >= 2 then
    let afterBracket := parts[1]
    let endParts := afterBracket.splitOn "]"
    if h2 : endParts.length >= 1 then
      let content := endParts[0].trimAscii.toString

      some (if content.endsWith ":" then (content.dropEnd 1).toString else content)
    else none
  else none


def extractSourceFile (doc : String) : Option String :=
  let pattern := "Source: '"
  let parts := doc.splitOn pattern
  if h : parts.length >= 2 then
    let afterPattern := parts[1]

    let quoteParts := afterPattern.splitOn "'"
    if h2 : quoteParts.length >= 1 then
      some quoteParts[0]
    else none
  else none


def extractLineRange (doc : String) : Option (Nat × Nat) :=
  let pattern := "lines "
  let parts := doc.splitOn pattern
  if h : parts.length >= 2 then
    let afterPattern := parts[1]

    match afterPattern.splitOn "-" with
    | [startPart, endPart] =>

      let startLine := (startPart.takeWhile Char.isDigit).toNat?
      let endLine := (endPart.takeWhile Char.isDigit).toNat?
      match startLine, endLine with
      | some st, some en => some (st, en)
      | _, _ => none
    | _ => none
  else none


def parseDocstring (doc : String) : DocstringInfo :=
  { rustName := extractRustName doc
    source := extractSourceFile doc
    lineStart := (extractLineRange doc).map Prod.fst
    lineEnd := (extractLineRange doc).map Prod.snd }


def getDocstring (env : Environment) (name : Name) : IO (Option String) :=
  Lean.findDocString? env name


def getDocstringInfo (env : Environment) (name : Name) : IO DocstringInfo := do
  match ← getDocstring env name with
  | some doc => return parseDocstring doc
  | none => return default

end Utils.Lib.Docstring
