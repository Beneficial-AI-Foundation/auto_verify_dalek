














import Lean
import Utils.Lib.Types

open Lean
open Utils.Lib.Types

namespace Utils.Lib.StatusCsv


structure StatusRow where
  function : String
  lean_name : String
  source : String
  lines : String
  spec_theorem : String
  extracted : String
  verified : String
  notes : String
  ignored : String
  ai_proveable : String
  deriving Repr, Inhabited


structure StatusFile where
  header : String
  rows : Array StatusRow
  deriving Repr


def defaultPath : System.FilePath := "status.csv"


private def containsSubstr (s sub : String) : Bool :=
  (s.splitOn sub).length > 1


def escapeField (s : String) : String :=
  if containsSubstr s "," || containsSubstr s "\"" || containsSubstr s "\n" then

    "\"" ++ s.replace "\"" "\"\"" ++ "\""
  else
    s


private def parseField (s : String) : String :=
  let trimmed := s.trimAscii.toString
  if trimmed.startsWith "\"" && trimmed.endsWith "\"" && trimmed.length >= 2 then

    let inner := trimmed.drop 1 |>.dropEnd 1
    inner.replace "\"\"" "\""
  else
    s


def splitCsvLine (line : String) : Array String := Id.run do
  let mut fields : Array String := #[]
  let mut current := ""
  let mut inQuotes := false
  let mut i := 0
  let chars := line.toList

  while i < chars.length do
    let c := chars[i]!
    if c == '"' then
      if inQuotes && i + 1 < chars.length && chars[i + 1]! == '"' then

        current := current.push '"'
        i := i + 1
      else

        inQuotes := !inQuotes
    else if c == ',' && !inQuotes then

      fields := fields.push current
      current := ""
    else
      current := current.push c
    i := i + 1


  fields := fields.push current
  return fields


def joinCsvLine (fields : Array String) : String :=
  ",".intercalate (fields.map escapeField).toList


def parseRow (line : String) : Option StatusRow :=
  let fields := splitCsvLine line
  if fields.size >= 10 then
    some {
      function := fields[0]!
      lean_name := fields[1]!
      source := fields[2]!
      lines := fields[3]!
      spec_theorem := fields[4]!
      extracted := fields[5]!
      verified := fields[6]!
      notes := fields[7]!
      ignored := fields[8]!
      ai_proveable := fields[9]!
    }
  else if fields.size >= 2 then

    some {
      function := fields[0]!
      lean_name := fields[1]!
      source := fields.getD 2 ""
      lines := fields.getD 3 ""
      spec_theorem := fields.getD 4 ""
      extracted := fields.getD 5 ""
      verified := fields.getD 6 ""
      notes := fields.getD 7 ""
      ignored := ""
      ai_proveable := fields.getD 8 ""
    }
  else
    none


def StatusRow.toCsvLine (row : StatusRow) : String :=
  joinCsvLine #[row.function, row.lean_name, row.source, row.lines,
                row.spec_theorem, row.extracted, row.verified, row.notes, row.ignored, row.ai_proveable]


def readStatusFile (path : System.FilePath := defaultPath) : IO StatusFile := do
  let content ← IO.FS.readFile path
  let lines := content.splitOn "\n" |>.filter (·.trimAscii.toString != "")
  match lines with
  | [] => return { header := "", rows := #[] }
  | header :: dataLines =>
    let rows := dataLines.filterMap parseRow
    return { header := header, rows := rows.toArray }


def writeStatusFile (file : StatusFile) (path : System.FilePath := defaultPath) : IO Unit := do
  let headerLine := file.header
  let sortedRows := file.rows.qsort (·.lean_name < ·.lean_name)
  let dataLines := sortedRows.map StatusRow.toCsvLine
  let allLines := #[headerLine] ++ dataLines
  let content := "\n".intercalate allLines.toList
  IO.FS.writeFile path (content ++ "\n")


def StatusFile.getLeanNames (file : StatusFile) : Array String :=
  file.rows.map (·.lean_name)


def StatusRow.fromFunctionOutput (fn : FunctionOutput) : StatusRow :=
  let verifiedStr := if fn.verified then "verified"
                     else if fn.externally_verified then "externally verified"
                     else if fn.specified then "specified"
                     else ""
  let extractedStr := if fn.is_relevant then "extracted" else ""
  let ignoredStr := if fn.is_ignored then "ignored" else ""
  { function := fn.rust_name.getD ""
    lean_name := fn.lean_name
    source := fn.source.getD ""
    lines := fn.lines.getD ""
    spec_theorem := fn.spec_file.getD ""
    extracted := extractedStr
    verified := verifiedStr
    notes := ""
    ignored := ignoredStr
    ai_proveable := "" }


def StatusRow.sameUpdatableFields (a b : StatusRow) : Bool :=
  a.function == b.function &&
  a.source == b.source &&
  a.lines == b.lines &&
  a.spec_theorem == b.spec_theorem &&
  a.extracted == b.extracted &&
  a.verified == b.verified &&
  a.ignored == b.ignored



def StatusRow.updateFrom (row : StatusRow) (fn : FunctionOutput) : StatusRow :=
  let verifiedStr := if fn.verified then "verified"
                     else if fn.externally_verified then "externally verified"
                     else if fn.specified then "specified"
                     else ""
  let extractedStr := if fn.is_relevant then "extracted" else ""
  let ignoredStr := if fn.is_ignored then "ignored" else ""
  { row with
    function := fn.rust_name.getD row.function
    source := fn.source.getD row.source
    lines := fn.lines.getD row.lines
    spec_theorem := fn.spec_file.getD row.spec_theorem
    extracted := extractedStr
    verified := verifiedStr
    ignored := ignoredStr }


def StatusFile.addRow (file : StatusFile) (row : StatusRow) : StatusFile :=
  { file with rows := file.rows.push row }


def StatusFile.hasLeanName (file : StatusFile) (leanName : String) : Bool :=
  file.rows.any (·.lean_name == leanName)


def StatusFile.findByLeanName (file : StatusFile) (leanName : String) : Option StatusRow :=
  file.rows.find? (·.lean_name == leanName)


def StatusFile.upsertFromFunction (file : StatusFile) (fn : FunctionOutput) : StatusFile :=
  let idx := file.rows.findIdx? (·.lean_name == fn.lean_name)
  match idx with
  | some i =>

    let updatedRow := file.rows[i]!.updateFrom fn
    { file with rows := file.rows.set! i updatedRow }
  | none =>

    file.addRow (StatusRow.fromFunctionOutput fn)


def StatusFile.removeByLeanNames (file : StatusFile) (names : Std.HashSet String) : StatusFile :=
  { file with rows := file.rows.filter fun row => !names.contains row.lean_name }


def StatusFile.findDuplicateLeanNames (file : StatusFile) : Array String := Id.run do
  let mut seen : Std.HashSet String := {}
  let mut duplicates : Std.HashSet String := {}
  for row in file.rows do
    if seen.contains row.lean_name then
      duplicates := duplicates.insert row.lean_name
    else
      seen := seen.insert row.lean_name
  return duplicates.toArray.qsort (· < ·)


def StatusFile.deduplicate (file : StatusFile) : StatusFile := Id.run do
  let mut seen : Std.HashSet String := {}
  let mut uniqueRows : Array StatusRow := #[]
  for row in file.rows do
    if !seen.contains row.lean_name then
      seen := seen.insert row.lean_name
      uniqueRows := uniqueRows.push row
  return { file with rows := uniqueRows }

end Utils.Lib.StatusCsv
