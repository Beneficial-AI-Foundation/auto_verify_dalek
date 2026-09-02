













import Lean
import Lean.PrettyPrinter
import Std.Data.HashSet
import Curve25519Dalek.ExternallyVerified

open Lean
open Lean.Meta
open Lean.PrettyPrinter

namespace Utils.Lib.Analysis








abbrev EnvM := ReaderT Environment Id

instance : MonadEnv EnvM where
  getEnv := read
  modifyEnv _ := pure ()



def specSuffix : String := "_spec"


def getSpecName (name : Name) : Name := name.appendAfter specSuffix


def getDirectDeps (env : Environment) (name : Name) : Except String (Array Name) := do
  let some constInfo := env.find? name
    | throw s!"Constant '{name}' not found in environment"
  let some value := constInfo.value?
    | throw s!"Constant '{name}' has no value (it may be an axiom, opaque, or primitive)"
  return value.getUsedConstants


def filterToKnownFunctions (knownNames : Std.HashSet Name) (deps : Array Name) : Array Name :=
  deps.filter (fun name => knownNames.contains name)


def hasSpecTheorem (env : Environment) (name : Name) : Bool :=
  env.find? (getSpecName name) |>.isSome


def proofContainsSorry (env : Environment) (name : Name) : Bool :=
  match env.find? name with
  | some constInfo =>
    match constInfo.value? with
    | some value => value.getUsedConstants.any (· == ``sorryAx)
    | none => true
  | none => true


def isVerified (env : Environment) (name : Name) : Bool :=
  let specName := getSpecName name
  match env.find? specName with
  | some _ => !proofContainsSorry env specName
  | none => false



def isExternallyVerified (env : Environment) (name : Name) : Bool :=
  let specName := getSpecName name
  if !proofContainsSorry env specName then false
  else externallyVerifiedAttr.hasTag env specName



def getSpecFilePath (env : Environment) (name : Name) : Option String :=
  let specName := getSpecName name

  if env.find? specName |>.isNone then none
  else

    match env.getModuleIdxFor? specName with
    | none => none
    | some modIdx =>
      let moduleName := env.allImportedModuleNames[modIdx.toNat]!

      some (moduleName.toString.replace "." "/" ++ ".lean")



def getSpecStatement (env : Environment) (name : Name) : IO (Option String) := do
  let specName := getSpecName name
  match env.find? specName with
  | none => return none
  | some constInfo =>
    let type := constInfo.type

    let (fmt, _) ← (Meta.ppExpr type).run'.toIO
      { fileName := "", fileMap := default }
      { env := env }
    return some (Format.pretty fmt)


structure SpecParts where
  docstring : Option String := none
  statement : Option String := none
  deriving Repr, Inhabited


structure StatementLineResult where
  line : String
  isEnd : Bool



def processStatementLine (line : String) : StatementLineResult :=
  let parts := line.splitOn ":= by"
  if parts.length > 1 then
    { line := parts[0]!.trimAsciiEnd.toString ++ " := by ...", isEnd := true }
  else if line.trimAsciiEnd.toString.endsWith ":=" then
    { line := line.trimAsciiEnd.toString ++ " ...", isEnd := true }
  else
    { line := line, isEnd := false }


def parseSpecSource (relevantLines : Array String) : SpecParts := Id.run do
  let mut docstringLines : Array String := #[]
  let mut statementLines : Array String := #[]
  let mut inDocstring := false
  let mut docstringDone := false

  for line in relevantLines do
    if !docstringDone then

      if line.trimAsciiStart.toString.startsWith "/-" then
        inDocstring := true
        docstringLines := docstringLines.push line
      else if inDocstring then
        docstringLines := docstringLines.push line
        if (line.splitOn "-/").length > 1 then
          inDocstring := false
          docstringDone := true
      else if line.trimAsciiStart.toString.startsWith "@[" then

        docstringDone := true
        continue
      else if line.trimAsciiStart.toString.startsWith "theorem" then
        docstringDone := true
        let result := processStatementLine line
        statementLines := statementLines.push result.line
        if result.isEnd then
          break
      else
        continue
    else

      if line.trimAsciiStart.toString.startsWith "@[" then
        continue
      let result := processStatementLine line
      statementLines := statementLines.push result.line
      if result.isEnd then
        break

  let docstring := if docstringLines.isEmpty then none
    else some (String.intercalate "\n" docstringLines.toList)
  let statement := if statementLines.isEmpty then none
    else some (String.intercalate "\n" statementLines.toList)
  return { docstring, statement }



def getSpecParts (env : Environment) (name : Name) : IO SpecParts := do
  let specName := getSpecName name

  if env.find? specName |>.isNone then return {}

  let rangesOpt : Option DeclarationRanges := (findDeclarationRangesCore? specName : EnvM _).run env
  match rangesOpt with
  | none => return {}
  | some ranges =>

    let some modIdx := env.getModuleIdxFor? specName | return {}
    let moduleName := env.allImportedModuleNames[modIdx.toNat]!

    let filePath : System.FilePath := moduleName.toString.replace "." "/" ++ ".lean"
    if !(← filePath.pathExists) then return {}

    let contents ← IO.FS.readFile filePath
    let lines := contents.splitOn "\n"
    let range := ranges.range
    let startLine := range.pos.line
    let endLine := range.endPos.line
    if startLine == 0 || endLine == 0 then return {}
    let relevantLines := lines.toArray.extract (startLine - 1) endLine
    return parseSpecSource relevantLines


structure AnalysisResult where
  name : Name
  allDeps : Array Name
  filteredDeps : Array Name

  specified : Bool

  verified : Bool
  error : Option String := none
  deriving Repr


def analyzeFunction (env : Environment) (knownNames : Std.HashSet Name) (name : Name) : AnalysisResult :=
  match getDirectDeps env name with
  | .ok deps =>
    { name := name
      allDeps := deps
      filteredDeps := filterToKnownFunctions knownNames deps
      specified := hasSpecTheorem env name
      verified := isVerified env name
      error := none }
  | .error msg =>
    { name := name
      allDeps := #[]
      filteredDeps := #[]
      specified := false
      verified := false
      error := some msg }


def analyzeFunctions (env : Environment) (knownNames : Std.HashSet Name) (names : List Name) : List AnalysisResult :=
  names.map (analyzeFunction env knownNames)


def resolveConstantName (env : Environment) (nameStr : String) : Option Name :=
  let name := nameStr.toName
  if env.find? name |>.isSome then some name else none



partial def getTransitiveDepsWithErrors (env : Environment) (knownNames : Std.HashSet Name) (name : Name)
    (visited : Std.HashSet Name := {}) (errors : Array String := #[]) : Std.HashSet Name × Array String :=
  if visited.contains name then (visited, errors)
  else
    let visited := visited.insert name
    match getDirectDeps env name with
    | .error msg =>

      (visited, errors.push s!"Warning: {msg}")
    | .ok deps =>
      let filteredDeps := filterToKnownFunctions knownNames deps
      filteredDeps.foldl
        (fun (acc, errs) dep => getTransitiveDepsWithErrors env knownNames dep acc errs)
        (visited, errors)



partial def getTransitiveDeps (env : Environment) (knownNames : Std.HashSet Name) (name : Name)
    (visited : Std.HashSet Name := {}) : IO (Std.HashSet Name) := do
  let (result, errors) := getTransitiveDepsWithErrors env knownNames name visited
  for err in errors do
    IO.eprintln err
  return result


def isFullyVerified (env : Environment) (knownNames : Std.HashSet Name) (name : Name) : Bool :=

  if !isVerified env name then false
  else

    let (allDeps, _) := getTransitiveDepsWithErrors env knownNames name
    let transitiveDeps := allDeps.erase name

    transitiveDeps.all (isVerified env)

end Utils.Lib.Analysis
