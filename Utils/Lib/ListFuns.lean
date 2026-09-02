









import Lean
import Std.Data.HashSet
import Utils.Config
import Utils.Lib.Types
import Utils.Lib.Docstring
import Utils.Lib.Analysis

open Lean

namespace Utils.Lib.ListFuns

open Utils.Lib.Types
open Utils.Lib.Docstring
open Utils.Lib.Analysis
open Utils.Config






def containsSubstr (s sub : String) : Bool :=
  (s.splitOn sub).length > 1






def isDefinition (ci : ConstantInfo) : Bool :=
  match ci with
  | .defnInfo _ => true
  | _ => false


def hasExcludedPrefix (name : Name) : Bool :=
  excludedNamespacePrefixes.any fun pfx =>
    pfx.toName.isPrefixOf name


def isExtractionArtifactName (name : Name) : Bool :=
  let str := name.toString
  extractionArtifactSuffixes.any fun sfx => str.endsWith sfx


def isHiddenFunction (name : Name) : Bool :=
  let str := name.toString
  hiddenFunctions.any fun hidden => str == hidden


def isIgnoredFunction (name : Name) : Bool :=
  let str := name.toString
  ignoredFunctions.any fun ignored => str == ignored


def passesBasicFilters (name : Name) : Bool :=
  !hasExcludedPrefix name










def isRelevantSource (source : Option String) (crate : String) : Bool :=
  match source with
  | none => false
  | some s =>

    containsSubstr s crate &&
    !s.startsWith "/" &&
    !containsSubstr s "/cargo/registry/"






def getModuleDefinitions (env : Environment) (moduleName : Name) : Array Name := Id.run do
  let some moduleIdx := env.header.moduleNames.idxOf? moduleName
    | return #[]
  let constNames := env.header.moduleData[moduleIdx]!.constNames
  let mut result : Array Name := #[]
  for name in constNames do
    if let some ci := env.find? name then
      if isDefinition ci then
        result := result.push name
  return result


def getBodyName (name : Name) : Name :=
  name.appendAfter "_body"


structure RawFunctionData where
  name : Name
  docInfo : DocstringInfo
  rawDeps : Array Name
  isExtractionArtifact : Bool
  isHidden : Bool
  deriving Repr


def gatherRawData (env : Environment) (name : Name) : IO RawFunctionData := do
  let isArtifact := isExtractionArtifactName name
  let hidden := isHiddenFunction name
  let mut docInfo ← getDocstringInfo env name


  if docInfo.rustName.isNone && !name.toString.endsWith "_body" then
    let bodyName := getBodyName name
    if env.find? bodyName |>.isSome then
      let bodyDocInfo ← getDocstringInfo env bodyName

      docInfo := bodyDocInfo

  let rawDeps := match getDirectDeps env name with
    | .ok deps => deps
    | .error _ => #[]
  return { name, docInfo, rawDeps, isExtractionArtifact := isArtifact, isHidden := hidden }


def buildFunctionRecord
    (env : Environment)
    (rawData : RawFunctionData)
    (relevantNames : Std.HashSet Name)
    (crate : String)
    : IO FunctionRecord := do
  let docInfo := rawData.docInfo
  let lineRange := match docInfo.lineStart, docInfo.lineEnd with
    | some s, some e => some (s, e)
    | _, _ => none
  let filteredDeps := rawData.rawDeps.filter (relevantNames.contains ·)
  let isRelevant := isRelevantSource docInfo.source crate
  let specParts ← getSpecParts env rawData.name
  return {
    leanName := rawData.name
    rustName := docInfo.rustName
    source := docInfo.source
    lineRange := lineRange
    dependencies := filteredDeps
    isRelevant := isRelevant
    isExtractionArtifact := rawData.isExtractionArtifact
    isHidden := rawData.isHidden
    isIgnored := isIgnoredFunction rawData.name
    isSpecified := hasSpecTheorem env rawData.name
    isVerified := isVerified env rawData.name
    isFullyVerified := isFullyVerified env relevantNames rawData.name
    isExternallyVerified := isExternallyVerified env rawData.name
    specFilePath := getSpecFilePath env rawData.name
    specDocstring := specParts.docstring
    specStatement := specParts.statement
  }


def buildFunctionRecords
    (env : Environment)
    (moduleName : Name := funsModule)
    (crate : String := crateName)
    : IO (Array FunctionRecord) := do

  let allDefs := getModuleDefinitions env moduleName


  let basicFiltered := allDefs.filter passesBasicFilters


  let rawDataArray ← basicFiltered.mapM (gatherRawData env)



  let mut relevantNames : Std.HashSet Name := {}
  for rawData in rawDataArray do
    if isRelevantSource rawData.docInfo.source crate then
      relevantNames := relevantNames.insert rawData.name


  let records ← rawDataArray.mapM fun rawData =>
    buildFunctionRecord env rawData relevantNames crate


  return records.qsort (·.leanName.toString < ·.leanName.toString)


def getRelevantFunctions
    (env : Environment)
    (moduleName : Name := funsModule)
    (crate : String := crateName)
    : IO (Array FunctionRecord) := do
  let all ← buildFunctionRecords env moduleName crate
  return all.filter (·.isRelevant)






def loadEnvironment : IO Environment := do
  Lean.initSearchPath (← Lean.findSysroot)
  importModules #[{ module := mainModule }] {}


def getFunsDefinitionsAsStrings (env : Environment) : IO (Array String) := do
  let records ← getRelevantFunctions env
  return records.map (·.leanName.toString)

end Utils.Lib.ListFuns
