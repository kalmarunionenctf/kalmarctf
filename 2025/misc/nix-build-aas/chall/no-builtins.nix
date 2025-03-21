# Forbid using any of the nix builtins
# Ref: https://nix.dev/manual/nix/2.18/language/builtins.html
{
  "__add" = throw "__add is not available";
  "__currentSystem" = throw "__currentSystem is not available";
  "__getAttr" = throw "__getAttr is not available";
  "__isPath" = throw "__isPath is not available";
  "__readFile" = throw "__readFile is not available";
  "__trace" = throw "__trace is not available";
  "fetchMercurial" = throw "fetchMercurial is not available";
  "__addDrvOutputDependencies" = throw "__addDrvOutputDependencies is not available";
  "__currentTime" = throw "__currentTime is not available";
  "__getContext" = throw "__getContext is not available";
  "__isString" = throw "__isString is not available";
  "__readFileType" = throw "__readFileType is not available";
  "__traceVerbose" = throw "__traceVerbose is not available";
  "fetchTarball" = throw "fetchTarball is not available";
  "__addErrorContext" = throw "__addErrorContext is not available";
  "__deepSeq" = throw "__deepSeq is not available";
  "__getEnv" = throw "__getEnv is not available";
  "__langVersion" = throw "__langVersion is not available";
  "__replaceStrings" = throw "__replaceStrings is not available";
  "__tryEval" = throw "__tryEval is not available";
  "fetchTree" = throw "fetchTree is not available";
  "__all" = throw "__all is not available";
  "__div" = throw "__div is not available";
  "__getFlake" = throw "__getFlake is not available";
  "__length" = throw "__length is not available";
  "__seq" = throw "__seq is not available";
  "__typeOf" = throw "__typeOf is not available";
  "fromTOML" = throw "fromTOML is not available";
  "__any" = throw "__any is not available";
  "__elem" = throw "__elem is not available";
  "__groupBy" = throw "__groupBy is not available";
  "__lessThan" = throw "__lessThan is not available";
  "__sort" = throw "__sort is not available";
  "__unsafeDiscardOutputDependency" = throw "__unsafeDiscardOutputDependency is not available";
  "import" = throw "import is not available";
  "__appendContext" = throw "__appendContext is not available";
  "__elemAt" = throw "__elemAt is not available";
  "__hasAttr" = throw "__hasAttr is not available";
  "__listToAttrs" = throw "__listToAttrs is not available";
  "__split" = throw "__split is not available";
  "__unsafeDiscardStringContext" = throw "__unsafeDiscardStringContext is not available";
  "isNull" = throw "isNull is not available";
  "__attrNames" = throw "__attrNames is not available";
  "__fetchurl" = throw "__fetchurl is not available";
  "__hasContext" = throw "__hasContext is not available";
  "__mapAttrs" = throw "__mapAttrs is not available";
  "__splitVersion" = throw "__splitVersion is not available";
  "__unsafeGetAttrPos" = throw "__unsafeGetAttrPos is not available";
  "map" = throw "map is not available";
  "__attrValues" = throw "__attrValues is not available";
  "__filter" = throw "__filter is not available";
  "__hashFile" = throw "__hashFile is not available";
  "__match" = throw "__match is not available";
  "__storeDir" = throw "__storeDir is not available";
  "__zipAttrsWith" = throw "__zipAttrsWith is not available";
  "null" = throw "null is not available";
  "__bitAnd" = throw "__bitAnd is not available";
  "__filterSource" = throw "__filterSource is not available";
  "__hashString" = throw "__hashString is not available";
  "__mul" = throw "__mul is not available";
  "__storePath" = throw "__storePath is not available";
  "abort" = throw "abort is not available";
  "placeholder" = throw "placeholder is not available";
  "__bitOr" = throw "__bitOr is not available";
  "__findFile" = throw "__findFile is not available";
  "__head" = throw "__head is not available";
  "__nixPath" = throw "__nixPath is not available";
  "__stringLength" = throw "__stringLength is not available";
  "baseNameOf" = throw "baseNameOf is not available";
  "removeAttrs" = throw "removeAttrs is not available";
  "__bitXor" = throw "__bitXor is not available";
  "__flakeRefToString" = throw "__flakeRefToString is not available";
  "__intersectAttrs" = throw "__intersectAttrs is not available";
  "__nixVersion" = throw "__nixVersion is not available";
  "__sub" = throw "__sub is not available";
  "break" = throw "break is not available";
  "scopedImport" = throw "scopedImport is not available";
  "__catAttrs" = throw "__catAttrs is not available";
  "__floor" = throw "__floor is not available";
  "__isAttrs" = throw "__isAttrs is not available";
  "__parseDrvName" = throw "__parseDrvName is not available";
  "__substring" = throw "__substring is not available";
  "builtins" = throw "builtins is not available";
  "throw" = throw "throw is not available";
  "__ceil" = throw "__ceil is not available";
  "__foldl'" = throw "__foldl' is not available";
  "__isBool" = throw "__isBool is not available";
  "__parseFlakeRef" = throw "__parseFlakeRef is not available";
  "__tail" = throw "__tail is not available";
  "derivation" = throw "derivation is not available";
  "toString" = throw "toString is not available";
  "__compareVersions" = throw "__compareVersions is not available";
  "__fromJSON" = throw "__fromJSON is not available";
  "__isFloat" = throw "__isFloat is not available";
  "__partition" = throw "__partition is not available";
  "__toFile" = throw "__toFile is not available";
  "derivationStrict" = throw "derivationStrict is not available";
  "true" = throw "true is not available";
  "__concatLists" = throw "__concatLists is not available";
  "__functionArgs" = throw "__functionArgs is not available";
  "__isFunction" = throw "__isFunction is not available";
  "__path" = throw "__path is not available";
  "__toJSON" = throw "__toJSON is not available";
  "dirOf" = throw "dirOf is not available";
  "__concatMap" = throw "__concatMap is not available";
  "__genList" = throw "__genList is not available";
  "__isInt" = throw "__isInt is not available";
  "__pathExists" = throw "__pathExists is not available";
  "__toPath" = throw "__toPath is not available";
  "false" = throw "false is not available";
  "__concatStringsSep" = throw "__concatStringsSep is not available";
  "__genericClosure" = throw "__genericClosure is not available";
  "__isList" = throw "__isList is not available";
  "__readDir" = throw "__readDir is not available";
  "__toXML" = throw "__toXML is not available";
  "fetchGit" = throw "fetchGit is not available";
}
