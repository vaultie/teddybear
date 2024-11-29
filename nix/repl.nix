{
  lib,
  nodejs,
  uni,
  writeShellScriptBin,
}:
writeShellScriptBin "teddybear-repl" ''
  ${lib.getExe nodejs} -i -e "const t = require(\"${uni}\");"
''
