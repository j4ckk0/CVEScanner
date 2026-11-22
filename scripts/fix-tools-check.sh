#!/usr/bin/env bash
#
# Apply fixes with the real build tools: npm, yarn 1, yarn 4, pnpm and Gradle each upgrade a vulnerable version of
# samples/fix-tools, offline, as the window's Apply fixes and --apply-fixes --yes run them.
#
#   scripts/fix-tools-check.sh
#
# Needs java, node with npm, yarn and pnpm (through corepack: yarn 1 by default, yarn 4 by the project's
# packageManager), and gradle on the PATH, and the program built (cvescanner-app/target/cvescanner.jar). Runs on Linux,
# and on Windows in Git Bash (the release's CI does both, .github/workflows/fix-tools.yml).
#
# First the tools fill their own caches, online: the versions the projects lock and the versions that fix them. These
# downloads are the tools' and this script's, never CVEScanner's: the scan and the fixes then run with the tools offline.
# Then each project is checked: its manifest and lockfile name the fixed version, written as the project wrote it
# (exact, ^ or ~; pnpm and yarn 4 pin it, since offline they resolve no range, and so does yarn 1 a ^ on Windows), and
# the folder scanned again holds no finding. minimist, which the projects have only through mkdirp, is overridden in each
# (npm's overrides, yarn's resolutions, pnpm-workspace.yaml). Last, without the tools on the PATH, nothing is applied
# and nothing changes.
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
root=$PWD
jar=$root/cvescanner-app/target/cvescanner.jar
db=$root/samples/db/advisory-database-main.zip
[ -f "$jar" ] || { echo "$jar missing: build first (scripts/build.sh)" >&2; exit 1; }
for tool in java node npm yarn pnpm gradle; do command -v "$tool" >/dev/null || { echo "$tool not found on the PATH" >&2; exit 1; }; done
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
# A path as Java reads it: Git Bash's /c/... is C:/... on Windows.
native() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A step that fails is said with the end of what its tool wrote; in GitHub Actions as an annotation too, since the
# run's page shows annotations to anyone and its log only to the repository's members.
step_log=$work/step.log
quiet() { "$@" > "$step_log" 2>&1; }
# An online step tried three times: a registry may refuse a CI runner's address for a while (429 Too Many Requests).
online() {
  local pause
  for pause in 30 90; do quiet "$@" && return 0; echo "  (retrying in ${pause}s: $* failed)"; sleep $pause; done
  quiet "$@"
}
annotate() {   # annotate TITLE TEXT: an error annotation in GitHub Actions, its lines kept
  [ -n "${GITHUB_ACTIONS:-}" ] || return 0
  local text=$2
  text=${text//'%'/'%25'}; text=${text//$'\r'/}; text=${text//$'\n'/'%0A'}
  echo "::error::fix-tools: $1%0A$text"
}
failed_step() {
  local code=$1 line=$2 command=$3 tail
  tail=$(tail -n 15 "$step_log" 2>/dev/null || true)
  echo "  FAILED  line $line: $command (exit $code)"; echo "$tail"
  annotate "line $line: $command" "$tail"
}
trap 'failed_step $? $LINENO "$BASH_COMMAND"' ERR
failures=0
failed_checks=""
check() {   # check DESCRIPTION FILE TEXT [absent]: the file holds the text, or does not with "absent"
  if grep -qF -- "$3" "$2"; then found=yes; else found=no; fi
  if { [ "${4:-}" = absent ] && [ $found = no ]; } || { [ "${4:-}" != absent ] && [ $found = yes ]; }; then
    echo "  ok      $1"
  else
    echo "  FAILED  $1 ($2 $([ "${4:-}" = absent ] && echo holds || echo lacks) $3)"; failures=$((failures + 1))
    failed_checks+="$1"$'\n'
  fi
}

echo "==> Filling the tools' caches (online)"
mkdir -p "$work/prime"
cp -a samples/fix-tools/. "$work/prime/"
(cd "$work/prime/npm" && online npm ci --ignore-scripts --no-audit --no-fund && online npm cache add lodash@4.17.21 \
  && online npm cache add minimist@1.2.6)
(cd "$work/prime/yarn1" && online yarn install --frozen-lockfile --ignore-scripts)
(cd "$work/prime/yarn4" && online yarn install --immutable)
(cd "$work/prime/pnpm" && online pnpm install --frozen-lockfile)
(cd "$work/prime/gradle" && online gradle dependencies)
# the fixed versions, through a project of its own, resolved: an override makes the tool resolve again, offline, from
# the metadata a resolution leaves in its cache (pnpm's above, from the lockfile alone, left none)
for tool in yarn1 yarn4 pnpm; do
  mkdir -p "$work/prime/fixed-$tool"
  manager=$([ $tool = yarn4 ] && echo ', "packageManager": "yarn@4.9.2"' || true)
  echo "{ \"name\": \"fixed\", \"version\": \"1.0.0\", \"private\": true$manager, \"dependencies\": { \"lodash\": \"4.17.21\", \"minimist\": \"1.2.6\", \"mkdirp\": \"0.5.5\" } }" \
    > "$work/prime/fixed-$tool/package.json"
  [ $tool = yarn4 ] && printf 'nodeLinker: node-modules\n' > "$work/prime/fixed-$tool/.yarnrc.yml"
  # a CI runner makes yarn 4 and pnpm refuse to write a lockfile: this project has none yet
  (cd "$work/prime/fixed-$tool" && case $tool in
     pnpm) online pnpm install --no-frozen-lockfile ;;
     *) YARN_ENABLE_IMMUTABLE_INSTALLS=false online yarn install ;;
   esac)
done
mkdir -p "$work/prime/fixed-gradle"
cp samples/fix-tools/gradle/settings.gradle "$work/prime/fixed-gradle/"
sed 's/commons-text:1.9/commons-text:1.10.0/' samples/fix-tools/gradle/build.gradle > "$work/prime/fixed-gradle/build.gradle"
echo "tasks.register('fetch') { doLast { configurations.runtimeClasspath.files } }" >> "$work/prime/fixed-gradle/build.gradle"
(cd "$work/prime/fixed-gradle" && online gradle fetch)

echo "==> Applying the fixes (the tools offline)"
mkdir -p "$work/run"
cp -a samples/fix-tools/. "$work/run/"
# installed, as a project is: pnpm's lockfile keeps only versions, its dependents' ranges are read from node_modules
(cd "$work/run/pnpm" && quiet pnpm install --offline --frozen-lockfile --ignore-scripts)
set +e
java -jar "$(native "$jar")" --no-gui --lang en -d "$(native "$work/run")" --db "$(native "$db")" -o "$(native "$work/out")" \
  --apply-fixes --yes > "$work/fixes.log" 2>&1
code=$?
set -e
sed -n '/^Fixes:/,/^====/p' "$work/fixes.log"
[ $code -eq 0 ] || { echo "  FAILED  exit code $code, not 0"; cat "$work/fixes.log"; failures=$((failures + 1));
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error::fix-tools: the fixes exited $code"; }
r=$work/run
check "npm: exact, as written"         "$r/npm/package.json"      '"lodash": "4.17.21"'
check "npm: locked"                    "$r/npm/package-lock.json" 'lodash-4.17.21.tgz'
check "npm: the old version gone"      "$r/npm/package-lock.json" '4.17.20' absent
if command -v cygpath >/dev/null; then   # Windows: no caret reaches yarn 1 through cmd.exe, the version is pinned
  check "yarn 1: ^ pinned on Windows"  "$r/yarn1/package.json"    '"lodash": "4.17.21"'
  check "yarn 1: the pin said"         "$work/fixes.log"          'cannot reach yarn 1 intact'
else
  check "yarn 1: ^, as written"        "$r/yarn1/package.json"    '"lodash": "^4.17.21"'
fi
check "yarn 1: locked"                 "$r/yarn1/yarn.lock"       'lodash-4.17.21.tgz'
check "yarn 1: the old version gone"   "$r/yarn1/yarn.lock"       '4.17.20' absent
check "yarn 4: exact, as written"      "$r/yarn4/package.json"    '"lodash": "4.17.21"'
check "yarn 4: locked"                 "$r/yarn4/yarn.lock"       'lodash@npm:4.17.21'
check "yarn 4: the old version gone"   "$r/yarn4/yarn.lock"       '4.17.20' absent
check "pnpm: ~ pinned, said so"        "$r/pnpm/package.json"     '"lodash": "4.17.21"'
check "pnpm: locked"                   "$r/pnpm/pnpm-lock.yaml"   'lodash@4.17.21'
check "pnpm: the old version gone"     "$r/pnpm/pnpm-lock.yaml"   '4.17.20' absent
check "pnpm: the pin said"             "$work/fixes.log"          'pnpm cannot resolve a range offline'
check "Gradle: the build file"         "$r/gradle/build.gradle"   'commons-text:1.10.0'
# minimist, there only through mkdirp: overridden, its vulnerable version only where the tool can say so
check "npm: minimist overridden"       "$r/npm/package.json"      '"minimist@1.2.5": "1.2.6"'
check "npm: minimist locked"           "$r/npm/package-lock.json" 'minimist-1.2.6.tgz'
check "npm: minimist 1.2.5 gone"       "$r/npm/package-lock.json" 'minimist-1.2.5.tgz' absent
check "yarn 1: minimist resolved"      "$r/yarn1/package.json"    '"minimist": "1.2.6"'
check "yarn 1: minimist locked"        "$r/yarn1/yarn.lock"       'minimist-1.2.6.tgz'
check "yarn 1: minimist 1.2.5 gone"    "$r/yarn1/yarn.lock"       'minimist-1.2.5.tgz' absent
check "yarn 4: minimist resolved"      "$r/yarn4/package.json"    '"minimist@npm:^1.2.5": "npm:1.2.6"'
check "yarn 4: minimist locked"        "$r/yarn4/yarn.lock"       'minimist@npm:1.2.6'
check "yarn 4: minimist 1.2.5 gone"    "$r/yarn4/yarn.lock"       'resolution: "minimist@npm:1.2.5"' absent
check "pnpm: minimist overridden"      "$r/pnpm/pnpm-workspace.yaml" "'minimist@1.2.5': 1.2.6"
check "pnpm: minimist locked"          "$r/pnpm/pnpm-lock.yaml"   'minimist@1.2.6: {}'
check "pnpm: minimist 1.2.5 gone"      "$r/pnpm/pnpm-lock.yaml"   'minimist@1.2.5: {}' absent
check "scanned again: no finding left" "$work/out/report.md"      'lodash' absent
check "scanned again: minimist too"    "$work/out/report.md"      'minimist' absent
# one annotation for them all: GitHub shows only the first ten of a step
[ $failures -eq 0 ] || annotate "$failures check(s) failed" "$failed_checks"$'\n'"$(sed -n '/^Fixes:/,$p' "$work/fixes.log" | head -n 120)"

echo "==> Without the tools on the PATH"
mkdir -p "$work/bare" "$work/nobin"
cp -a samples/fix-tools/. "$work/bare/"
java_bin=$(dirname "$(command -v java)")
set +e
PATH="$work/nobin" "$java_bin/java" -jar "$(native "$jar")" --no-gui --lang en -d "$(native "$work/bare")" \
  --db "$(native "$db")" -o "$(native "$work/out-bare")" --apply-fixes --yes > "$work/bare.log" 2>&1
code=$?
set -e
[ $code -eq 0 ] || { echo "  FAILED  exit code $code, not 0"; cat "$work/bare.log"; failures=$((failures + 1)); }
check "gradle missing: said" "$work/bare.log" "gradle is not installed"
check "lodash: its first tool missing, said" "$work/bare.log" "npm is not installed"
if diff -r samples/fix-tools "$work/bare" >/dev/null; then echo "  ok      nothing changed"
else echo "  FAILED  files changed without their tools"; failures=$((failures + 1)); fi

echo
[ $failures -eq 0 ] && echo "All checks passed." || { echo "$failures check(s) failed."; exit 1; }
