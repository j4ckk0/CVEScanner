#!/usr/bin/env bash
#
# The README's pictures, taken again: docs/images/*.png in English, docs/images/fr/*.png in French (ScreenshotsTest),
# the window on a virtual display. The examples are scanned with real databases, given as arguments — none is in the
# repository; download them as README "The databases" says:
#
#   scripts/screenshots.sh Maven-all.zip npm-all.zip PyPI-all.zip nvdcve-2.0-*.json.zip
#
# (OSV.dev's ecosystem exports and NVD's yearly CVE feeds). The VEX picture uses the samples alone.
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."   # the project root
[ $# -gt 0 ] || { sed -n '3,10p' "$0" >&2; exit 1; }
command -v xvfb-run >/dev/null || { echo "xvfb-run not found (sudo apt install xvfb): the pictures are taken on a virtual display" >&2; exit 1; }
dbs=()
for db in "$@"; do dbs+=("$(readlink -f "$db")"); done
. scripts/externals.sh
running_instance "the screenshots"
take_build_lock
exec env -u DISPLAY -u WAYLAND_DISPLAY xvfb-run -a -s "-screen 0 1600x1100x24" \
  mvn -q package -Dtest=ScreenshotsTest -Dsurefire.failIfNoSpecifiedTests=false -Dcvescanner.windowWait=900 \
  -Dcvescanner.screenshots="$PWD/docs/images" -Dcvescanner.screenshotDbs="$(IFS=:; echo "${dbs[*]}")"
