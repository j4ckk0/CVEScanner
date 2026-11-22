#!/usr/bin/env bash
#
# The window test alone (WindowChecklistTest): the window started on the samples and clicked through, on a virtual
# display. Needs xvfb-run: it never runs on the desktop, whose pointer and keyboard it would take.
#
#   scripts/window-check.sh
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."   # the project root
command -v xvfb-run >/dev/null || { echo "xvfb-run not found (sudo apt install xvfb): the window test needs a virtual display" >&2; exit 1; }
. scripts/externals.sh
running_instance "the window test"
take_build_lock
exec env -u DISPLAY -u WAYLAND_DISPLAY xvfb-run -a -s "-screen 0 1600x1000x24" \
  mvn -q package -Dtest=WindowChecklistTest -Dsurefire.failIfNoSpecifiedTests=false -Dcvescanner.windowTest=true
