#!/usr/bin/env bash
#
# The project's CI, run locally: a clean build with every test, the window test included when xvfb-run is there
# (on a virtual display, never on the desktop; without it, the window test is left out and said so).
#
#   scripts/ci.sh
#
# Run by .githooks/pre-push before every push; enable the hooks once with:
#   git config core.hooksPath .githooks
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."   # the project root
. scripts/externals.sh   # setup done? (offers it otherwise); the externals first
running_instance "the build"
take_build_lock
if command -v xvfb-run >/dev/null; then
  exec env -u DISPLAY -u WAYLAND_DISPLAY xvfb-run -a -s "-screen 0 1600x1000x24" mvn -q clean package -Dcvescanner.windowTest=true
fi
echo "ci: xvfb-run not found, the window test left out (sudo apt install xvfb)" >&2
exec mvn -q clean package
