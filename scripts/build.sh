#!/usr/bin/env bash
#
# Build the modules (the scan, the program) and cvescanner-app/target/cvescanner.jar, the
# program (compile + tests).
#
#   scripts/build.sh
#   scripts/build.sh -DskipTests        # extra arguments are passed to mvn
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."   # the project root
. scripts/externals.sh   # setup done? (offers it otherwise); the externals first
running_instance "building"
take_build_lock
exec mvn clean package "$@"
