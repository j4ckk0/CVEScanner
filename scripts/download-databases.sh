#!/usr/bin/env bash
#
# The databases downloaded into the project's database/, which scripts/run.sh loads: the distribution's
# download-databases.sh (cvescanner-app/src/dist), with --dir database; its arguments go to it (--help).
#
#   scripts/download-databases.sh                # asks, then the GitHub Advisory Database and NVD's CVE feeds
#   scripts/download-databases.sh all --accept   # every database, no question asked
#
set -euo pipefail
root=$(dirname "$(readlink -f "$0")")/..
exec "$root/cvescanner-app/src/dist/download-databases.sh" --dir "$(readlink -f "$root")/database" "$@"
