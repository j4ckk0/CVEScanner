#!/usr/bin/env bash
#
# Download the vulnerability databases CVEScanner reads, on a computer with internet access, into database/ (the
# project's, which scripts/run.sh loads) or the folder --dir names: then copy them beside the program, into its
# database folder, on the computer that scans. The program itself never reaches the network; this script does.
#
#   scripts/download-databases.sh                     # the GitHub Advisory Database and NVD's CVE feeds
#   scripts/download-databases.sh all                 # every database below
#   scripts/download-databases.sh osv cvelist         # only these
#   scripts/download-databases.sh --dir /media/usb/database ghsa
#   scripts/download-databases.sh --dry-run all       # prints what it would download
#
#   ghsa      advisory-database-main.zip, the GitHub Advisory Database (recommended; about 500 MB)
#   osv       Maven-all.zip, npm-all.zip, PyPI-all.zip: OSV.dev's exports (about 270 MB together)
#   nvd       nvdcve-2.0-YYYY.json.zip from 2002 to this year, and nvdcve-2.0-modified.json.zip: NVD's CVE feeds,
#             for the components off-the-shelf (about 220 MB together)
#   cvelist   YYYY-MM-DD_all_CVEs_at_midnight.zip.zip, the CVE List's newest release (about 650 MB)
#
# Run it again to update: a file the server has not changed since is not downloaded again, and a newer CVE List
# replaces the older one. Each file is written beside its final name first, so that an interrupted download leaves
# the previous file whole. Needs curl.
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."   # the project root

dir=database
dry=false
sets=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || { echo "--dir needs a folder" >&2; exit 2; }; dir=$2; shift 2 ;;
    --dry-run) dry=true; shift ;;
    -h|--help) sed -n '3,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    ghsa|osv|nvd|cvelist) sets+=("$1"); shift ;;
    all) sets+=(ghsa osv nvd cvelist); shift ;;
    *) echo "unknown argument $1 (ghsa, osv, nvd, cvelist, all, --dir DIR, --dry-run)" >&2; exit 2 ;;
  esac
done
[ ${#sets[@]} -gt 0 ] || sets=(ghsa nvd)
command -v curl >/dev/null || { echo "curl not found in PATH" >&2; exit 1; }
$dry || mkdir -p "$dir"

progress=(-sS)
[ -t 1 ] && progress=(--progress-bar)
failed=0

# get NAME URL: DIR/NAME downloaded, unless the server has not changed it since the copy there
get() {
  local name=$1 url=$2 file="$dir/$1" part="$dir/$1.part"
  if $dry; then echo "$url -> $file"; return 0; fi
  local since=()
  [ -f "$file" ] && since=(-z "$file")
  echo "== $name"
  rm -f "$part"
  if ! curl -fL --retry 3 --remote-time ${since[@]+"${since[@]}"} "${progress[@]}" -o "$part" "$url"; then
    echo "   failed: $url" >&2
    rm -f "$part"
    failed=$((failed + 1))
    return 1
  fi
  if [ -s "$part" ]; then
    mv -f "$part" "$file"
  else
    rm -f "$part"
    echo "   unchanged"
  fi
}

for set in "${sets[@]}"; do
  case $set in
    ghsa)
      get advisory-database-main.zip https://github.com/github/advisory-database/archive/refs/heads/main.zip || true ;;
    osv)
      for e in Maven npm PyPI; do get "$e-all.zip" "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip" || true; done ;;
    nvd)
      for y in $(seq 2002 "$(date +%Y)") modified; do
        get "nvdcve-2.0-$y.json.zip" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.zip" || true
      done ;;
    cvelist)
      # the newest release's asset of the whole list (not its _delta_ files), named by its day
      url=$(curl -fsSL https://api.github.com/repos/CVEProject/cvelistV5/releases/latest \
              | grep -o '"browser_download_url": *"[^"]*_all_CVEs_at_midnight\.zip\.zip"' | head -1 | sed 's/.*"\(http[^"]*\)"$/\1/') || true
      if [ -z "${url:-}" ]; then
        echo "   the CVE List's newest release not found (https://github.com/CVEProject/cvelistV5/releases)" >&2
        failed=$((failed + 1))
      else
        name=${url##*/}
        if get "$name" "$url" && ! $dry; then
          # the older days' lists: the new one replaces them
          for old in "$dir"/*_all_CVEs_at_midnight.zip.zip; do
            [ -f "$old" ] && [ "${old##*/}" != "$name" ] && { rm -f "$old"; echo "   removed the older ${old##*/}"; }
          done
        fi
      fi ;;
  esac
done

$dry && exit 0
echo
echo "In $(readlink -f "$dir"):"
ls -lh "$dir" | sed -n '2,$p' | grep -v '\.part$' || true
[ "$failed" -eq 0 ] || { echo "$failed download(s) failed: run the script again" >&2; exit 1; }
