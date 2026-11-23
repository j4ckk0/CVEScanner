#!/usr/bin/env bash
#
# Download the vulnerability databases CVEScanner reads into the database folder beside this script, which the
# program loads at each start, or into the folder --dir names (a USB stick's, for a computer without internet
# access). It asks before reaching the internet; --accept downloads without asking. CVEScanner itself never reaches
# the network: this script, apart from it, is the one that does.
#
#   ./download-databases.sh                     # the GitHub Advisory Database and NVD's CVE feeds
#   ./download-databases.sh all                 # every database below
#   ./download-databases.sh osv cvelist         # only these
#   ./download-databases.sh --dir /media/usb/database ghsa
#   ./download-databases.sh --accept            # no question asked (a scheduled update)
#   ./download-databases.sh --dry-run all       # what it would download, the internet not reached
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
here=$(dirname "$(readlink -f "$0")")

dir=$here/database
dry=false
accept=false
ghsa=false osv=false nvd=false cvelist=false
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || { echo "--dir needs a folder" >&2; exit 2; }; dir=$2; shift 2 ;;
    --accept) accept=true; shift ;;
    --dry-run) dry=true; shift ;;
    -h|--help) sed -n '3,/^[^#]/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    ghsa) ghsa=true; shift ;;
    osv) osv=true; shift ;;
    nvd) nvd=true; shift ;;
    cvelist) cvelist=true; shift ;;
    all) ghsa=true; osv=true; nvd=true; cvelist=true; shift ;;
    *) echo "unknown argument $1 (ghsa, osv, nvd, cvelist, all, --dir DIR, --accept, --dry-run)" >&2; exit 2 ;;
  esac
done
$ghsa || $osv || $nvd || $cvelist || { ghsa=true; nvd=true; }
year=$(date +%Y)

if $dry; then
  $ghsa && echo "https://github.com/github/advisory-database/archive/refs/heads/main.zip -> $dir/advisory-database-main.zip"
  if $osv; then for e in Maven npm PyPI; do echo "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip -> $dir/$e-all.zip"; done; fi
  if $nvd; then for y in $(seq 2002 "$year") modified; do echo "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.zip -> $dir/nvdcve-2.0-$y.json.zip"; done; fi
  $cvelist && echo "the newest release of https://github.com/CVEProject/cvelistV5/releases -> $dir/YYYY-MM-DD_all_CVEs_at_midnight.zip.zip"
  exit 0
fi
command -v curl >/dev/null || { echo "curl not found in PATH" >&2; exit 1; }

# Asked first: what is downloaded, from where, how much.
echo "This downloads from the internet, into $dir:"
$ghsa    && printf "  %-35s from %-44s about %s\n" "the GitHub Advisory Database" "github.com" "500 MB"
$osv     && printf "  %-35s from %-44s about %s\n" "OSV.dev's Maven, npm, PyPI exports" "osv-vulnerabilities.storage.googleapis.com" "270 MB"
$nvd     && printf "  %-35s from %-44s about %s\n" "NVD's CVE feeds, 2002 to $year" "nvd.nist.gov" "220 MB"
$cvelist && printf "  %-35s from %-44s about %s\n" "the CVE List's newest release" "github.com (api.github.com to find it)" "650 MB"
echo "Files the servers have not changed since the last download are not downloaded again."
if ! $accept; then
  [ -t 0 ] || { echo "No one to ask (not run in a terminal): --accept downloads without asking." >&2; exit 1; }
  read -r -p "Download? [y/N] " answer
  case "$answer" in
    [yY]|[yY][eE][sS]|[oO]|[oO][uU][iI]) ;;
    *) echo "Nothing downloaded."; exit 0 ;;
  esac
fi
mkdir -p "$dir"

progress=(-sS)
[ -t 1 ] && progress=(--progress-bar)
failed=0

# get NAME URL: DIR/NAME downloaded, unless the server has not changed it since the copy there
get() {
  local name=$1 url=$2 file="$dir/$1" part="$dir/$1.part"
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

if $ghsa; then get advisory-database-main.zip https://github.com/github/advisory-database/archive/refs/heads/main.zip || true; fi
if $osv; then
  for e in Maven npm PyPI; do get "$e-all.zip" "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip" || true; done
fi
if $nvd; then
  for y in $(seq 2002 "$year") modified; do
    get "nvdcve-2.0-$y.json.zip" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.zip" || true
  done
fi
if $cvelist; then
  # the newest release's asset of the whole list (not its _delta_ files), named by its day
  url=$(curl -fsSL https://api.github.com/repos/CVEProject/cvelistV5/releases/latest \
          | grep -o '"browser_download_url": *"[^"]*_all_CVEs_at_midnight\.zip\.zip"' | head -1 | sed 's/.*"\(http[^"]*\)"$/\1/') || true
  if [ -z "${url:-}" ]; then
    echo "   the CVE List's newest release not found (https://github.com/CVEProject/cvelistV5/releases)" >&2
    failed=$((failed + 1))
  else
    name=${url##*/}
    if get "$name" "$url"; then
      # the older days' lists: the new one replaces them
      for old in "$dir"/*_all_CVEs_at_midnight.zip.zip; do
        if [ -f "$old" ] && [ "${old##*/}" != "$name" ]; then rm -f "$old"; echo "   removed the older ${old##*/}"; fi
      done
    fi
  fi
fi

echo
echo "In $(readlink -f "$dir"):"
ls -lh "$dir" | sed -n '2,$p' | grep -v '\.part$' || true
[ "$failed" -eq 0 ] || { echo "$failed download(s) failed: run the script again" >&2; exit 1; }
