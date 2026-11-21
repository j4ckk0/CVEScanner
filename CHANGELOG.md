# Changelog

What each version brought, newest first. The GitHub Releases carry the same notes with the downloads and their
checksums.

## 1.0 — 2026-11-21

The first version as a project of its own, from the single-file prototype it was.

- **Which known vulnerabilities apply to your projects**: every `pom.xml`, Gradle build file (and version catalog) and
  `package.json` of a folder, their declared dependencies — and with a lockfile npm's transitive ones — checked against
  the GitHub Advisory Database, the CVE List or OSV.dev's exports, given as the zip files you download.
- **A table to filter, search and sort**, by severity, ecosystem, CVE, match; the packages to upgrade and to which
  version; the dependencies that could not be checked, and why.
- **CVSS 3.x and 4.0 scores, base and environmental**: presets for where the software runs (internet-facing, internal,
  air-gapped, developer workstation) or values of your own; the severity, the filters and the reports follow.
- **Reports**: `report.md` to read, `findings.csv` and `findings.json` for programs; a command line for CI, its exit
  code past `--fail-on`.
- **Never reaches the network**: no download, no browser, nothing of a database read as HTML; checked at every build.
- **French and English**, the window, the command line and `report.md`; FlatLaf's looks, light and dark.
- **Nothing to install**: the Windows and Linux archives carry their own Java runtime.
- **Examples to scan first**: a Maven, a Gradle, an npm and a yarn project declaring real packages at vulnerable
  versions (Log4Shell, Text4Shell, Spring4Shell, lodash…), and what a scan finds in them.
