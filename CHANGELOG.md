# Changelog

What each version brought, newest first. The GitHub Releases carry the same notes with the downloads and their
checksums.

## 1.2 — 2026-11-21

- **Everything from the command line too**: the window's filters (`--min-severity`, `--ecosystem`, `--hide-approximate`,
  `--hide-name-matches`, `--search`), applied to the reports, the counts and `--fail-on`; and its *Apply fixes*
  (`--apply-fixes`, a dry run until `--yes`, `--allow-major`, `--fix-packages`), exit code 3 when a confirmed fix
  could not be applied. The window and the command line filter by one same rule.
- **Installed products**: *Installed product* in the window, `--installed` on the command line, scans what an
  installation ships rather than source projects: each jar's Maven coordinates (`pom.properties`), the jars inside fat
  jars, WARs and EARs (`app.war!/WEB-INF/lib/x.jar`), the installed `node_modules`, the Python packages of a
  `site-packages` (a new **PyPI** ecosystem, with OSV's PyPI export), and the version strings native libraries hold
  (`libgdal.so.30` now gets a version).
- **Apply fixes**: tick the packages to upgrade in *Packages to upgrade*, then *Apply fixes…*. Each upgrade is made
  by the project's own build tool, offline: `mvn versions:use-dep-version` / `versions:set-property`, the Gradle file
  edited then checked by Gradle, `npm install`, `yarn add` / `yarn up`, `pnpm add`. Nothing is installed: a missing
  tool means the fix is not applied. A fix is not applied either when its version needs a newer Java or Node than the
  project targets, or when that cannot be checked offline; a major version change is applied only once confirmed. The
  commands are shown first, the files put back if a step fails, the folder scanned again after.
- **An ignore file for reviewed findings**: `cvescanner-ignore.csv` at the root of the folder scanned (or `--ignore
  FILE`; `--no-ignore` reads none) sets findings aside by CVE or advisory, package and version, with a reason and, if
  you want, a last day. They leave the counters, `findings.csv` and `--fail-on`, and are listed apart in an **Ignored**
  tab and in `report.md` and `findings.json`, with the entries past their date and those naming nothing. In the window,
  right-click a finding, **Ignore this finding…**; **Stop ignoring** takes it back.

## 1.1 — 2026-11-21

- **Components off-the-shelf**: GDAL, FFmpeg, OpenSSL, zlib, curl, SQLite… checked against NVD's CVE feeds (and the
  CVE List) by their CPE, vendor, product and version ranges. CVEScanner finds them four ways: a `cots.csv` inventory,
  an SBOM (CycloneDX, SPDX; its Maven and npm packages checked as such), a C/C++ build manifest (pkg-config, vcpkg,
  Conan), a binary (a DLL's version resource, or its file name). NVD's yearly feeds are read a record at a time.
- The fix of a flavoured version in its own flavour (Guava 32.0.0-jre, not -android); a package under an `npm:` alias
  in a yarn.lock is a direct dependency.
- The window: clearer column headers (Base score, Environment score, CVSS version), more room, tables scrolling
  sideways.
- `examples/cots-app`, and what NVD's real feeds find in it.

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
