# Changelog

What each version brought, newest first. The GitHub Releases carry the same notes with the downloads and their
checksums.

## 1.5 — 2026-11-22

- **The dependency tree**: each dependency knows the packages that bring it, from Maven's and Gradle's walks and from
  `package-lock.json` (v2, v3), `yarn.lock` (v1, berry), `pnpm-lock.yaml`, `poetry.lock` and `uv.lock`, each package
  under its nearest path. Checked against `npm ls`, `pnpm list`, `mvn dependency:tree` and `gradle dependencies`. The
  window's new **Dependencies** tab shows each file's tree with the worst finding of each dependency;
  **`dependencies.csv`** puts it in a spreadsheet, a row per dependency with its depth and its path
  (`jackson-dataformat-yaml 2.14.2 > snakeyaml 1.33`). Gradle's lockfile, `Pipfile.lock` and npm's v1 lockfile do not
  record what brings a package: their indirect ones are listed apart, with no depth.

- **Direct dependencies only**: `--direct-only` (the old `--no-transitive` its alias) and the toolbar's box scan what
  the projects declare, at their locked versions: no Maven repository nor Gradle cache read, the lockfiles' indirect
  packages left out. It replaces *View ▸ Transitive dependencies*. After a full scan, **Hide indirect dependencies**
  (`--hide-transitive`) leaves them out of the tables, the counts and the reports.

- **Fixed**: in a `yarn.lock` or `pnpm-lock.yaml`, another version of a declared package (debug 2.6.9 under express,
  debug 4.3.1 declared) was said direct; yarn berry's entry of the project itself was listed as a package.

- **Fixed**: a Python package is matched against the CVE List by its pypi.org registry and its PEP 503 name (`Foo_Bar`
  is `foo-bar`); it was matched only when the record named no registry. An SBOM's `pkg:pypi` components are checked as
  Python packages, no longer as components off-the-shelf by their name. In the `pnpm-lock.yaml` of pnpm 6 and 7
  (lockfile 5.x), a package with peers is read at its version (`18.2.0_react@18.2.0` was unresolved), and Apply fixes
  reads the range a dependent installed with its peers asks.

- **Gradle transitive dependencies**: a build's `gradle.lockfile` gives the versions Gradle resolved, the transitive
  ones included; a build without one gets them from the poms of Gradle's cache, resolved as Gradle does (the highest
  version asked wins, a declared one raised; `platform()` and `enforcedPlatform()`; `exclude` blocks; catalog
  entries followed from the line using them). Version-less declarations a platform gives a version to are now read.
  `--gradle-cache DIR`; `--direct-only` turns off Gradle's cache with Maven's.
  Checked against `gradle dependencies`.

- **Apply fixes for transitive Maven dependencies**: one the project has only through a library is pinned, its fixed
  version added to the `dependencyManagement` of the module's topmost pom, then the pom read by Maven offline; applied
  only once ticked. Decided per declaration: one a declared pom of its chain governs follows that one's upgrade. Checked
  with the real Maven by `scripts/fix-tools-check.sh` (snakeyaml through jackson-dataformat-yaml).

- **Python projects**: `requirements*.txt` (its `-r` includes followed), `pyproject.toml` (PEP 621, Poetry) and
  `Pipfile`, with their lockfiles `poetry.lock`, `uv.lock` and `Pipfile.lock`, whose versions win, the declared
  packages direct, the others transitive. A pinned version is exact; a range is checked at its lowest (≈); a URL, a
  path or a VCS source is listed among the unchecked. A virtual environment (a folder holding `pyvenv.cfg`) is passed
  over.

- **Scans that read the databases once**: each database file's records for the package names scanned are kept
  between scans in `cache/` beside the program, the zip read again only when it changes or a scan meets a name not
  covered yet. The examples against the full OSV and NVD exports: about 100 seconds, then 1.4 seconds, the same
  findings. `--cache-dir DIR`, `--no-cache`.

## 1.4 — 2026-11-22

- **Apply fixes for transitive npm packages**: a package the project has only through others is overridden, its
  vulnerable version only — npm's `overrides` under each dependent using it (npm 10 and 11), pnpm's in
  `pnpm-workspace.yaml`, yarn 4's `resolutions` by the ranges asked; yarn 1, which overrides every copy, only when the
  lockfile holds no other version. An override the tool ignores (its lockfile unchanged) is not applied, and said. A fix outside what a
  dependent asks (read from the lockfile; for pnpm from the installed dependents) is applied only once ticked. Checked
  with the real npm, yarn 1, yarn 4 and pnpm by `scripts/fix-tools-check.sh`, on Linux and Windows.
- **Maven transitive dependencies**: what a project's dependencies bring is checked too, resolved as Maven does (the
  nearest version, the widest scope, the project's dependency management, BOM imports, exclusions; optional, test and
  provided ones not followed) from the poms of the local Maven repository, a sibling module's from its own pom; shown
  `transitive via` the dependency declared. A pom not in the repository is said in one warning. A version an
  external parent or an imported BOM manages is now resolved too. `--maven-repo DIR`, `--no-transitive`, *View ▸
  Maven transitive dependencies*. Checked against `mvn dependency:list` on a Spring Boot project: the same 85
  dependencies, versions and scopes.
- **The README's pictures taken again**, in English and in French (`docs/images/fr`), with one of a VEX document; by
  `scripts/screenshots.sh`, the window driven on a virtual display (`ScreenshotsTest`).
- **A language chosen in the window** measures its drop-down lists again: a French label is no longer cut short.
- **The window tested on every build**: `WindowChecklistTest` starts the window and clicks it through on a virtual
  display (a scan, the packages ticked and the plan of Apply fixes, an installed product, a VEX document, the database
  age, French), in `scripts/ci.sh` and the build workflow; `scripts/window-check.sh` runs it alone.

## 1.3 — 2026-11-22

- **A CycloneDX SBOM** beside the reports, `bom.cdx.json` (CycloneDX 1.6): every dependency by its package URL, a
  component off-the-shelf with its CPE, and every finding with its base and environmental ratings and its fix; the
  findings the ignore file sets aside are analysed `not_affected`, with the entry's reason.
- **A database's age**: each report says the date of each database's newest record, and a scan warns of one older than
  30 days (`--db-max-age DAYS`, *View ▸ Database age…*; 0: never).
- **Jars without Maven coordinates**, in an installed product, are checked by their name: every group's advisories for
  their artifactId, those of the group their OSGi name belongs to as their own, the others as *Jar name match ⚠*,
  which *Hide name matches* and `--hide-name-matches` leave out.
- **VEX documents**: a CycloneDX VEX document's `not_affected` and `false_positive` statements set their findings
  aside, said in the Ignored tab and the reports with the document; `in_triage` and `exploitable` are shown with the
  finding. Read from the folder's `*.vex.json`, `--vex FILE`, and the window's *VEX documents* row.
- **The ignore file from the command line**: `--ignore-add ID --reason … [--package] [--version] [--until]`,
  `--ignore-remove ID`, `--ignore-list`, without a scan.
- **Apply fixes, checked with the real npm, yarn 1, yarn 4, pnpm and Gradle** (`scripts/fix-tools-check.sh`, run on
  Linux and Windows by a workflow). A version is written as the project wrote it: npm no longer turns an exact version
  into `^`; yarn 1 keeps `^` (on Linux; on Windows it pins, a caret not reaching it intact through `cmd.exe`) and `~`;
  pnpm and yarn 4, which resolve no range offline, pin the version; each pin is said in the plan. Gradle's and npm's
  caches are found where `GRADLE_USER_HOME` and npm's configuration put them: `npm_config_cache`, or the `cache` an
  npmrc names (the user's, the global one, npm's own), read as npm reads them, without starting npm.

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
