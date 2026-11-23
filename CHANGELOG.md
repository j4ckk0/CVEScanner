# Changelog

What each version brought, newest first. The GitHub Releases carry the same notes with the downloads and their
checksums.

## Unreleased

- **`download-databases.sh`** (Linux) and **`download-databases.bat`** (Windows), beside the program in the
  archives: download the databases into its `database` folder, or the folder `--dir` names. They say what they will
  download, from where and how much, and ask before reaching the internet; `--accept` downloads without asking. The
  GitHub Advisory Database and NVD's feeds by default, or those named (`ghsa`, `osv`, `nvd`, `cvelist`, `all`); run
  again, only what the servers have changed. The program itself still never reaches the network.
- From a clone, `scripts/download-databases.sh` and `.bat` download into the project's `database/`, which
  `scripts/run.sh` and `.bat` now load, as the launchers load theirs.

## 1.10 — 2026-11-23

- **The databases in a list with tick boxes**: *Choose databases ▾* drops down every database zip known (those of
  the `database` folder, those named with `--db`, those added in the window), each listed once. A scan reads the
  ticked ones; an unticked zip stays in the list, unticked at the next start too. *Add database zips…* lists others,
  ticked, and a zip listed already is ticked rather than listed twice; × removes one added in the window; *Tick all*
  and *Untick all*. The field names the zips ticked, their paths in its tooltip. What is added or unticked is kept
  even when the `database` folder holds zips, where the zips chosen used to be forgotten at the next start.
- The help of the command line, its examples, the manual and the README say how to read several databases at once
  (`--db` repeated, `--db-dir`).

## 1.9 — 2026-11-23

- **An analysis moved to another computer**: *File ▸ Export analysis…* (or `--export-analysis FILE`) keeps the scan
  in a `.cvescan` file: its dependencies, the findings with their CVSS vectors, the ignore entries and VEX statements,
  the databases read. On a computer that cannot reach the folder, *File ▸ Open analysis…* (or dropping the file, or
  `cvescanner.sh FILE.cvescan`) shows it as it was scanned, with no database; **Re-check** (Scan, the file in the
  folder field; `--from-analysis FILE` on the command line) matches its dependencies against that computer's
  databases. `--as-scanned` writes the reports from its findings as they were. *Apply fixes* and *Ignore this
  finding…* wait for the projects themselves, or for an ignore file chosen there.
- **Examples of command lines** at the end of `--help`, of *Help ▸ Command line…* and of the manual: a folder with a
  database and a reports folder, every database of a folder, a CI job, an installed product, an analysis carried
  from one computer to another.
- The README's pictures show the window as it is after a scan, its settings collapsed.

## 1.8 — 2026-11-22

- After the welcome the settings are **collapsed at each start**, whatever was chosen the time before; ▾ shows them
  for the session.
- **`findings.csv` in the window's order**: its columns are those of the findings table, in its order and under its
  English names (Package, Version, Vulnerabilities, CVE, Severity, CVSS base score, Environment score, CVSS version,
  Fixed in, Published, Summary, Advisory, Ecosystem, Upgrade to, Match, Scope, Path, File), then Base severity, CVSS
  base vector, Environment vector, Environment, Approximate, URL. Published, Path, Vulnerabilities and Upgrade to are
  new. **A script reading the file by its old headers (`severity`, `package`, `fixed_in`…) needs them changed.**
- **A warning when no database covers an ecosystem found**: the Maven, npm or PyPI packages with NVD's feeds alone,
  the components off-the-shelf with the advisories alone, are said unchecked, in the window's status line ("⚠ no
  database for Maven, npm: not checked"), on the command line and in the reports.
- The welcome shows the **environment** line too, to be chosen before the first scan; the search, the filters and the
  counters still come with the findings.

## 1.7.2 — 2026-11-22

- The window's *Base score* is named **CVSS base score** (*Score CVSS de base*): the findings' column, the details,
  the header's tooltip, the environment's help.
- **Fixed**: *Clear the preferences* leaves an empty file, so that an older `cvescanner.properties` beside the program
  is not taken over again at the next start.
- The README, the examples' README, the manual (`cvescanner.1`) and the database folder's README checked against
  the program and corrected where they had fallen behind it.

## 1.7.1 — 2026-11-22

1.7 was tagged but not published: its Linux archive failed to build. 1.7.1 is 1.7 with that fixed.

- **Fixed**: the Linux archive is built again (the descriptor of its files, which names the new manual, did not read).

- **Scan waits for what it needs**: on the welcome and in the toolbar, *Scan* is greyed until a folder to analyze and a
  database are given, their fields outlined in red until then.
- **The preferences in your own folder**: the folder analyzed last, the databases and the window's settings are kept
  in `~/.config/cvescanner` (Linux) or `%APPDATA%\CVEScanner` (Windows), no longer beside the program (that file is
  taken over once); *Help ▸ Preferences folder…* says where, copies the path and clears them. The databases' index
  stays in `cache/` beside the program.
- **The command line's help**: *Help ▸ Command line…* in the window lists every option; `cvescanner.bat --help`
  (`-h`, `/?`) prints them in its console, as `cvescanner-cli.bat --help` (or `/?`) and `cvescanner.sh --help` do;
  on Linux, `cvescanner.sh --man` shows the manual, `cvescanner.1`, shipped beside the program.

- **Findings and Packages to upgrade in one tab**: the findings grouped by package version, a row each in bold with
  its worst severity, the version fixing all its findings (*Upgrade to*), its tick for *Apply fixes* and how many
  advisories it has; ▸ (a click, →) opens its findings below it, ← closes it, a search opens them all. A click on a
  header sorts, each package keeping its findings; the line beside the counters says how many package versions hold the
  findings shown. Its columns: the package, its version, how many advisories, the CVE, the severity, the base and
  environment scores, the CVSS version, the fixed version, the date published, the summary, the advisory, then the
  tick, the ecosystem, the version to upgrade to, the match, the scope, the path, the file.
- **Filters in the column headers**: in the findings table, a ▾ at the right of each header lists the column's values
  to tick, as a spreadsheet filters; a filtered column's ▾ is drawn in colour, and *Clear filters* clears them too.
- **Path**, a new column of the findings: the folder of the file a finding comes from (`maven-webapp/service`), to
  sort, search and filter by project.
- The **Dependencies** tab names each file's ecosystem (`pom.xml · Maven`).
- The severity box is gone from the filters: the coloured counters set the lowest severity shown, for the findings
  and their export, as it did.
- Every column of the tables can be narrowed or widened by hand; a header's ▾ is drawn inside its own column.
- **The settings collapse**: once the first scan's findings are shown, the databases, the scan and the environment
  rows are collapsed to the folder's row, and the findings' table shows 8 rows, the details having the rest; ▾ at the
  end of the folder's row shows the settings again, ▴ collapses them, and the choice is kept.
- `samples/db/examples.zip`: made-up advisories for every vulnerable package of the examples, so that each shows its
  findings when the program runs from the repository without a real database.

## 1.6.1 — 2026-11-22

- The first field of the window is *Folder to analyze* (*Dossier à analyser*), no longer *Project folder*.
- Before the first scan, the welcome alone below the toolbar: the environment, the search, the filters and the counters
  come with the findings.

## 1.6 — 2026-11-22

- **Standard and expert modes** (*View ▸ Mode*): standard, the first time, leaves out the *Ignore file* and *VEX
  documents* rows and the CVSS version's choice, and scans with their defaults (the folder's own ignore file and
  `*.vex.json`, CVSS 4.0 first); expert shows them and gets back what was chosen. Switching scans again when the files
  read change.
- **The search and the filters apart**: the search on a row of its own, the severity, the ecosystem and the boxes on
  the next, under *Filters*.
- **A more modern window**: rounder controls, striped tables, *Scan* in the accent colour; severities as coloured
  pills; the counters as pills, filled for the severities shown, a click on the lowest filled one showing them all
  again; the details in cards (Fix, Scores, References, Description) with buttons above them for the right-click
  menus' actions (copy the advisory link, the CVEs, the package; ignore, stop ignoring).
- **Easier to begin**: until the first scan, the steps where the tables will be, with *Scan* and *Try the examples*;
  a folder dropped on the window is scanned; the ▾ beside the folder lists the last eight scanned. In standard mode the
  environment is one choice with *Customise…* for the reach and the requirements.
- *Scan:* on a toolbar row of its own: the scan mode and *Direct dependencies only*.

## 1.5.2 — 2026-11-22

- **Fixed**: a jar whose file name gives no version (`commons-lang3.jar`) is checked by its file name and its
  manifest's version (`Implementation-Version`, else `Bundle-Version`); it was only said unchecked.
- **Fixed**, in *Apply fixes* for npm: a pre-release (`1.2.4-beta`) is within a range only when the range names a
  pre-release of the same version, as npm has it; `^1.2.3` took it.
- **Fixed**: a fix in a numbered pre-release (`2.0-beta1`, `2.0-rc.2`) is no longer preferred for a version in the same
  one: `1.1` is the fix for `1.0-beta1`, not `2.0-beta1`.
- **Fixed**: a `cots.csv` line whose CPE names no vendor or no product is said unchecked, with why; it was checked as
  an empty name.

## 1.5.1 — 2026-11-22

1.5 was tagged but not published: its Windows build failed. 1.5.1 is 1.5 with that fixed.

- **Fixed, on Windows**: a damaged file of the databases' index cache is written again (it stayed open, and Windows
  refused to replace it: the zip was read again at every scan).

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
