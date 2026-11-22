# Architecture review — CVEScanner

Reviewed 70 main source files (7,200 lines) across `cvescanner-core` (12 packages) and `cvescanner-app` (1 package),
by measuring every file's size and every package-to-package import, then reading:
- the largest files: `MainWindow`, `Reports`, `Cvss`, `VulnDb`, `CveList`, `MavenScanner`;
- the most-depended-on files: `model/*`, `Engine`, `ProjectFiles`, `Collector`.

Not covered in depth: the body of each format reader (`GradleScanner`, `NpmScanner`, the `cots/*` readers, `Osv`,
`NvdFeed`) beyond their signatures and dependencies; tests and scripts (their comments are reviewed separately).

## Verdict

A new developer finds their way quickly in the core. The packages are cut by concern (`db` for the databases, `cots`
for components, `cvss` for scoring, `report` for output, `i18n` for languages), the names are specific (`NvdFeed`,
`JsonStream`, `PeVersionInfo`, `KnownProducts`), and only one file is over 400 lines.

Two things get in the way:
- **`MainWindow`, 1,244 lines with seven responsibilities.** It is where every window change starts, and the reader
  has lost track long before the end.
- **The ecosystem as a raw string.** `"Maven"`, `"npm"` and `"COTS"` appear 33 times in 12 files. Adding the next
  ecosystem (Python and .NET are on the list) means changing about eight places that nothing ties together.

## What's working

- **Core and app split with a hard rule.** The core needs only the JDK (`java.xml`); the window only presents. Keep
  this boundary.
- **Packages by concern, one reader per format.** `cots/{InventoryReader, SbomReader, ManifestReader, BinaryReader}`
  and `db/{Osv, CveList, NvdFeed}` each read one thing. Where a file format lives is predictable.
- **`cvss` is self-contained math** with its own reference test, and `json` is a small, dependency-free parser plus
  its streaming twin.
- **Texts as data.** `Phrase` (a key plus its arguments) lets one finding be said in French, in English and in the
  machine formats without the core knowing about languages.
- **File sizes are disciplined.** Apart from `MainWindow`, the largest file is 373 lines and the median is about 100.
- **Safety is structural, not scattered.** `NoNetworkResolver`, `Gui.html` and `Gui.noHtml`, and the `Reports` escaping
  helpers each sit in one place, and a test guards each of them.

## Findings

### 1. `MainWindow` holds seven responsibilities in 1,244 lines

**Where:** `cvescanner-app/.../MainWindow.java`. Its own section banners already mark the seams:
- column definitions and table setup: lines 131–175 and 677–838;
- menus and language: 330–412;
- toolbar and control bars: 412–575;
- environment and scoring state: 529–651;
- filtering: 840–933;
- scanning: 934–1050;
- the ignore file: 1084–1197;
- export and clipboard: 1198–1244.

**Why it costs:** a maintainer adding a column, a filter or a menu item must load the whole window to find the five
lines that matter. The four tables' columns, renderers, popups and sorters are mixed with scanning and file writing.
Most edits touch this file, so merge conflicts concentrate here.

**Proposed change:** extract three package-private classes. Each has an obvious seam and a narrow interface back to
the window.
- **`FindingTables`**: the four column lists, `configureTables`, `setup`, the renderers and the two popup menus, about
  260 lines. It exposes the tables, their models and sorters, `selectedFinding()` and `selectedIgnored()`.
- **`EnvironmentBar`**: `environmentBar`, `setEnvironment`, `syncEnvironmentControls`, and restoring and saving the
  scoring choice, about 130 lines. It exposes `environment()`, `preferV4()` and a change listener that the window
  answers with `rescore()`.
- **`IgnoreActions`**: `ignore`, `stopIgnoring`, `rereadIgnores`, `chooseIgnoreFile`, `setIgnoreChoice` and
  `updateIgnoreField`, about 115 lines. It needs a callback to re-split the findings and a way to report a status
  message.

What remains, the composition, scanning, filters, details and export, would be about 650 lines and could be stated in
one sentence: "the window that scans and shows the findings".

**Effort / risk:** medium. This is purely structural: the fields move along with their methods. There are no window
tests, so verify each extraction with the off-screen render of every tab.

### 2. The ecosystem has no type: 33 string literals in 12 files

**Where:**
- `"COTS"` is written out in `cots/InventoryReader`, `SbomReader`, `ManifestReader`, `BinaryReader` and
  `db/NvdFeed`, while `VulnDb.COTS` exists for the same value.
- `"Maven"` and `"npm"` appear in `project/*Scanner`, `version/Versions` and `db/CveList`.
- The app has its own copies in `MainWindow`'s ecosystem filter and its "copy coordinate" separator.
- `VulnDb.product(Dependency)` (vendor:product splitting) is defined in the database loader.
- `report/Reports` imports `db.VulnDb` only to read `VulnDb.COTS`.

**Why it costs:** the concept a reader most needs to follow, what kind of dependency this is, is invisible as a type.
A typo compiles. Adding Python means finding, by search, the version comparator, the OSV ecosystem name, the window's
filter, the reports' COTS note and the matcher branches. `report → db` is an edge that exists only because the
constant has no home.

**Proposed change:** an `enum Ecosystem { MAVEN("Maven"), NPM("npm"), COTS("COTS") }` in `model`. It carries the
display and OSV name, `versionComparator()`, and `coordinate(name, version)` (the `:` versus `@` the window builds by
hand). `Dependency.ecosystem` and `Finding.ecosystem` become `Ecosystem`, and the COTS helpers (`product()`) move
beside it.

The machine formats keep writing the same strings, so `findings.csv` and `findings.json` don't change and the golden
files stay green. Point that out in the commit.

**Effort / risk:** medium. About 40 call sites; the compiler finds them all. The risk is in the JSON and CSV writers
and the OSV reader, which must keep using the exact names; the golden tests cover both.

### 3. `Engine.scan` does five jobs, and its three matching loops repeat one pattern

**Where:** `engine/Engine.java:67–154`. In one 90-line method it:
1. loads the ignore file;
2. finds the files;
3. calls eight readers by hand;
4. loads the databases;
5. matches with three loops (OSV, NVD, CVE List) and counts files.

The NVD and CVE List loops are the same algorithm: skip covered CVEs, keep the best basis per CVE.

**Why it costs:** the matching rules (which database wins, how duplicates are removed) are the heart of the
program's correctness, but they are buried inline between file discovery and file counting. A maintainer changing
precedence has to read the whole scan.

**Proposed change:** extract **`engine/Matcher`** with `List<Finding> findings(Dependency, Index)`. It keeps the
precedence (advisories, then NVD, then CVE List) in one place, written once as "best basis per CVE, the sources in
order". `Engine.scan` then reads as the five steps.

**Effort / risk:** small to medium. The behaviour is pinned by the golden tests and `ExamplesTest`.

### 4. `Reports` mixes three output formats with a model aggregation the window also uses

**Where:**
- `report/Reports.java` holds `packages()` (grouping findings into `PackageSummary`), `markdown()`, `csv()`,
  `json()` and the escaping helpers.
- `MainWindow` calls `Reports.packages(...)` and `Reports.counts(...)` to fill its tab and chips.

**Why it costs:** a reader looking for "how are findings grouped by package" will not look in the report writer, and
the window depending on `Reports` for model logic reads as the UI depending on an exporter.

**Proposed change:**
- move `packages()` to `PackageSummary.of(List<Finding>)`, and `counts()` to `Severity.count(List<Finding>)` or a
  small `model` helper;
- optionally split the writers into `MarkdownReport`, `CsvReport` and `JsonReport`, with `Reports.writeAll` as the
  facade. The file is 373 lines, so this second split is optional; the first is the one that matters.

**Effort / risk:** small. Moving static methods is caught by the compiler.

### 5. Edges that point the wrong way, and two small cycles

**Where:**
- **`db → engine`:** `VulnDb.load` takes `engine.ScanListener` and formats with `Engine.STAMP`. The loader depends on
  its own orchestrator.
- **`report → engine`:** for `Engine.STAMP`.
- **`model ↔ cvss`:** `Finding` holds `cvss.Score`/`Rating`, while `cvss.Scoring` imports `model.Finding`.
- **`model ↔ ignore`:** `ScanResult` holds `Ignores`, while `IgnoredFinding` holds `model.Finding`.

**Why it costs:** the apparent rule is "engine orchestrates, everything else is below it; model is the bottom". These
edges break it, so a reader can't predict which way an import goes.

**Proposed change:**
- move `ScanListener` and the date format (`STAMP`, renamed `TIMESTAMP_UTC`) to a neutral spot: `model`, or a tiny
  `progress` package;
- move `Scoring` (applying an environment to findings) to `engine`, which leaves `cvss` a pure leaf;
- accept `model ↔ ignore` or move `ScanResult` to `engine`, which is where it is produced.

**Effort / risk:** small. These are import changes only.

### 6. "Scanner" and "Reader" name one role

**Where:**
- `project/{MavenScanner, GradleScanner, NpmScanner}` and `cots/{InventoryReader, SbomReader, ManifestReader,
  BinaryReader}` all do the same job: read files into a `Collector`.
- Their entry points differ: `scan(poms, col, warn)`, `scan(gradle, props, col)` plus `scanCatalogs(...)`,
  `scan(pkgJsons, root, col, warn)`, `scan(binaries, col)`.
- `Collector` itself is generic: it collects dependencies and the ones that couldn't be checked.

**Why it costs:** two words for one role makes a reader wonder whether a "Scanner" does more than a "Reader" (it
doesn't). The uneven signatures are why `Engine.scan` must call each by hand.

**Proposed change:**
- rename the three to `MavenReader`, `GradleReader` and `NpmReader` (the `cots` ones read files and don't walk
  anything);
- rename `Collector` to `DependencyCollector`.

A common interface is not worth it for eight readers with different inputs; the consistent names are the gain.

**Effort / risk:** small. Renames inside one module; check the test class names and `CLAUDE.md` too.

### 7. `MainWindow.show(ScanResult)` overloads `java.awt.Window.show()`

**Where:** `MainWindow.java:1029`.

**Why it costs:** `show` already means "make the window visible" on every `Window`. A reader seeing `show(get())` in
`startScan` thinks of visibility, not of filling the tables.

**Proposed change:** rename it `showResult`. It has one call site.

**Effort / risk:** small.

## Patterns

- **Generic helper names, 3 cases:**
  - `Gui`: safe text for Swing plus score formatting; it could be `SwingText`;
  - `VulnDb.accept(byte[], …)`: it classifies a record and indexes it, so `indexRecord`;
  - `MainWindow.item(key, action)`: it builds a menu item acting on the selected finding, so `findingItem`.
- **Static-only classes as namespaces** (`Reports`, `Engine`, `Cli`, the readers): this is consistent and fine. It is
  noted only because it makes findings 3 and 4 cheap: the methods move without any object wiring.
- **Comments:** reviewed separately with `review-code-comments`; see that report.

## Suggested order

1. **#7 `showResult`**, then **#6 the Reader names**: trivial renames that make the code read correctly right away.
2. **#5 the edge fixes**: import-only moves that restore a predictable layering before the bigger moves.
3. **#4 `PackageSummary.of` / `counts`**: this takes the window's dependency on `Reports` away, before splitting the
   window.
4. **#1 the `MainWindow` split**, one class per commit: `IgnoreActions` first (the newest code, the clearest seam),
   then `EnvironmentBar`, then `FindingTables`.
5. **#2 `Ecosystem`** and **#3 `Matcher`**: do these just before adding the next ecosystem. That is when they pay for
   themselves, and the golden tests keep them honest.

## Status — applied 2026-11-21

Every finding, one commit each, the CI green after each one. The examples against the real OSV and NVD data give the
same results before and after: 668 findings (181 critical, 356 high, 113 medium, 18 low).

Where the result differs from the proposal:
- **#5:** `Scoring` went to `model`, not `engine`. The database readers score their findings, so in `engine` it would
  have brought back a `db → engine` edge. `Severity` moved into `cvss`, which makes `cvss` a leaf. `ScanListener` and
  the timestamp format (`ScanResult.TIMESTAMP_UTC`) are in `model`. The `model ↔ ignore` cycle stays, as accepted.
- **#2:** the version order lives on the enum (`Ecosystem.compare`, `versionOrder`, `nearestFix`), and `Versions` keeps
  the ecosystem-free algorithms. Otherwise `model` and `version` would depend on each other.
- **#1:** `MainWindow` is 901 lines, not about 650: the toolbar, filters, scanning, details and export remain. It is
  under the 1,000-line mark; `FindingTables`, `EnvironmentBar` and `IgnoreActions` are about 200 lines each.
- **Patterns:** the three generic names were renamed too: `SwingText`, `VulnDb.indexRecord` and
  `MainWindow.findingItem`.

## Status — the window split further, 2026-11-22

`MainWindow` had grown back to 992 lines with Apply fixes and the VEX documents. Its parts moved out, one class each,
the window test (`WindowChecklistTest`) clicking the window through before and after:
- `DatabaseChoice` (the databases' row), `FilterBar` (the filters), `SummaryBar` (the severity chips and the count
  shown), `DetailsPane` (the details of the selection, per tab), `StatusLine` (the status line, its progress bar and
  tooltip), `ViewMenu` (the looks, the database age), `TableActions` (what a click, a double-click, a right-click
  does), `ExportAction` (File ▸ Export), `Clipboard`;
- the tables' filtering went into `FindingTables.filter`, beside the sorters it sets.

`MainWindow` is now 533 lines: the frame and its layout, the menu bar and the language, and the scan (start, result,
the findings refreshed for the environment and the ignore file).
