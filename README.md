# CVEScanner

[![build](https://github.com/j4ckk0/CVEScanner/actions/workflows/build.yml/badge.svg)](https://github.com/j4ckk0/CVEScanner/actions/workflows/build.yml)
[![Licence: Apache 2.0](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENSE)
![Java 25](https://img.shields.io/badge/Java-25-orange)
![Windows | Linux](https://img.shields.io/badge/runs%20on-Windows%20%7C%20Linux-lightgrey)

**Which known vulnerabilities apply to your Maven, Gradle and npm projects?** CVEScanner looks through a folder for
every `pom.xml`, Gradle build file and `package.json`, reads the dependencies they declare (and, with a lockfile, the
npm ones they pull in), and checks each against a vulnerability database you downloaded as zip files: the GitHub
Advisory Database, the CVE List, OSV.dev's exports. The findings are shown in a table you can filter, search and sort,
and written as reports (`report.md`, `findings.csv`, `findings.json`). Each has its CVSS base score and an
environmental score for where the software runs: internet-facing, internal network, air-gapped, developer
workstation, or values of your own.

It is a desktop program with a command line for CI, made for computers without internet access: it runs on its own —
each distribution carries its Java runtime — and it **never reaches the network** (see [No network](#no-network)). It
speaks French and English.

| | |
|---|---|
| You scan projects | [**The databases**](#the-databases), then [**The window**](#the-window) or [**The command line**](#the-command-line) |
| You read the results | [**Understanding the results**](#understanding-the-results) and [**CVSS scores and environments**](#cvss-scores-and-environments) |
| You want it on your machine | [**Build and run**](#build-and-run) and [**Packaging**](#packaging): self-contained archives for Windows and Linux |
| You read or change the code | [**Layout**](#layout) |
| Your security team asks | [**No network**](#no-network) |

## No network

The program reads the folder it scans and the database zips it is given, and writes its reports and its settings
beside it; that is all. No download, no update check, no browser, no file manager, no other program started: a link
is copied to the clipboard, to open elsewhere, and after an export the folder's path is offered to copy.

**No name lookup either, not even the JDK's own**: `NoNetworkResolver` takes the place of Java's name service and
answers every lookup as an unknown host. **A scanned project or a database cannot make it reach the network**: the
`pom.xml` parser refuses DTDs, external entities and XInclude; what a database writes (an advisory's summary, its
details, its links) is shown as text, never as HTML a window would fetch an image or a style sheet from, and only
`https://` links are kept, to copy. `NoNetworkTest` reads every class of the program and of FlatLaf, the one library
shipped, for what reaches the network, at every build; `HostileAdvisoryTest` and `PomParserTest` try the rest.

## The databases

Download one or more of these files on a computer with internet access, and give them to CVEScanner **without
extracting them**: drop them in the `database` folder beside the program (loaded at each start), or choose them in the
window, or name them with `--db`.

| Database | Download | Matches |
|---|---|---|
| GitHub Advisory Database (recommended) | <https://github.com/github/advisory-database/archive/refs/heads/main.zip> (`advisory-database-main.zip`, the same as *Code → Download ZIP*) | the exact Maven/npm package and its affected versions, with the CVE IDs |
| CVE List, the CVE Program's official list (optional) | <https://github.com/CVEProject/cvelistV5/releases>: the newest release's asset `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (about 500 MB, a zip in a zip); not the `_delta_` files | exact when the record names the package (**CVE record**); otherwise by product name, marked **CVE name match ⚠**, to check; some CVEs cannot be tied to a package at all (Log4Shell's record) |
| OSV.dev exports (optional) | `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` and `…/npm/all.zip` | as the GitHub Advisory Database |

When several are loaded, a CVE already covered by an advisory is reported once. To update, download fresh files and
delete the old ones; each report says which files, of which date, it used.

## The window

Start `cvescanner.bat` or `CVEScanner.exe` (Windows), `cvescanner.sh` (Linux); give it a folder to scan it at once.

1. **Project folder**: the folder of your project(s), its sub-folders scanned too.
2. **Vulnerability database**: the zips of `database/` are already there; *Choose database zip…* for others.
3. **Environment** (optional): where the scanned software runs, for the environmental score; changing it re-scores
   at once, without scanning again.
4. **Scan.** Reading a database takes from a few seconds to a minute or two, as its size.

The table sorts by any column and filters as you type: **Search** (every word must match, across the columns and the
aliases; Ctrl+F, Esc to clear), the **severity** (the coloured counters do the same), the **ecosystem**, *Only with
CVE ID*, *Hide approximate (≈) versions*, *Hide CVE name matches ⚠*. Its tabs: **Findings**, one row per
vulnerability and dependency, its details below (the fix, the scores, the match, the links); **Packages to upgrade**,
one row per package version with the version that fixes all its findings; **Unchecked dependencies**, those whose
version could not be known (an external BOM, a dynamic version like `1.+`), and why. A double-click or a right-click
copies the advisory's link, the CVEs, the package's coordinates. **Export…** writes the three reports for the rows
shown. *View ▸ Look* offers FlatLaf's looks, light and dark; the language is on the right of the menus. The choices are
kept in `cvescanner.properties`, beside the program.

## The command line

```
cvescanner.sh --no-gui -d /src/my-app --env airgapped --fail-on HIGH      (Linux)
cvescanner-cli.bat --no-gui -d C:\src\my-app --fail-on HIGH               (Windows)
```

| Option | |
|---|---|
| `-d DIR` | the folder to scan |
| `-o DIR` | the reports' folder (the launchers: `reports/` beside the program) |
| `--db FILE`, `--db-dir DIR` | a database zip (repeatable), every zip of a folder (the launchers: `database/`) |
| `--cve-only` | only the vulnerabilities that have a CVE ID |
| `--env PRESET` | `none` (default), `internet`, `internal`, `airgapped`, `devci` |
| `--reach R`, `--cr/--ir/--ar V` | the reach (`internet`, `internal`, `local`), the security requirements (`L`, `M`, `H`, `X`) |
| `--cvss 4\|3` | the CVSS version preferred when an advisory has both (default 4) |
| `--lang fr\|en` | the messages' and `report.md`'s language (default: the window's, else French) |
| `--fail-on LEVEL` | exit code 2 when a finding is at or above `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |

Exit codes: `0`, `1` on an error, `2` past `--fail-on`. Without a display the program goes to the command line by itself.

## Understanding the results

- **Severity** is the environmental severity when an environment applies and the advisory has a CVSS vector,
  otherwise the base one; the filters, the counters, *Packages to upgrade*, the reports and `--fail-on` all use it.
- **Fixed in**: the first version without the vulnerability (— when no fix is published).
- **≈ version**: an npm project without a lockfile is checked at the *lowest* version its range allows (`^4.17.0` →
  `4.17.0`); the version installed may be newer. Commit a lockfile for exact results.
- **Maven and Gradle** results cover the **declared** dependencies (and `dependencyManagement`); their transitive
  ones are only known to the build tool: run `mvn dependency:tree`, or enable Gradle's dependency locking.
- A finding means the version is in an advisory's affected range; whether the vulnerable code is used by your
  application still needs a human eye.

## CVSS scores and environments

For every finding with a CVSS vector, CVSS 3.0, 3.1 or 4.0, CVEScanner computes its **base score** and its
**environmental score**: the same vector with the environment's metrics. CVSS defines no list of environments; the
presets fill in its metrics, to adjust freely:

| Setting | CVSS metric | Effect |
|---|---|---|
| **Reachable** | Modified Attack Vector (MAV) | *Internal network only*: network attacks count as adjacent; *Local access only*: network and adjacent ones as local |
| **Confidentiality / Integrity / Availability** | Security Requirements CR / IR / AR | how much a breach of each would hurt the system; *Not defined* is CVSS's default (neutral in 3.x, high in 4.0) |

| Preset | Reachable | C | I | A |
|---|---|---|---|---|
| Not applied (base score) | — | — | — | — |
| Internet-facing production | unrestricted | High | High | High |
| Internal network service | internal | Medium | Medium | Medium |
| Air-gapped / offline system | local | Medium | Medium | Medium |
| Developer workstation / CI only | internal | Medium | High | Low |

An advisory with a rating and no vector keeps its rating. Example: Log4Shell, CVSS 4.0 base 10.0, scores 8.8 on an
air-gapped system. The CVSS 4.0 scoring is ported from the FIRST/Red Hat reference calculator (BSD 2-Clause, see
NOTICE).

## Languages

Every text a user reads is in a `messages_<code>.properties` file of its module, one per language, the same keys in
each: the scan's in `cvescanner-core/…/i18n/texts/`, the window's in `cvescanner-app/…/texts/`. `I18n` finds each
module's as a service (`I18nTexts`); what a scan finds and says later is kept as a `Phrase`, said in the language in
use. The window, the command line and `report.md` speak the language chosen; **`findings.csv` and `findings.json` are
always in English**, their readers being programs. Each module's tests check its texts (`TextsCheck`): the same keys in
each language, none blank, none unused.

## Build and run

Nothing to install: `scripts/setup.sh` deploys the JDK and Maven the scripts use (see "Externals").

```bash
scripts/setup.sh    # once: deploys the externals (JDK, Maven) into external/
scripts/run.sh      # builds cvescanner-app/target/cvescanner.jar if needed, then starts the program
scripts\setup.bat, scripts\run.bat    # same, on Windows
```

| Script | What it does |
|---|---|
| `scripts/setup.sh` / `.bat` | deploys the externals; `--force` downloads and deploys everything again |
| `scripts/build.sh` / `.bat` | builds the jar and runs the tests; what follows goes to Maven (`-DskipTests`) |
| `scripts/run.sh` / `.bat` | builds the jar if a source is newer, then runs it; `--rebuild` forces the build, the other arguments go to the program |
| `scripts/package.sh` / `.bat` | builds the distribution into `releases/` (see "Packaging") |
| `scripts/ci.sh` | a clean build with every test, run by `.githooks/pre-push` |
| `scripts/release.sh` | by hand, the GitHub release of a pushed tag (the release workflow does it on its own, see PUBLISHING.md) |
| `scripts/cvss-reference.py` | writes the CVSS scores `CvssReferenceTest` expects, with Red Hat's Python library `cvss` (used at development time only, never shipped) |

Every script uses the externals of `external/` and nothing installed on the machine. The version lives in `pom.xml`,
once, as `<revision>`. The pre-push hook is enabled once per clone with `git config core.hooksPath .githooks`.

## Externals

The software the build and the distributions need is not under source control. `externals.conf` names each one and its
version, and `scripts/setup.sh` deploys them under generic names into `external/`: `jdk` and `maven`. The
distributions' runtime is linked from that JDK. To fetch from a local mirror, set `MIRROR` in `externals.conf`, its
credentials in `externals.local.conf` (not under source control) or in the environment.

## Packaging

Each system builds its own self-contained distribution into `releases/`: `scripts/package.sh` on Linux,
`scripts\package.bat` on Windows. A release builds both, on GitHub.

| Archive | Built by | Holds |
|---|---|---|
| `cvescanner-<version>-linux.tar.gz` | `scripts/package.sh` | `cvescanner.sh` |
| `cvescanner-<version>-windows.zip` | `scripts\package.bat` | `cvescanner.bat` (the signed `javaw.exe`, no console), `CVEScanner.exe` (not signed), `cvescanner-cli.bat` (the command line) |

Each holds `cvescanner.jar`, its runtime `jre/` — linked by `jlink` from the JDK that builds: the program's two
modules, FlatLaf, the JDK's modules they need, the French and English locale data —, the `database/` folder, `LICENSE`,
`NOTICE`, FlatLaf's licence in `licenses/`, and Java's AOT cache of the program, `cvescanner.aot`, for a faster start:
the build makes it by running the program once on the samples (it needs a display, or `xvfb-run` on Linux); should that
fail, the archive goes without it, with a warning.

## Publishing

The licence, and how a version becomes a release on GitHub (a pushed tag `vX.Y`): [PUBLISHING.md](PUBLISHING.md);
what each version brought: [CHANGELOG.md](CHANGELOG.md). CVEScanner is not published on Maven Central.

## Layout

Two Maven modules, each a jar and a Java module, built in this order by the parent `pom.xml`:

| Module | Jar, Java module | What it is |
|---|---|---|
| `cvescanner-core/` | `cvescanner-core`, `org.jtools.cvescanner.core` | the scan, with no window; the JDK alone (`java.xml`) |
| `cvescanner-app/` | `cvescanner`, `org.jtools.cvescanner` | the program: its window, its looks (FlatLaf), its distributions (`-Pdist`) |

| Path | What it holds |
|---|---|
| `cvescanner-core/…/project/` | the projects' dependencies: `ProjectFiles` (the files found), `MavenScanner` (POMs, their properties and parents), `GradleScanner` (build files, catalogs), `NpmScanner` (package.json and its lockfiles), `Collector` |
| `cvescanner-core/…/db/` | the databases: `VulnDb` (the zips streamed, nested ones followed, only what the projects use kept), `Osv` (OSV records, their ranges), `CveList` (CVE JSON 5 records, their package and name matches) |
| `cvescanner-core/…/engine/` | `Engine` (a scan: files, dependencies, databases, matches), `ScanListener` (its progress) |
| `cvescanner-core/…/cvss/` | `Cvss` (vectors, the 3.x formulas, the 4.0 macrovectors), `Scoring` (a finding scored for an environment), `Environment`, `Reach`, `Requirement`, `Rating`, `Score` |
| `cvescanner-core/…/model/` | what a scan finds: `Finding`, `Dependency`, `Unresolved`, `PackageSummary`, `ScanResult`, `Severity`, `MatchBasis` |
| `cvescanner-core/…/report/`, `…/cli/` | `Reports` (report.md, findings.csv, findings.json, the packages to upgrade); `Options` and `Cli` (the command line) |
| `cvescanner-core/…/json/`, `…/version/`, `…/i18n/` | `Json` (a small parser and writer); `Versions` (Maven's and npm's version order); the languages: `I18n`, `I18nLanguage`, `I18nTexts`, `Phrase` |
| `cvescanner-app/…/` | `Launcher` (the entry point), `MainWindow`, `FindingDetails` (a finding's page, escaped), the table's `Column`, `ListTableModel` and renderers, `Settings`, `Looks`, `HelpMenu`, `I18nLabels` and `I18nLanguageBox`, `NoNetworkResolver` |
| `cvescanner-app/src/dist/`, `…/src/assembly/` | the distributions' launchers, the `database/` folder, FlatLaf's licence, and what goes in each archive |
| `*/src/test/` | core: `GoldenTest` (the samples' reports, case by case), `FrenchReportTest`, `CvssReferenceTest` (9,000 vectors scored by another implementation), `HostileReportTest`, the rules' unit tests, `PomParserTest`, `CoreTextsTest`; app: `NoNetworkTest`, `NoNetworkResolverTest`, `HostileAdvisoryTest`, `AppTextsTest` |
| `samples/` | sample projects and made-up databases, and `make_fixtures.py`, which writes them |
| `.github/workflows/` | `build.yml`, the build and the tests on every push; `release.yml`, the release on a tag `vX.Y` |

## Licence

Apache License 2.0 — see [LICENSE](LICENSE); [NOTICE](NOTICE) records the third-party terms: the CVSS v4.0 calculator
(BSD 2-Clause), FlatLaf, the Java runtime, and those of the databases you download.
