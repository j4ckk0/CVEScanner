# CVEScanner — orientation for Claude

A desktop program (and a command line) that tells which known vulnerabilities apply to the dependencies of Maven,
Gradle and npm projects, from vulnerability database zips the user downloads (GitHub Advisory Database, CVE List,
OSV.dev exports), scored with CVSS 3.x/4.0 for the environment the software runs in. `README.md` is the map.

## Decisions (taken with the user, not to be undone without asking)

- **Prerequisites are DocComparator's** (`~/Developpement/github/DocComparator`), not JToolsFramework's: the same
  `externals.conf` (Temurin JDK, Maven) deployed by `scripts/setup.sh` into `external/`, the same scripts, hooks,
  workflows, parent-pom conventions, jlink distributions for Windows and Linux. When in doubt, do as DocComparator does.
- **Strictly offline**: the program never reaches the network — no download, no browser. The one program it starts is
  the scanned project's build tool, on Apply fixes once the user confirms the commands, in its offline mode; only
  `fix/ToolRunner` may use `ProcessBuilder` (NoNetworkTest). Nothing is installed: a missing tool means no fix.
  Links are copied to the clipboard, a report's folder is shown, never opened. `NoNetworkTest` keeps it so.
- **Two modules**: `cvescanner-core` (the scan, the databases, CVSS, the reports, the command line; `java.xml` only,
  no `java.desktop`) and `cvescanner-app` (the window, the distributions).
- **FlatLaf** (the version the parent pom names) is the only library shipped; the enforcer rule keeps any other out.
- **French and English**, French by default; `findings.csv` / `findings.json` keep English keys (machine formats).
- **Settings** in `cvescanner.properties` beside the program, never `java.util.prefs`.
- **GitHub releases only** (tag `vX.Y`, PUBLISHING.md); no Maven Central.
- Commits as `j4ckk0 <j4ckk057@gmail.com>`.
- **Ignore file** `cvescanner-ignore.csv` (id,package,version,until,reason) at the root of the folder scanned, or
  `--ignore`; the window may write it there (Ignore… / Stop ignoring), the only file it writes into a scanned project.
  Ignored findings are out of the counts, `findings.csv` and `--fail-on`, listed apart in `report.md`/`findings.json`.

## Commands

```bash
scripts/setup.sh      # once: external/jdk and external/maven
scripts/build.sh      # build + tests (extra arguments go to mvn)
scripts/ci.sh         # clean build with every test, the window test under xvfb-run; run by .githooks/pre-push
scripts/window-check.sh  # the window test alone (WindowChecklistTest), on a virtual display
scripts/screenshots.sh DB...  # the README's pictures, English and French, the examples scanned with real databases
scripts/run.sh        # the window (or: scripts/run.sh --no-gui -d DIR --db ZIP ...)
scripts/package.sh    # releases/cvescanner-<version>-linux.tar.gz
```

## Tests worth knowing

- `WindowChecklistTest` (app): the window started in the test's JVM (`WindowDriver`) and clicked through with a Robot;
  only with `-Dcvescanner.windowTest=true`, which `scripts/ci.sh` and the build workflow pass under `xvfb-run`.
  Components it looks up have a test name (`MainWindow.nameForTests`).

- `cli/GoldenTest` (core): the scan of `samples/` must give what the original prototype gave, case by case
  (`src/test/resources/org/jtools/cvescanner/cli/golden/*`). A change of behaviour that is wanted updates the golden
  files in the same commit, and says so in its message.
- `samples/` is written by `samples/make_fixtures.py samples`; its databases are made-up advisories.

## Languages

Every text a user reads is in its module's `messages_{en,fr}.properties` (`i18n/texts/` in core, `texts/` in the app),
the same keys in each; `TextsCheck` (CoreTextsTest, AppTextsTest) fails on a missing, blank, duplicated or unused key.
What a scan finds that is said later (a reason, a note, a warning) is kept as a `Phrase` (key + arguments). The window,
the console and report.md speak the language chosen; findings.csv / findings.json are always written in English.
Tests speak English (`I18nEnglishInTests`).

## Conventions

- Comments tell the intention (why the code is as it is), never what the next line does, never the history.
- A unit does one thing; a name says what the thing is. Past ~1000 lines a file is a finding.
- Trials of the window never open on the user's desktop: render off-screen, or `xvfb-run`.
- Build with `clean` (the scripts do): without it the shade plugin reuses the previous `cvescanner.jar`, whose old core
  classes win over the new ones.
- Commit messages: a feature title in plain English.
