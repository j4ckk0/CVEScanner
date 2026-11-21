# CVEScanner

**Which known vulnerabilities apply to your Maven, Gradle and npm projects?** CVEScanner looks through a folder for
every `pom.xml`, Gradle build file and `package.json`, reads the dependencies they declare (and, with a lockfile, the
npm ones they pull in), and checks each against a vulnerability database. You download the database yourself, as
zip files, on a computer with internet access. The findings are shown in a table you can filter, search and sort,
and written as reports (`report.md`, `findings.csv`, `findings.json`). Each finding has its CVSS base score and an
environmental score for where the software runs: internet-facing, internal network, air-gapped, developer
workstation, or values of your own.

It is a desktop program with a command line for CI. It is made for computers without internet access: it reads the
database zips you give it and does not download anything.

> Work in progress: the program comes from a single-file prototype and is being turned into this project.

## The databases

Download one or more of these files on a computer with internet access, and give them to CVEScanner **without
extracting them**.

| Database | Download | Matches |
|---|---|---|
| GitHub Advisory Database (recommended) | <https://github.com/github/advisory-database/archive/refs/heads/main.zip> (`advisory-database-main.zip`) | the exact Maven/npm package and its affected versions, with the CVE IDs |
| CVE List, the CVE Program's official list (optional) | <https://github.com/CVEProject/cvelistV5/releases>: the newest release's asset `YYYY-MM-DD_all_CVEs_at_midnight.zip.zip` (not the `_delta_` files) | exact when the record names the package; otherwise by product name, marked **CVE name match ⚠**, to check |
| OSV.dev exports (optional) | `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` and `…/npm/all.zip` | as the GitHub Advisory Database |

When several are loaded, a CVE already covered by an advisory is reported once.

## Build and run

Nothing needs to be installed: `scripts/setup.sh` deploys the JDK and Maven the scripts use, from `externals.conf`,
into `external/`.

```bash
scripts/setup.sh    # once: deploys the externals (JDK, Maven) into external/
scripts/run.sh      # builds cvescanner-app/target/cvescanner.jar if needed, then starts the program
scripts/run.sh --no-gui -d ~/src/my-app --db ~/Downloads/advisory-database-main.zip --fail-on HIGH
scripts\setup.bat, scripts\run.bat    # the same, on Windows
```

`scripts/build.sh` builds and runs the tests, `scripts/ci.sh` runs a clean build with every test (and runs before
every push once `git config core.hooksPath .githooks` is set), and `scripts/package.sh` builds the self-contained
distribution.

## Layout

| Module | Jar, Java module | What it is |
|---|---|---|
| `cvescanner-core/` | `cvescanner-core`, `org.jtools.cvescanner.core` | the scan, with no window: the projects' dependencies (`project`), the databases (`db`), the matching (`engine`), CVSS (`cvss`), what a scan finds (`model`), the reports (`report`), the command line (`cli`); the JDK alone |
| `cvescanner-app/` | `cvescanner`, `org.jtools.cvescanner` | the program: its window, the findings' table, its filters and details |

`samples/` holds sample projects and made-up databases, written by `samples/make_fixtures.py`; the tests scan them.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE); [NOTICE](NOTICE) records the third-party terms, among them the CVSS
v4.0 calculator's (BSD 2-Clause) and those of the databases you download.
