# Publishing CVEScanner: its licence, GitHub's releases

CVEScanner is published on GitHub only: its sources, and on the Releases page the two self-contained distributions.
It is not on Maven Central.

## 1. The licence

Apache License 2.0, like the other jtools projects, copyright jtools.org:

- `LICENSE` at the root, the licence's full text; `NOTICE` beside it, the third-party terms: the CVSS v4.0 calculator
  the scoring is ported from (BSD 2-Clause), FlatLaf (Apache License 2.0), whose classes the distributions hold, the
  runtime linked from Eclipse Temurin (GPLv2 with the Classpath Exception) the distributions carry, and the terms of
  the vulnerability databases a user downloads.
- `<licenses>`, `<organization>` and `<developers>` in `pom.xml`.
- The Apache header at the top of every Java source, written by `license-maven-plugin` as the sources are built
  (`update-file-header`, phase `process-sources`): a new source gets it at the next build.
- The "Licence" section of `README.md`.
- Each distribution carries `LICENSE` and `NOTICE` at its root, FlatLaf's licence in `licenses/`, and the runtime's
  own in `jre/legal/`; `scripts/package.sh` and `scripts\package.bat` check they are there.

## 2. A release on GitHub

What a user downloads: the two self-contained distributions, each with its Java runtime and built on its own system, on
the repository's Releases page, with the version's notes from `CHANGELOG.md` and the archives' SHA-256. A release is
public as soon as it is made: it is made when asked for, never as a side effect of a push.

1. Bump the version in the parent `pom.xml`: `<revision>` (`1.0`) and `<windowsVersion>` (`1.0.0.0`, the four parts
   launch4j wants).
2. Give `CHANGELOG.md` its section, `## 1.0 — <date>`: what the version brings, a bullet list, for a user.
3. Commit, tag and push the tag:

       git tag -a v1.0 -m "1.0"
       git push origin main v1.0

The tag starts `.github/workflows/release.yml` on GitHub: it checks that the tag, the pom and the changelog agree,
then on Linux and on Windows deploys the externals (`scripts/setup.sh`, `scripts\setup.bat`), builds and tests the
distribution (`scripts/package.sh`, `scripts\package.bat`) and checks its launchers use the AOT cache, then creates
the release with the two archives (`gh release create`, with the workflow's own token: no personal token is
involved). Every push of `main` also runs `.github/workflows/build.yml`: the build and the tests, without a screen.

Before a tag, the release workflow can be run by hand as a dry run (*Actions*, *release*, *Run workflow*, on `main`):
the two distributions of the version `pom.xml` names, built and checked on Linux and on Windows, are kept as the
run's artefacts, to download and try; nothing is published, and neither the tag nor the changelog is checked.

By hand, should the workflow be unavailable: `scripts/package.sh` on Linux and `scripts\package.bat` on Windows, the
Windows archive copied into `releases/` beside the Linux one, then `scripts/release.sh 1.0`, which creates the
release from the pushed tag and uploads the archives — with a fine-grained token for this repository only (*Contents:
read and write*), in `$GITHUB_TOKEN` or `~/.config/github/cvescanner-release-token`. `scripts/release.sh --dry-run
1.0` prints the notes and calls nothing.
