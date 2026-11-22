# Examples

Small projects that declare **real packages at versions with known, published vulnerabilities**, one per kind of
build CVEScanner reads, and an installed product to scan as such. Scan this folder to see the program at work: drop
a database zip in `database/` (see the main README, "The databases"), start CVEScanner, choose this `examples`
folder, press *Scan*. Or:

```
cvescanner.sh --no-gui -d examples            (Linux, from the unpacked archive)
cvescanner-cli.bat --no-gui -d examples       (Windows)
```

Without a real database, from the repository: choose `samples/db/examples.zip`, made-up advisories for every
vulnerable package below (their CVE and fixed version as the tables give them, their text invented), and for
`cots-app` also `samples/db/cots-cvelist.zip` and `samples/db/nvdcve-2.0-2024.json.zip`. Each example then shows its
vulnerable packages; a real database adds the many other advisories they have.

They are not projects to build or install: nothing in them runs, and the lockfiles were written by hand, without the
integrity hashes npm and yarn add (CVEScanner reads only the versions).

| Folder | What it shows |
|---|---|
| `maven-webapp/` | a Maven parent and its module: versions set by `<properties>` and `<dependencyManagement>` in the parent, used by the module |
| `gradle-app/` | a Gradle build in Kotlin (`build.gradle.kts`): versions in the version catalog (`gradle/libs.versions.toml`, one by `version.ref`), in a `val`, written out |
| `npm-app/` | `package.json` and its `package-lock.json` (v3): direct dependencies, a transitive one (`follow-redirects`, from `axios`), development ones, a transitive development one (`minimist`, from `mkdirp`) |
| `yarn-app/` | `package.json` and its `yarn.lock` (Yarn 1): transitive dependencies (`lodash` from `async`; `is-glob`, `is-extglob` from `glob-parent`), a package under an `npm:` alias (`lodash-legacy`, which is `lodash` 4.17.11) |
| `installed-app/` | an installed product, to scan in *Installed product* mode (`--installed`): a Spring-Boot-like fat jar (`opt/shop/lib/shop-1.4.jar`, its jars in `BOOT-INF/lib`), a WAR (`opt/tomcat/webapps/admin.war`), an installed `node_modules` (`qs` nested under `express`), a Python `site-packages`, and a jar copied in by hand without Maven coordinates (`opt/shop/ext/commons-collections-3.2.1.jar`, its manifest only); the jars hold only the real artifacts' `pom.properties`, no code (see "Installed product" below) |
| `cots-app/` | components off-the-shelf of a C/C++ application, given the ways CVEScanner reads: a `cots.csv` inventory, a CycloneDX `bom.json`, a `vcpkg.json`, a `conanfile.txt` (see "Components off-the-shelf" below) |

## What a scan finds

Scanned with OSV.dev's Maven and npm exports of 2026-11-21: **283 findings, 204 distinct advisories, in all 32
vulnerable package versions, and no dependency left unchecked.** A newer database finds more: advisories are added
every day. For each package, one of its best known CVEs, and the version that fixes that one (a package's *Upgrade to*
gives the version that fixes them all):

**Maven** (`maven-webapp`)

| Package | Version | A known CVE | Fixed in |
|---|---|---|---|
| `org.apache.logging.log4j:log4j-core` | 2.14.1 | CVE-2021-44228, Log4Shell | 2.15.0 |
| `org.apache.commons:commons-text` | 1.9 | CVE-2022-42889, Text4Shell | 1.10.0 |
| `org.springframework:spring-beans`, `spring-webmvc` | 5.3.17 | CVE-2022-22965, Spring4Shell | 5.3.18 |
| `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | CVE-2019-12384 | 2.9.9.1 |
| `org.yaml:snakeyaml` | 1.33 | CVE-2022-1471 | 2.0 |
| `commons-collections:commons-collections` | 3.2.1 | CVE-2015-7501 | 3.2.2 |
| `ch.qos.logback:logback-classic` | 1.2.3 | CVE-2023-6378 | 1.2.13 |
| `com.h2database:h2` (test scope) | 1.4.199 | CVE-2021-42392 | 2.0.206 |

**Gradle** (`gradle-app`)

| Package | Version | A known CVE | Fixed in |
|---|---|---|---|
| `com.google.guava:guava` | 31.1-jre | CVE-2023-2976 | 32.0.0-jre |
| `io.netty:netty-codec-http` | 4.1.68.Final | CVE-2021-43797 | 4.1.71.Final |
| `com.google.protobuf:protobuf-java` | 3.21.5 | CVE-2022-3171 | 3.21.7 |
| `com.thoughtworks.xstream:xstream` | 1.4.17 | CVE-2021-39139 | 1.4.18 |
| `commons-io:commons-io` | 2.6 | CVE-2021-29425 | 2.7 |
| `org.apache.httpcomponents:httpclient` | 4.5.12 | CVE-2020-13956 | 4.5.13 |
| `junit:junit` (test) | 4.12 | CVE-2020-15250 | 4.13.1 |

**npm** (`npm-app`)

| Package | Version | A known CVE | Fixed in |
|---|---|---|---|
| `lodash` | 4.17.15 | CVE-2021-23337 | 4.17.21 |
| `axios` | 0.21.0 | CVE-2020-28168 | 0.21.1 |
| `follow-redirects` (transitive) | 1.13.0 | CVE-2022-0155 | 1.14.7 |
| `jquery` | 3.4.1 | CVE-2020-11022 | 3.5.0 |
| `moment` | 2.29.1 | CVE-2022-24785 | 2.29.2 |
| `node-fetch` | 2.6.0 | CVE-2022-0235 | 2.6.7 |
| `json5` (dev) | 2.2.1 | CVE-2022-46175 | 2.2.2 |
| `semver` (dev) | 5.7.1 | CVE-2022-25883 | 5.7.2 |
| `minimist` (transitive, dev) | 1.2.5 | CVE-2021-44906 | 1.2.6 |

**yarn** (`yarn-app`)

| Package | Version | A known CVE | Fixed in |
|---|---|---|---|
| `async` | 2.6.3 | CVE-2021-43138 | 2.6.4 |
| `glob-parent` | 5.1.1 | CVE-2020-28469 | 5.1.2 |
| `marked` | 1.1.0 | CVE-2022-21680 | 4.0.10 |
| `shell-quote` | 1.7.2 | CVE-2021-42740 | 1.7.3 |
| `ua-parser-js` | 0.7.21 | CVE-2021-27292 | 0.7.24 |
| `ws` (dev) | 7.4.5 | CVE-2021-32640 | 7.4.6 |
| `lodash` (transitive, from `async`) | 4.17.15 | CVE-2021-23337 | 4.17.21 |
| `lodash` (as `lodash-legacy`) | 4.17.11 | CVE-2019-10744 | 4.17.12 |

## Components off-the-shelf (`cots-app`)

Scan it with NVD's CVE feeds in `database/` (see the main README, "The databases"). With NVD's yearly feeds 2002–2026
and its "modified" feed of 2026-11-21 — 26 zips, read in about 100 seconds with 512 MB of memory —: **385 findings in
all 15 components, every one an exact vendor:product CPE match.** For each, one of its CVEs and the version that fixes
that one; *Upgrade to* fixes every one that has a fix:

| Component (vendor:product) | Version | From | Findings | A known CVE | Fixed in | Upgrade to |
|---|---|---|---|---|---|---|
| `osgeo:gdal` | 3.4.1 | `cots.csv` | 7 | CVE-2026-8084 | — (up to 3.12.4) | no fix given |
| `ffmpeg:ffmpeg` | 4.4.2 | `cots.csv` | 54 | CVE-2022-3964 | 4.4.4 | 9.0 (some unfixed) |
| `openssl:openssl` | 1.1.1k | `cots.csv` | 48 | CVE-2022-0778 | 1.1.1n | 1.1.1zj (some unfixed) |
| `zlib:zlib` | 1.2.11 | `cots.csv` | 4 | CVE-2018-25032 | 1.2.12 | 1.3.1 (some unfixed) |
| `haxx:libcurl` | 7.79.1 | `cots.csv` | 65 | CVE-2022-22576 | 7.83.0 | 8.22.0 (some unfixed) |
| `sqlite:sqlite` | 3.36.0 | `cots.csv` | 18 | CVE-2022-35737 | 3.39.2 | 3.54.0 (some unfixed) |
| `xmlsoft:libxml2` | 2.9.12 | `cots.csv` | 31 | CVE-2022-40303 | 2.10.3 | 2.15.4 (some unfixed) |
| `libpng:libpng` | 1.6.37 | `cots.csv` | 10 | CVE-2025-64720 | 1.6.51 | 1.6.57 |
| `libtiff:libtiff` | 4.3.0 | `bom.json` (CPE) | 61 | CVE-2025-61144 | 4.7.1 | 4.7.2 (some unfixed) |
| `libexpat_project:libexpat` | 2.4.1 | `bom.json` (name) | 51 | CVE-2022-22822 | 2.4.3 | 2.8.4 (some unfixed) |
| `freetype:freetype` | 2.10.4 | `bom.json` (name) | 4 | CVE-2022-27404 | 2.12.0 | 2.12.0 (some unfixed) |
| `webmproject:libwebp` | 1.2.0 | `vcpkg.json` (override) | 2 | CVE-2023-4863 | 1.3.2 | 1.3.2 |
| `freedesktop:poppler` | 21.01.0 ≈ | `vcpkg.json` (`version>=`) | 11 | CVE-2021-30860 | 22.09.0 | 25.07.0 (some unfixed) |
| `uclouvain:openjpeg` | 2.4.0 | `conanfile.txt` | 4 | CVE-2021-3575 | — | no fix given |
| `libarchive:libarchive` | 3.5.1 | `conanfile.txt` | 15 | CVE-2022-36227 | 3.6.2 | 3.8.0 (some unfixed) |

"—" and "no fix given": NVD bounds those CVEs by the last version affected ("up to 3.12.4"), not by a fixed one.
Poppler's version is the minimum `vcpkg.json` asks for (≈): the one installed may be newer. libcurl's findings include
those NVD files under `haxx:curl`, the same component's other name.

## What a scan does not find

What Maven and Gradle would add themselves, transitive dependencies, is not read: `logback-classic` 1.2.3 brings
`logback-core` 1.2.3, which carries CVE-2021-42550 (fixed in 1.2.8), and is not reported because it is not declared.
Run `mvn dependency:tree` to see them, or declare them. npm and yarn give their transitive dependencies in their
lockfiles: those are reported.

## Installed product

`installed-app/` scanned in *Installed product* mode with OSV.dev's Maven, npm and PyPI exports of 2026-11-21:
**327 findings, 326 distinct advisories, in all 23 package versions it ships**, for example:

- **in the jars**: `log4j-core` 2.14.1 inside `shop-1.4.jar!/BOOT-INF/lib/` (CVE-2021-44228, Log4Shell), `struts2-core`
  2.5.25 inside `admin.war!/WEB-INF/lib/` (CVE-2020-17530), `tomcat-embed-core` 9.0.40, `jackson-databind` 2.9.8,
  `commons-fileupload` 1.3.2;
- **in `node_modules`**: `qs` 6.7.0, installed under `express` (CVE-2022-24999), `node-forge` 0.10.0, `axios` 0.21.1,
  `jsonwebtoken` 8.5.1;
- **in `site-packages`**: `Django` 3.1.0, `Pillow` 8.1.0, `requests` 2.25.0 (CVE-2023-32681), `urllib3` 1.26.4,
  `Jinja2` 2.11.2, `PyYAML` 5.3.1;
- **in a jar without Maven coordinates**: `commons-collections` 3.2.1, known by its file name alone, matched to the
  advisories of `commons-collections:commons-collections` (CVE-2015-7501, CVE-2015-6420) as *Jar name match ⚠*;
  `--hide-name-matches` leaves these two out.

A source scan of `examples` reads none of these: their jars, `node_modules` and `site-packages` are what an
installation holds, not what a project declares.

