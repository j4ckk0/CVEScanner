# Examples

Four small projects that declare **real packages at versions with known, published vulnerabilities**, one per kind of
build CVEScanner reads. Scan this folder to see the program at work: drop a database zip in `database/` (see the
main README, "The databases"), start CVEScanner, choose this `examples` folder, press *Scan*. Or:

```
cvescanner.sh --no-gui -d examples            (Linux, from the unpacked archive)
cvescanner-cli.bat --no-gui -d examples       (Windows)
```

They are not projects to build or install: nothing in them runs, and the lockfiles were written by hand, without the
integrity hashes npm and yarn add (CVEScanner reads only the versions).

| Folder | What it shows |
|---|---|
| `maven-webapp/` | a Maven parent and its module: versions set by `<properties>` and `<dependencyManagement>` in the parent, used by the module |
| `gradle-app/` | a Gradle build in Kotlin (`build.gradle.kts`): versions in the version catalog (`gradle/libs.versions.toml`, one by `version.ref`), in a `val`, written out |
| `npm-app/` | `package.json` and its `package-lock.json` (v3): direct dependencies, a transitive one (`follow-redirects`, from `axios`), development ones, a transitive development one (`minimist`, from `mkdirp`) |
| `yarn-app/` | `package.json` and its `yarn.lock` (Yarn 1): transitive dependencies (`lodash` from `async`; `is-glob`, `is-extglob` from `glob-parent`), a package under an `npm:` alias (`lodash-legacy`, which is `lodash` 4.17.11) |

## What a scan finds

Scanned with OSV.dev's Maven and npm exports of 2026-11-21: **283 findings, 204 distinct advisories, in all 32
vulnerable package versions, and no dependency left unchecked.** A newer database finds more: advisories are added
every day. For each package, one of its best known CVEs, and the version that fixes that one (*Packages to upgrade*
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

## What a scan does not find

What Maven and Gradle would add themselves, transitive dependencies, is not read: `logback-classic` 1.2.3 brings
`logback-core` 1.2.3, which carries CVE-2021-42550 (fixed in 1.2.8), and is not reported because it is not declared.
Run `mvn dependency:tree` to see them, or declare them. npm and yarn give their transitive dependencies in their
lockfiles: those are reported.
