# Dependency Vulnerability Report

- **Generated:** 2026-11-21 08:59 UTC
- **Scanned directory:** `<samples>/projects`
- **Database:** `advisory-database-main.zip` (OSV / GitHub advisories, 12 records (12 relevant), file dated 2026-11-21 05:55 UTC)
- **Files scanned:** 2 pom.xml, 1 Gradle build files, 1 version catalogs, 3 package.json
- **Dependencies analysed:** 13 (plus 3 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)
- **Ignore file:** `<samples>/ignore/cvescanner-ignore.csv` (5 entries)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 0 |
| LOW | 1 |
| UNKNOWN | 0 |
| **Total** | **8** (7 unique vulnerabilities in 7 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | Maven | `org.apache.commons:commons-text` | 1.9 | 1.10.0 | 1 | gradle/gradle/libs.versions.toml |
| CRITICAL | Maven | `org.yaml:snakeyaml` | 1.33 | 2.0 | 1 | gradle/build.gradle |
| HIGH | npm | `axios` | 0.21.0 ≈ | 0.21.2 | 1 | npm-nolock/package.json |
| HIGH | Maven | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | 2.9.10.7 | 1 | maven/child/pom.xml, maven/pom.xml |
| HIGH | Maven | `com.google.guava:guava` | 31.1-jre | 32.0.0-jre | 1 | gradle/build.gradle |
| HIGH | npm | `lodash` | 4.17.20 | 4.17.21 | 1 | yarn/yarn.lock |
| LOW | npm | `jquery` | 3.4.0 ≈ | 3.5.0 | 1 | npm-nolock/package.json |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `gradle/build.gradle`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 9.8 (v3.1) | — | `org.yaml:snakeyaml` | 1.33 | implementation | [GHSA-mjmj-j48q-9wg2](https://osv.dev/vulnerability/GHSA-mjmj-j48q-9wg2) | Advisory | CVE-2022-1471 | 2.0 | Test vuln in org.yaml:snakeyaml |
| HIGH | — | — | `com.google.guava:guava` | 31.1-jre | implementation | [GHSA-7g45-4rm6-3mm3](https://osv.dev/vulnerability/GHSA-7g45-4rm6-3mm3) | Advisory | CVE-2023-2976 | 32.0.0-jre | Test vuln in com.google.guava:guava |

### `gradle/gradle/libs.versions.toml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `org.apache.commons:commons-text` | 1.9 | catalog:commons-text | [GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) | Advisory | CVE-2022-42889 | 1.10.0 | Test vuln in org.apache.commons:commons-text |

### `maven/child/pom.xml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | compile | [GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) | Advisory | CVE-2020-36518 | 2.9.10.7 | Test vuln in com.fasterxml.jackson.core:jackson-databind |

### `maven/pom.xml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | dependencyManagement | [GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) | Advisory | CVE-2020-36518 | 2.9.10.7 | Test vuln in com.fasterxml.jackson.core:jackson-databind |

### `npm-nolock/package.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `axios` | 0.21.0 | dependencies | [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) | Advisory | CVE-2021-3749 | 0.21.2 | Test vuln in axios |
| LOW | 2.3 (v4.0) | — | `jquery` | 3.4.0 | devDependencies | [GHSA-gxr4-xjj5-5px2](https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2) | Advisory | CVE-2020-11022 | 3.5.0 | Test vuln in jquery |

### `yarn/yarn.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.6 (v4.0) | — | `lodash` | 4.17.20 | direct | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

## Dependencies that could not be checked (3)

| File | Ecosystem | Package | Declared | Reason |
|---|---|---|---|---|
| gradle/build.gradle | Maven | `org.foo:bar` | 1.+ | dynamic version |
| maven/child/pom.xml | Maven | `org.springframework:spring-core` | — | version managed outside this repo (external parent/BOM) |
| npm-nolock/package.json | npm | `left` | git+https://x/y.git | non-registry source |

## Ignored findings (4)

Findings reviewed and set aside by the ignore file or a VEX document: they are not in the counts above, nor in findings.csv, nor taken into account by --fail-on.

| Severity | Package | Version | Advisory | CVE | Until | Reason | File | Entry |
|---|---|---|---|---|---|---|---|---|
| CRITICAL | `minimist` | 1.2.5 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | 2999-12-31 | Development tool only | npm-lock/package-lock.json | line 4 |
| CRITICAL | `minimist` | 1.2.5 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | CVE-2021-44906 | 2999-12-31 | Development tool only | yarn/yarn.lock | line 4 |
| CRITICAL | `org.apache.logging.log4j:log4j-core` | 2.14.1 | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | CVE-2021-44228 | — | Not exposed: JNDI lookups disabled, see SEC-12 | maven/child/pom.xml | line 3 |
| HIGH | `lodash` | 4.17.15 | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | CVE-2021-23337 | — | Upgrade planned | npm-lock/package-lock.json | line 5 |

Entries past their date, their findings reported again:

- line 6: `CVE-2020-36518` — expired after 2020-01-01

Entries that set none of the findings aside:

- line 7: `CVE-2099-0001`

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
