# Dependency Vulnerability Report

- **Generated:** 2026-11-21 05:48 UTC
- **Scanned directory:** `/tmp/claude-1000/-home-j4ckk0-Developpement-git-CVEScanner/9bbecb33-1601-49ef-94d3-4104c4827408/scratchpad/OUT/projects`
- **Database:** `advisory-database-main.zip` (OSV / GitHub advisories, 12 records (12 relevant), file dated 2026-11-21 05:30 UTC)
- **Database:** `2026-11-19_all_CVEs_at_midnight.zip.zip` (CVE List (CVE JSON 5), 10 records (8 relevant), file dated 2026-11-21 05:30 UTC)
- **Files scanned:** 2 pom.xml, 1 Gradle build files, 1 version catalogs, 3 package.json
- **Dependencies analysed:** 13 (plus 3 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Custom (reachable: local access only; confidentiality: high, integrity: low, availability: not defined). *Severity* is the environmental severity where a CVSS vector is available.

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 4 |
| HIGH | 7 |
| MEDIUM | 0 |
| LOW | 1 |
| UNKNOWN | 0 |
| **Total** | **12** (9 unique vulnerabilities in 10 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | npm | `minimist` | 1.2.5 | 1.2.6 | 1 | npm-lock/package-lock.json, yarn/yarn.lock |
| CRITICAL | Maven | `org.apache.commons:commons-text` | 1.9 | 1.10.0 | 1 | gradle/gradle/libs.versions.toml |
| CRITICAL | Maven | `org.apache.logging.log4j:log4j-core` | 2.14.1 | 2.15.0 | 1 | maven/child/pom.xml |
| HIGH | npm | `axios` | 0.21.0 ≈ | 0.21.2 | 1 | npm-nolock/package.json |
| HIGH | Maven | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | 2.9.10.7 | 1 | maven/child/pom.xml, maven/pom.xml |
| HIGH | Maven | `com.google.guava:guava` | 31.1-jre | 32.0.0-jre | 1 | gradle/build.gradle |
| HIGH | npm | `lodash` | 4.17.15 | 4.17.21 | 1 | npm-lock/package-lock.json |
| HIGH | npm | `lodash` | 4.17.20 | 4.17.21 | 1 | yarn/yarn.lock |
| HIGH | Maven | `org.yaml:snakeyaml` | 1.33 | 2.0 | 1 | gradle/build.gradle |
| LOW | npm | `jquery` | 3.4.0 ≈ | 3.5.0 | 1 | npm-nolock/package.json |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `gradle/build.gradle`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `com.google.guava:guava` | 31.1-jre | implementation | [GHSA-7g45-4rm6-3mm3](https://osv.dev/vulnerability/GHSA-7g45-4rm6-3mm3) | Advisory | CVE-2023-2976 | 32.0.0-jre | Test vuln in com.google.guava:guava |
| HIGH | 9.8 (v3.1) | 8.4 | `org.yaml:snakeyaml` | 1.33 | implementation | [GHSA-mjmj-j48q-9wg2](https://osv.dev/vulnerability/GHSA-mjmj-j48q-9wg2) | Advisory | CVE-2022-1471 | 2.0 | Test vuln in org.yaml:snakeyaml |

### `gradle/gradle/libs.versions.toml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `org.apache.commons:commons-text` | 1.9 | catalog:commons-text | [GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) | Advisory | CVE-2022-42889 | 1.10.0 | Test vuln in org.apache.commons:commons-text |

### `maven/child/pom.xml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 10.0 (v4.0) | 9.3 | `org.apache.logging.log4j:log4j-core` | 2.14.1 | compile | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | Advisory | CVE-2021-44228 | 2.15.0 | Test vuln in org.apache.logging.log4j:log4j-core |
| HIGH | — | — | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | compile | [GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) | Advisory | CVE-2020-36518 | 2.9.10.7 | Test vuln in com.fasterxml.jackson.core:jackson-databind |

### `maven/pom.xml`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | dependencyManagement | [GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) | Advisory | CVE-2020-36518 | 2.9.10.7 | Test vuln in com.fasterxml.jackson.core:jackson-databind |

### `npm-lock/package-lock.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `minimist` | 1.2.5 | transitive (dev) | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | Advisory | CVE-2021-44906 | 1.2.6 | Test vuln in minimist |
| HIGH | 8.6 (v4.0) | 8.3 | `lodash` | 4.17.15 | direct | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

### `npm-nolock/package.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | — | — | `axios` | 0.21.0 | dependencies | [GHSA-cph5-m8f7-6c5x](https://osv.dev/vulnerability/GHSA-cph5-m8f7-6c5x) | Advisory | CVE-2021-3749 | 0.21.2 | Test vuln in axios |
| LOW | 2.3 (v4.0) | 2.0 | `jquery` | 3.4.0 | devDependencies | [GHSA-gxr4-xjj5-5px2](https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2) | Advisory | CVE-2020-11022 | 3.5.0 | Test vuln in jquery |

### `yarn/yarn.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `minimist` | 1.2.5 | direct | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | Advisory | CVE-2021-44906 | 1.2.6 | Test vuln in minimist |
| HIGH | 8.6 (v4.0) | 8.3 | `lodash` | 4.17.20 | direct | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

## Dependencies that could not be checked (3)

| File | Ecosystem | Package | Declared | Reason |
|---|---|---|---|---|
| gradle/build.gradle | Maven | `org.foo:bar` | 1.+ | dynamic version |
| maven/child/pom.xml | Maven | `org.springframework:spring-core` | — | version managed outside this repo (external parent/BOM) |
| npm-nolock/package.json | npm | `left` | git+https://x/y.git | non-registry source |

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
