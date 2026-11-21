# Dependency Vulnerability Report

- **Generated:** 2026-11-21 05:48 UTC
- **Scanned directory:** `/tmp/claude-1000/-home-j4ckk0-Developpement-git-CVEScanner/9bbecb33-1601-49ef-94d3-4104c4827408/scratchpad/OUT/projects`
- **Database:** `2026-11-19_all_CVEs_at_midnight.zip.zip` (CVE List (CVE JSON 5), 10 records (8 relevant), file dated 2026-11-21 05:30 UTC)
- **Files scanned:** 2 pom.xml, 1 Gradle build files, 1 version catalogs, 3 package.json
- **Dependencies analysed:** 13 (plus 3 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 3 |
| HIGH | 3 |
| MEDIUM | 1 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **7** (5 unique vulnerabilities in 6 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | npm | `minimist` | 1.2.5 | 1.2.6 | 1 | npm-lock/package-lock.json, yarn/yarn.lock |
| CRITICAL | Maven | `org.apache.commons:commons-text` | 1.9 | 1.10.0 | 1 | gradle/gradle/libs.versions.toml |
| HIGH | npm | `lodash` | 4.17.15 | 4.17.21 | 1 | npm-lock/package-lock.json |
| HIGH | npm | `lodash` | 4.17.20 | 4.17.21 | 1 | yarn/yarn.lock |
| HIGH | Maven | `org.yaml:snakeyaml` | 1.33 | 2.0 | 1 | gradle/build.gradle |
| MEDIUM | npm | `jquery` | 3.4.0 ≈ | 3.5.0 | 1 | npm-nolock/package.json |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `gradle/build.gradle`

| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.8 (v3.1) | — | `org.yaml:snakeyaml` | 1.33 | implementation | [CVE-2022-1471](https://www.cve.org/CVERecord?id=CVE-2022-1471) | CVE record | CVE-2022-1471 | 2.0 | Constructor Deserialization Remote Code Execution |

### `gradle/gradle/libs.versions.toml`

| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 9.3 (v4.0) | — | `org.apache.commons:commons-text` | 1.9 | catalog:commons-text | [CVE-2022-42889](https://www.cve.org/CVERecord?id=CVE-2022-42889) | CVE name match ⚠ | CVE-2022-42889 | 1.10.0 | Apache Commons Text performs variable interpolation. |

### `npm-lock/package-lock.json`

| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `minimist` | 1.2.5 | transitive (dev) | [CVE-2021-44906](https://www.cve.org/CVERecord?id=CVE-2021-44906) | CVE name match ⚠ | CVE-2021-44906 | 1.2.6 | Test description. |
| HIGH | 7.2 (v3.1) | — | `lodash` | 4.17.15 | direct | [CVE-2021-23337](https://www.cve.org/CVERecord?id=CVE-2021-23337) | CVE name match ⚠ | CVE-2021-23337 | 4.17.21 | Command injection in lodash |

### `npm-nolock/package.json`

| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 4.7 (v3.1) | — | `jquery` | 3.4.0 | devDependencies | [CVE-2020-11022](https://www.cve.org/CVERecord?id=CVE-2020-11022) | CVE name match ⚠ | CVE-2020-11022 | 3.5.0 | Test description. |

### `yarn/yarn.lock`

| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `minimist` | 1.2.5 | direct | [CVE-2021-44906](https://www.cve.org/CVERecord?id=CVE-2021-44906) | CVE name match ⚠ | CVE-2021-44906 | 1.2.6 | Test description. |
| HIGH | 7.2 (v3.1) | — | `lodash` | 4.17.20 | direct | [CVE-2021-23337](https://www.cve.org/CVERecord?id=CVE-2021-23337) | CVE name match ⚠ | CVE-2021-23337 | 4.17.21 | Command injection in lodash |

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
- *Base* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Env.* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
