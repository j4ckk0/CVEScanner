# Dependency Vulnerability Report

- **Generated:** 2026-11-21 12:17 UTC
- **Scanned directory:** `/home/j4ckk0/Developpement/github/CVEScanner/samples/projects`
- **Database:** `advisory-database-main.zip` (OSV / GitHub advisories, 12 records (12 relevant), file dated 2026-11-21 05:55 UTC)
- **Files scanned:** 2 pom.xml, 1 Gradle build files, 1 version catalogs, 3 package.json
- **Dependencies analysed:** 13 (plus 3 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)
- **Filter:** severity HIGH and above; ecosystems npm; approximate (≈) versions left out; holding "lod"

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 0 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **2** (1 unique vulnerabilities in 2 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| HIGH | npm | `lodash` | 4.17.15 | 4.17.21 | 1 | npm-lock/package-lock.json |
| HIGH | npm | `lodash` | 4.17.20 | 4.17.21 | 1 | yarn/yarn.lock |

## Findings by file

### `npm-lock/package-lock.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.6 (v4.0) | — | `lodash` | 4.17.15 | direct | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

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

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
