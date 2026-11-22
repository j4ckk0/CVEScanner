# Dependency Vulnerability Report

- **Generated:** 2026-11-22 10:07 UTC
- **Scanned directory:** `<samples>/projects-gradle-lock`
- **Database:** `advisory-database-main.zip` (OSV / GitHub advisories, 12 records (3 relevant), file dated 2026-11-21 05:55 UTC)
- **Files scanned:** 0 pom.xml, 1 Gradle build files, 0 version catalogs, 0 package.json
- **Dependencies analysed:** 5 (plus 0 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 2 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **2** (2 unique vulnerabilities in 2 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | Maven | `org.apache.logging.log4j:log4j-core` | 2.14.1 | 2.15.0 | 1 | gradle.lockfile |
| CRITICAL | Maven | `org.yaml:snakeyaml` | 1.33 | 2.0 | 1 | gradle.lockfile |

## Findings by file

### `gradle.lockfile`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 10.0 (v4.0) | — | `org.apache.logging.log4j:log4j-core` | 2.14.1 | direct | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | Advisory | CVE-2021-44228 | 2.15.0 | Test vuln in org.apache.logging.log4j:log4j-core |
| CRITICAL | 9.8 (v3.1) | — | `org.yaml:snakeyaml` | 1.33 | transitive | [GHSA-mjmj-j48q-9wg2](https://osv.dev/vulnerability/GHSA-mjmj-j48q-9wg2) | Advisory | CVE-2022-1471 | 2.0 | Test vuln in org.yaml:snakeyaml |

## Notes and limitations

- Maven results cover **declared** dependencies only: run `mvn dependency:tree`, or let the scan read the local Maven repository.
- Gradle builds with a lockfile (`gradle.lockfile`) give the versions Gradle resolved, the transitive ones included.
- Gradle builds without a lockfile cover their **declared** dependencies only: enable dependency locking, or let the scan read Gradle's cache.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
