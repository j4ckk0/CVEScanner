# Dependency Vulnerability Report

- **Generated:** 2026-11-21 08:10 UTC
- **Scanned directory:** `/home/j4ckk0/Developpement/github/CVEScanner/samples/cots-projects`
- **Database:** `nvdcve-2.0-2024.json.zip` (NVD CVE feed (JSON 2.0), 7 records (6 relevant), file dated 2026-11-21 08:09 UTC)
- **Database:** `cots-cvelist.zip` (CVE List (CVE JSON 5), 3 records (3 relevant), file dated 2026-11-21 08:09 UTC)
- **Files scanned:** 0 pom.xml, 0 Gradle build files, 0 version catalogs, 0 package.json, 1 component inventories
- **Dependencies analysed:** 5 (plus 1 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Internal network service (reachable: internal network only; confidentiality: medium, integrity: medium, availability: medium). *Severity* is the environmental severity where a CVSS vector is available.

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 0 |
| UNKNOWN | 1 |
| **Total** | **6** (6 unique vulnerabilities in 4 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| HIGH | COTS | `osgeo:gdal` | 3.4.1 | 3.5.0 | 2 | inventory/cots.csv |
| HIGH | COTS | `ffmpeg:ffmpeg` | 4.4.2 | no fix | 1 | inventory/cots.csv |
| MEDIUM | COTS | `libbar` | 2.0 | 3.0 | 2 | inventory/cots.csv |
| MEDIUM | COTS | `openssl:openssl` | 1.1.1k | 1.1.1l | 1 | inventory/cots.csv |

## Findings by file

### `inventory/cots.csv`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | 7.4 | `ffmpeg:ffmpeg` | 4.4.2 | inventory | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |
| HIGH | 8.8 (v3.1) | 8.0 | `osgeo:gdal` | 3.4.1 | inventory | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| HIGH | 8.1 (v3.1) | 7.3 | `osgeo:gdal` | 3.4.1 | inventory | [CVE-2024-2001](https://www.cve.org/CVERecord?id=CVE-2024-2001) | CVE record | CVE-2024-2001 | 3.5.0 | GDAL out-of-bounds read |
| MEDIUM | 4.4 (v3.1) | 4.4 | `libbar` | 2.0 | inventory | [CVE-2024-1006](https://nvd.nist.gov/vuln/detail/CVE-2024-1006) | CPE product match ⚠ | CVE-2024-1006 | 3.0 | Test NVD description. |
| MEDIUM | 7.5 (v3.1) | 6.5 | `openssl:openssl` | 1.1.1k | inventory | [CVE-2024-1003](https://nvd.nist.gov/vuln/detail/CVE-2024-1003) | CPE match | CVE-2024-1003 | 1.1.1l | Test NVD description. |
| UNKNOWN | — | — | `libbar` | 2.0 | inventory | [CVE-2024-2002](https://www.cve.org/CVERecord?id=CVE-2024-2002) | CVE name match ⚠ | CVE-2024-2002 | 2.5 | Test description. |

## Dependencies that could not be checked (1)

| File | Ecosystem | Package | Declared | Reason |
|---|---|---|---|---|
| inventory/cots.csv | COTS | `zlib:zlib` | — | no version given |

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
