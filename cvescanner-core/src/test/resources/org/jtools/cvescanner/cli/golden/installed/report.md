# Dependency Vulnerability Report

- **Generated:** 2026-11-21 20:10 UTC
- **Scanned directory:** `/home/j4ckk0/Developpement/github/CVEScanner/samples/installed`
- **Scan:** installed product, from its binaries
- **Database:** `installed.zip` (advisories + CVE records, 6 records (6 relevant), file dated 2026-11-21 11:30 UTC)
- **Files scanned:** 4 jars, WARs and EARs, 2 installed npm packages, 1 Python packages, 1 binaries examined
- **Dependencies analysed:** 10 (plus 0 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 6 |
| HIGH | 1 |
| MEDIUM | 1 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **8** (6 unique vulnerabilities in 7 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| CRITICAL | Maven | `log4j-core` | 2.14.1 | 2.15.0 | 1 | lib/log4j-core-2.14.1.jar |
| CRITICAL | npm | `minimist` | 1.2.5 | 1.2.6 | 1 | app/node\_modules/minimist/package.json |
| CRITICAL | COTS | `openssl:openssl` | 1.1.1k | 1.1.1l | 1 | native/libcrypto.so.1.1 |
| CRITICAL | Maven | `org.apache.commons:commons-text` | 1.9 | 1.10.0 | 1 | lib/commons-text-1.9.jar, web/shop.war\!/WEB-INF/lib/commons-text-1.9.jar |
| CRITICAL | Maven | `org.apache.logging.log4j:log4j-core` | 2.14.1 | 2.15.0 | 1 | app/app.jar\!/BOOT-INF/lib/log4j-core-2.14.1.jar |
| HIGH | npm | `lodash` | 4.17.20 | 4.17.21 | 1 | app/node\_modules/lodash/package.json |
| MEDIUM | PyPI | `requests` | 2.25.0 | 2.31.0 | 1 | venv/lib/python3.11/site-packages/requests-2.25.0.dist-info/METADATA |

## Findings by file

### `app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 10.0 (v4.0) | — | `org.apache.logging.log4j:log4j-core` | 2.14.1 | installed | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | Advisory | CVE-2021-44228 | 2.15.0 | Test vuln in org.apache.logging.log4j:log4j-core |

### `app/node_modules/lodash/package.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.6 (v4.0) | — | `lodash` | 4.17.20 | installed | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

### `app/node_modules/minimist/package.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `minimist` | 1.2.5 | installed | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | Advisory | CVE-2021-44906 | 1.2.6 | Test vuln in minimist |

### `lib/commons-text-1.9.jar`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `org.apache.commons:commons-text` | 1.9 | installed | [GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) | Advisory | CVE-2022-42889 | 1.10.0 | Test vuln in org.apache.commons:commons-text |

### `lib/log4j-core-2.14.1.jar`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 10.0 (v4.0) | — | `log4j-core` | 2.14.1 | installed | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | Jar name match ⚠ | CVE-2021-44228 | 2.15.0 | Test vuln in org.apache.logging.log4j:log4j-core |

### `native/libcrypto.so.1.1`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | 9.8 (v3.1) | — | `openssl:openssl` | 1.1.1k | binary | [CVE-2021-3711](https://www.cve.org/CVERecord?id=CVE-2021-3711) | CVE record | CVE-2021-3711 | 1.1.1l | SM2 decryption buffer overflow |

### `venv/lib/python3.11/site-packages/requests-2.25.0.dist-info/METADATA`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | — | — | `requests` | 2.25.0 | installed | [GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) | Advisory | CVE-2023-32681 | 2.31.0 | Test vuln in Requests |

### `web/shop.war!/WEB-INF/lib/commons-text-1.9.jar`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | — | — | `org.apache.commons:commons-text` | 1.9 | installed | [GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) | Advisory | CVE-2022-42889 | 1.10.0 | Test vuln in org.apache.commons:commons-text |

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
- *COTS* components (off-the-shelf: GDAL, FFmpeg…) come from component inventories (cots.csv), SBOMs, C/C++ build manifests and binaries. NVD matches them by their CPE's vendor and product (*CPE match*), or by product alone when their vendor is not known (*CPE product match ⚠*, to check); a CVE NVD says affects a component only on some platform is reported as affecting it. A version read from a binary's file name is approximate (≈).
