# Dependency Vulnerability Report

- **Generated:** 2026-11-21 20:07 UTC
- **Scanned directory:** `/home/j4ckk0/Developpement/github/CVEScanner/samples/cots-projects`
- **Database:** `nvdcve-2.0-2024.json.zip` (NVD CVE feed (JSON 2.0), 11 records (10 relevant), newest record 2026-11-21, file dated 2026-11-21 08:14 UTC)
- **Database:** `cots-cvelist.zip` (CVE List (CVE JSON 5), 3 records (3 relevant), file dated 2026-11-21 08:09 UTC)
- **Database:** `advisory-database-main.zip` (OSV / GitHub advisories, 12 records (3 relevant), file dated 2026-11-21 05:55 UTC)
- **Files scanned:** 0 pom.xml, 0 Gradle build files, 0 version catalogs, 0 package.json, 1 component inventories, 2 SBOMs, 4 C/C++ build manifests, 7 binaries examined
- **Dependencies analysed:** 18 (plus 8 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Internal network service (reachable: internal network only; confidentiality: medium, integrity: medium, availability: medium). *Severity* is the environmental severity where a CVSS vector is available.

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 11 |
| MEDIUM | 7 |
| LOW | 0 |
| UNKNOWN | 1 |
| **Total** | **19** (12 unique vulnerabilities in 10 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| HIGH | COTS | `osgeo:gdal` | 3.4.1 | 3.5.0 | 2 | binaries/gdal304.dll, inventory/cots.csv, manifests/vcpkg.json |
| HIGH | COTS | `ffmpeg:ffmpeg` | 4.4.2 ≈ | no fix | 1 | binaries/ffmpeg-4.4.2.exe, inventory/cots.csv, sbom/app.spdx.json |
| HIGH | npm | `lodash` | 4.17.15 | 4.17.21 | 1 | sbom/app.spdx.json |
| HIGH | Maven | `org.apache.logging.log4j:log4j-core` | 2.14.1 | 2.15.0 | 1 | sbom/bom.cdx.json |
| MEDIUM | COTS | `libbar` | 2.0 | 3.0 | 2 | inventory/cots.csv |
| MEDIUM | COTS | `haxx:libcurl` | 7.79.1 | 7.80.0 | 1 | manifests/conanfile.txt |
| MEDIUM | COTS | `libpng:libpng` | 1.6.37 | 1.6.38 | 1 | sbom/bom.cdx.json |
| MEDIUM | COTS | `libtiff:libtiff` | 4.3.0 | no fix | 1 | manifests/libtiff-4.pc |
| MEDIUM | COTS | `openssl:openssl` | 1.1.1k | 1.1.1l | 1 | inventory/cots.csv, manifests/conan.lock |
| MEDIUM | COTS | `sqlite:sqlite` | 3.36.0 ≈ | 3.37.0 | 1 | manifests/vcpkg.json |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `binaries/ffmpeg-4.4.2.exe`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | 7.4 | `ffmpeg:ffmpeg` | 4.4.2 | binary | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |

### `binaries/gdal304.dll`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.8 (v3.1) | 8.0 | `osgeo:gdal` | 3.4.1 | binary | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| HIGH | 8.1 (v3.1) | 7.3 | `osgeo:gdal` | 3.4.1 | binary | [CVE-2024-2001](https://www.cve.org/CVERecord?id=CVE-2024-2001) | CVE record | CVE-2024-2001 | 3.5.0 | GDAL out-of-bounds read |

### `inventory/cots.csv`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | 7.4 | `ffmpeg:ffmpeg` | 4.4.2 | inventory | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |
| HIGH | 8.8 (v3.1) | 8.0 | `osgeo:gdal` | 3.4.1 | inventory | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| HIGH | 8.1 (v3.1) | 7.3 | `osgeo:gdal` | 3.4.1 | inventory | [CVE-2024-2001](https://www.cve.org/CVERecord?id=CVE-2024-2001) | CVE record | CVE-2024-2001 | 3.5.0 | GDAL out-of-bounds read |
| MEDIUM | 4.4 (v3.1) | 4.4 | `libbar` | 2.0 | inventory | [CVE-2024-1006](https://nvd.nist.gov/vuln/detail/CVE-2024-1006) | CPE product match ⚠ | CVE-2024-1006 | 3.0 | Test NVD description. |
| MEDIUM | 7.5 (v3.1) | 6.5 | `openssl:openssl` | 1.1.1k | inventory | [CVE-2024-1003](https://nvd.nist.gov/vuln/detail/CVE-2024-1003) | CPE match | CVE-2024-1003 | 1.1.1l | Test NVD description. |
| UNKNOWN | — | — | `libbar` | 2.0 | inventory | [CVE-2024-2002](https://www.cve.org/CVERecord?id=CVE-2024-2002) | CVE name match ⚠ | CVE-2024-2002 | 2.5 | Test description. |

### `manifests/conan.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 7.5 (v3.1) | 6.5 | `openssl:openssl` | 1.1.1k | conan | [CVE-2024-1003](https://nvd.nist.gov/vuln/detail/CVE-2024-1003) | CPE match | CVE-2024-1003 | 1.1.1l | Test NVD description. |

### `manifests/conanfile.txt`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 7.5 (v3.1) | 6.5 | `haxx:libcurl` | 7.79.1 | conan | [CVE-2024-1009](https://nvd.nist.gov/vuln/detail/CVE-2024-1009) | CPE match | CVE-2024-1009 | 7.80.0 | Test NVD description. |

### `manifests/libtiff-4.pc`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 5.5 (v3.1) | 5.5 | `libtiff:libtiff` | 4.3.0 | pkg-config | [CVE-2024-1011](https://nvd.nist.gov/vuln/detail/CVE-2024-1011) | CPE match | CVE-2024-1011 | — | Test NVD description. |

### `manifests/vcpkg.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.8 (v3.1) | 8.0 | `osgeo:gdal` | 3.4.1 | vcpkg | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| HIGH | 8.1 (v3.1) | 7.3 | `osgeo:gdal` | 3.4.1 | vcpkg | [CVE-2024-2001](https://www.cve.org/CVERecord?id=CVE-2024-2001) | CVE record | CVE-2024-2001 | 3.5.0 | GDAL out-of-bounds read |
| MEDIUM | 5.5 (v3.1) | 5.5 | `sqlite:sqlite` | 3.36.0 | vcpkg | [CVE-2024-1010](https://nvd.nist.gov/vuln/detail/CVE-2024-1010) | CPE match | CVE-2024-1010 | 3.37.0 | Test NVD description. |

### `sbom/app.spdx.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | 7.4 | `ffmpeg:ffmpeg` | 4.4.2 | sbom | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |
| HIGH | 8.6 (v4.0) | 7.2 | `lodash` | 4.17.15 | sbom | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | Advisory | CVE-2021-23337 | 4.17.21 | Test vuln in lodash |

### `sbom/bom.cdx.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 10.0 (v4.0) | 8.9 | `org.apache.logging.log4j:log4j-core` | 2.14.1 | sbom | [GHSA-jfh8-c2jp-5v3q](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) | Advisory | CVE-2021-44228 | 2.15.0 | Test vuln in org.apache.logging.log4j:log4j-core |
| MEDIUM | 6.5 (v3.1) | 5.7 | `libpng:libpng` | 1.6.37 | sbom | [CVE-2024-1008](https://nvd.nist.gov/vuln/detail/CVE-2024-1008) | CPE match | CVE-2024-1008 | 1.6.38 | Test NVD description. |

## Dependencies that could not be checked (8)

| File | Ecosystem | Package | Declared | Reason |
|---|---|---|---|---|
| binaries/avcodec-58.dll | COTS | `ffmpeg:ffmpeg` | — | no version in the binary |
| binaries/libssl-1\_1-x64.dll | COTS | `openssl:openssl` | — | no version in the binary |
| binaries/linux/libgdal.so.30 | COTS | `osgeo:gdal` | — | no version in the binary |
| inventory/cots.csv | COTS | `zlib:zlib` | — | no version given |
| manifests/conanfile.txt | COTS | `zlib:zlib` | \[\>=1.2.11 \<2\] | version range |
| manifests/vcpkg.json | COTS | `xmlsoft:libxml2` | — | version set by the vcpkg baseline |
| sbom/app.spdx.json | COTS | `something` | — | no version given |
| sbom/bom.cdx.json | COTS | `<b>unnamed</b>` | — | no version given |

## Notes and limitations

- Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
- npm results include transitive dependencies when a lockfile is present.
- A match means the version is inside an advisory's affected range; whether the vulnerable code is reachable in your application still needs review.
- *CVE name match ⚠* findings come from CVE List records that describe the product only by name (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your package. The GitHub Advisory Database gives exact package matches.
- *Base score* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when there is no vector. *Environment score* applies the chosen environment (security requirements and maximum attack vector) as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
- *COTS* components (off-the-shelf: GDAL, FFmpeg…) come from component inventories (cots.csv), SBOMs, C/C++ build manifests and binaries. NVD matches them by their CPE's vendor and product (*CPE match*), or by product alone when their vendor is not known (*CPE product match ⚠*, to check); a CVE NVD says affects a component only on some platform is reported as affecting it. A version read from a binary's file name is approximate (≈).
