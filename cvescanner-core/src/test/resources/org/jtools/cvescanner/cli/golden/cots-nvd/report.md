# Dependency Vulnerability Report

- **Generated:** 2026-11-21 08:19 UTC
- **Scanned directory:** `/home/j4ckk0/Developpement/github/CVEScanner/samples/cots-projects`
- **Database:** `nvdcve-2.0-2024.json.zip` (NVD CVE feed (JSON 2.0), 11 records (10 relevant), file dated 2026-11-21 08:14 UTC)
- **Files scanned:** 0 pom.xml, 0 Gradle build files, 0 version catalogs, 0 package.json, 1 component inventories, 2 SBOMs, 4 C/C++ build manifests, 7 binaries examined
- **Dependencies analysed:** 18 (plus 8 that could not be resolved to a version)
- **Scoring:** CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)
- **Environment:** Not applied (base score)

## Summary

| Severity | Findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 4 |
| LOW | 0 |
| UNKNOWN | 0 |
| **Total** | **13** (8 unique vulnerabilities in 8 package versions) |

## Packages to upgrade

*Upgrade to* is the lowest version that fixes every listed advisory.

| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |
|---|---|---|---|---|---|---|
| HIGH | COTS | `ffmpeg:ffmpeg` | 4.4.2 ≈ | no fix | 1 | binaries/ffmpeg-4.4.2.exe, inventory/cots.csv, sbom/app.spdx.json |
| HIGH | COTS | `haxx:libcurl` | 7.79.1 | 7.80.0 | 1 | manifests/conanfile.txt |
| HIGH | COTS | `openssl:openssl` | 1.1.1k | 1.1.1l | 1 | inventory/cots.csv, manifests/conan.lock |
| HIGH | COTS | `osgeo:gdal` | 3.4.1 | 3.4.2 | 1 | binaries/gdal304.dll, inventory/cots.csv, manifests/vcpkg.json |
| MEDIUM | COTS | `libbar` | 2.0 | 3.0 | 1 | inventory/cots.csv |
| MEDIUM | COTS | `libpng:libpng` | 1.6.37 | 1.6.38 | 1 | sbom/bom.cdx.json |
| MEDIUM | COTS | `libtiff:libtiff` | 4.3.0 | no fix | 1 | manifests/libtiff-4.pc |
| MEDIUM | COTS | `sqlite:sqlite` | 3.36.0 ≈ | 3.37.0 | 1 | manifests/vcpkg.json |

> ≈ = lowest version allowed by the range in package.json (no lockfile found). The installed version may be newer; add a lockfile for exact results.

## Findings by file

### `binaries/ffmpeg-4.4.2.exe`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | — | `ffmpeg:ffmpeg` | 4.4.2 | binary | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |

### `binaries/gdal304.dll`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.8 (v3.1) | — | `osgeo:gdal` | 3.4.1 | binary | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |

### `inventory/cots.csv`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | — | `ffmpeg:ffmpeg` | 4.4.2 | inventory | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |
| HIGH | 7.5 (v3.1) | — | `openssl:openssl` | 1.1.1k | inventory | [CVE-2024-1003](https://nvd.nist.gov/vuln/detail/CVE-2024-1003) | CPE match | CVE-2024-1003 | 1.1.1l | Test NVD description. |
| HIGH | 8.8 (v3.1) | — | `osgeo:gdal` | 3.4.1 | inventory | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| MEDIUM | 4.4 (v3.1) | — | `libbar` | 2.0 | inventory | [CVE-2024-1006](https://nvd.nist.gov/vuln/detail/CVE-2024-1006) | CPE product match ⚠ | CVE-2024-1006 | 3.0 | Test NVD description. |

### `manifests/conan.lock`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 7.5 (v3.1) | — | `openssl:openssl` | 1.1.1k | conan | [CVE-2024-1003](https://nvd.nist.gov/vuln/detail/CVE-2024-1003) | CPE match | CVE-2024-1003 | 1.1.1l | Test NVD description. |

### `manifests/conanfile.txt`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 7.5 (v3.1) | — | `haxx:libcurl` | 7.79.1 | conan | [CVE-2024-1009](https://nvd.nist.gov/vuln/detail/CVE-2024-1009) | CPE match | CVE-2024-1009 | 7.80.0 | Test NVD description. |

### `manifests/libtiff-4.pc`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 5.5 (v3.1) | — | `libtiff:libtiff` | 4.3.0 | pkg-config | [CVE-2024-1011](https://nvd.nist.gov/vuln/detail/CVE-2024-1011) | CPE match | CVE-2024-1011 | — | Test NVD description. |

### `manifests/vcpkg.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.8 (v3.1) | — | `osgeo:gdal` | 3.4.1 | vcpkg | [CVE-2024-1001](https://nvd.nist.gov/vuln/detail/CVE-2024-1001) | CPE match | CVE-2024-1001 | 3.4.2 | Heap overflow in GDAL's reader. |
| MEDIUM | 5.5 (v3.1) | — | `sqlite:sqlite` | 3.36.0 | vcpkg | [CVE-2024-1010](https://nvd.nist.gov/vuln/detail/CVE-2024-1010) | CPE match | CVE-2024-1010 | 3.37.0 | Test NVD description. |

### `sbom/app.spdx.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| HIGH | 8.7 (v4.0) | — | `ffmpeg:ffmpeg` | 4.4.2 | sbom | [CVE-2024-1002](https://nvd.nist.gov/vuln/detail/CVE-2024-1002) | CPE match | CVE-2024-1002 | — | Test NVD description. |

### `sbom/bom.cdx.json`

| Severity | Base score | Environment score | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |
|---|---|---|---|---|---|---|---|---|---|---|
| MEDIUM | 6.5 (v3.1) | — | `libpng:libpng` | 1.6.37 | sbom | [CVE-2024-1008](https://nvd.nist.gov/vuln/detail/CVE-2024-1008) | CPE match | CVE-2024-1008 | 1.6.38 | Test NVD description. |

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
