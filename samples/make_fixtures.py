#!/usr/bin/env python3
"""Writes CVEScanner's samples: the projects cli/GoldenTest scans, and the made-up databases it scans them with.

Usage: python3 samples/make_fixtures.py OUTDIR    (the repository's: samples)
Writes in OUTDIR:
  projects/  Maven, Gradle, npm, yarn            cots-projects/  inventory, SBOMs, manifests, binaries
  ignore/    an ignore file                      db/  OSV.dev exports, GitHub Advisory Database, CVE List, NVD
The results expected are the golden files: cvescanner-core/src/test/resources/org/jtools/cvescanner/cli/golden/.
"""
import io, json, os, sys, zipfile

out = sys.argv[1] if len(sys.argv) > 1 else "fixtures"

def write(path, text):
    path = os.path.join(out, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)

# ------------------------------------------------------------------ projects
write("projects/maven/pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version>
  <packaging>pom</packaging>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency>
  </dependencies></dependencyManagement>
</project>
""")
write("projects/maven/child/pom.xml", """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>
  </dependencies>
</project>
""")
write("projects/gradle/build.gradle", """ext { snakeVersion = '1.33' }
dependencies {
    implementation 'org.yaml:snakeyaml:$snakeVersion'
    implementation "org.yaml:snakeyaml:${snakeVersion}"
    // implementation 'commented:out:1.0'
    implementation group: 'commons-text', name: 'commons-text', version: '1.9'
    implementation 'com.google.guava:guava:31.1-jre'
    implementation 'org.foo:bar:1.+'
}
""")
write("projects/gradle/gradle/libs.versions.toml", """[versions]
text = "1.9"
[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }
""")
write("projects/npm-lock/package.json", '{"dependencies":{"lodash":"^4.17.0"}}\n')
write("projects/npm-lock/package-lock.json", """{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.0"}},
"node_modules/lodash":{"version":"4.17.15"},
"node_modules/minimist":{"version":"1.2.5","dev":true}}}
""")
write("projects/npm-nolock/package.json",
      '{"dependencies":{"axios":"^0.21.0","left":"git+https://x/y.git"},"devDependencies":{"jquery":"~3.4.0"}}\n')
write("projects/yarn/package.json", '{"dependencies":{"lodash":"^4.17.0","foo":"npm:minimist@^1.2.0"}}\n')
write("projects/yarn/yarn.lock", """# yarn lockfile v1

lodash@^4.17.0, lodash@^4.17.20:
  version "4.17.20"

"foo@npm:minimist@^1.2.0":
  version "1.2.5"
""")

# ------------------------------------------------------------------ OSV records
def osv(id, eco, name, events, aliases=(), vec=None, sev=None, v4=None):
    a = {"package": {"ecosystem": eco, "name": name},
         "ranges": [{"type": "SEMVER" if eco == "npm" else "ECOSYSTEM", "events": events}]}
    r = {"id": id, "aliases": list(aliases), "summary": f"Test vuln in {name}", "affected": [a]}
    if vec: r["severity"] = [{"type": "CVSS_V3", "score": vec}]
    if v4: r.setdefault("severity", []).append({"type": "CVSS_V4", "score": v4})
    if sev: r["database_specific"] = {"severity": sev}
    return r

maven = [
    osv("GHSA-jfh8-c2jp-5v3q", "Maven", "org.apache.logging.log4j:log4j-core", [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}],
        ["CVE-2021-44228"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        v4="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    osv("GHSA-xxxx-old", "Maven", "org.apache.logging.log4j:log4j-core", [{"introduced": "0"}, {"fixed": "2.0-rc1"}], ["CVE-2000-0001"], sev="LOW"),
    osv("GHSA-57j2-w4cx-62h2", "Maven", "com.fasterxml.jackson.core:jackson-databind",
        [{"introduced": "2.9.0"}, {"fixed": "2.9.10.7"}, {"introduced": "2.10.0"}, {"fixed": "2.10.5"}], ["CVE-2020-36518"], sev="HIGH"),
    osv("GHSA-mjmj-j48q-9wg2", "Maven", "org.yaml:snakeyaml", [{"introduced": "0"}, {"fixed": "2.0"}], ["CVE-2022-1471"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    osv("GHSA-599f-7c49-w659", "Maven", "org.apache.commons:commons-text", [{"introduced": "1.5"}, {"fixed": "1.10.0"}], ["CVE-2022-42889"], sev="CRITICAL"),
    osv("GHSA-7g45-4rm6-3mm3", "Maven", "com.google.guava:guava", [{"introduced": "1.0"}, {"fixed": "32.0.0-android"}], ["CVE-2023-2976"], sev="HIGH"),
    osv("GHSA-guava-old", "Maven", "com.google.guava:guava", [{"introduced": "0"}, {"last_affected": "24.1-jre"}], ["CVE-2018-10237"], sev="MODERATE"),
]
npm = [
    osv("GHSA-35jh-r3h4-6jhm", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}], ["CVE-2021-23337"],
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", v4="CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    osv("GHSA-xvch-5gv4-984h", "npm", "minimist", [{"introduced": "0"}, {"fixed": "1.2.6"}], ["CVE-2021-44906"], sev="CRITICAL"),
    osv("GHSA-cph5-m8f7-6c5x", "npm", "axios", [{"introduced": "0"}, {"fixed": "0.21.2"}], ["CVE-2021-3749"], sev="HIGH"),
    osv("GHSA-gxr4-xjj5-5px2", "npm", "jquery", [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}], ["CVE-2020-11022"], sev="MODERATE",
        v4="CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"),
    osv("GHSA-noncve", "npm", "jquery", [{"introduced": "0"}, {"fixed": "3.4.0"}], sev="LOW"),
]
os.makedirs(os.path.join(out, "db/osv"), exist_ok=True)
for eco, recs in (("Maven", maven), ("npm", npm)):
    with zipfile.ZipFile(os.path.join(out, f"db/osv/{eco}-all.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for r in recs:
            z.writestr(r["id"] + ".json", json.dumps(r))
        z.writestr("other.json", json.dumps(osv("X", "Maven", "other:thing", [{"introduced": "0"}])))

with zipfile.ZipFile(os.path.join(out, "db/advisory-database-main.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("advisory-database-main/README.md", "# GitHub Advisory Database")
    for r in maven + npm:
        z.writestr(f"advisory-database-main/advisories/github-reviewed/2021/12/{r['id']}/{r['id']}.json", json.dumps(r, indent=2))

# ------------------------------------------------------------------ CVE List (CVE JSON 5) records
def cve(id, affected, title=None, desc="Test description. More text.", metrics=None, state="PUBLISHED", adp=None):
    cna = {"affected": affected, "descriptions": [{"lang": "en", "value": desc}]}
    if title: cna["title"] = title
    if metrics: cna["metrics"] = metrics
    c = {"cna": cna}
    if adp: c["adp"] = adp
    return {"dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": id, "state": state, "datePublished": "2022-10-13T00:00:00.000Z"}, "containers": c}

v31 = lambda vec, score: [{"cvssV3_1": {"vectorString": vec, "baseScore": score}}]
cves = [
    cve("CVE-2022-1471", [{"vendor": "SnakeYAML", "product": "SnakeYAML", "packageName": "org.yaml:snakeyaml",
                           "collectionURL": "https://repo.maven.apache.org/maven2",
                           "versions": [{"version": "0", "lessThan": "2.0", "status": "affected", "versionType": "maven"}]}],
        title="Constructor Deserialization Remote Code Execution", metrics=v31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8)),
    cve("CVE-2022-42889", [{"vendor": "Apache Software Foundation", "product": "commons-text",
                            "versions": [{"version": "1.5", "lessThan": "1.10.0", "status": "affected", "versionType": "maven"}]}],
        desc="Apache Commons Text performs variable interpolation. Upgrade to 1.10.0.",
        adp=[{"metrics": v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)}],
        metrics=[{"cvssV4_0": {"vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 9.3}}]),
    cve("CVE-2021-23337", [{"vendor": "lodash", "product": "lodash", "versions": [{"version": ">= 4.0.0, < 4.17.21", "status": "affected"}]}],
        title="Command injection in lodash", metrics=v31("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2)),
    cve("CVE-2021-44906", [{"vendor": "substack", "product": "minimist", "defaultStatus": "affected",
                            "versions": [{"version": "1.2.6", "lessThan": "*", "status": "unaffected", "versionType": "semver"}]}],
        metrics=[{"other": {"type": "x", "content": {"text": "critical"}}}]),
    cve("CVE-2020-11022", [{"vendor": "jquery", "product": "jQuery",
                            "versions": [{"version": "1.2", "lessThan": "3.5.0", "status": "affected", "versionType": "semver"}]}],
        metrics=v31("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)),
    cve("CVE-2021-3749", [{"vendor": "axios", "product": "axios", "versions": [{"version": "0.21.1", "status": "affected"}]}]),
    cve("CVE-2020-36518", [{"vendor": "n/a", "product": "jackson-databind",
                            "versions": [{"version": "2.9.0", "lessThan": "2.12.6.1", "status": "affected"}]}]),
    cve("CVE-2023-2976", [{"vendor": "Google", "product": "guava",
                           "versions": [{"version": "1.0", "lessThan": "32.0.0", "status": "affected"}]}], state="REJECTED"),
    cve("CVE-2021-44228", [{"vendor": "Apache Software Foundation", "product": "Apache Log4j2",
                            "versions": [{"version": "2.0-beta9", "lessThan": "log4j-core*", "status": "affected", "versionType": "custom"}]}],
        title="Log4Shell"),
    cve("CVE-2099-0001", [{"vendor": "Acme", "product": "guava", "versions": [{"version": "0", "lessThan": "99", "status": "affected"}]}]),
]
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
    for r in cves:
        cid = r["cveMetadata"]["cveId"]; y, n = cid.split("-")[1], cid.split("-")[2]
        z.writestr(f"cves/{y}/{n[:-3]}xxx/{cid}.json", json.dumps(r, indent=2))
    z.writestr("cves/deltaLog.json", json.dumps([{"fetchTime": "x", "new": [], "updated": []}]))
with zipfile.ZipFile(os.path.join(out, "db/2026-11-19_all_CVEs_at_midnight.zip.zip"), "w", zipfile.ZIP_STORED) as z:
    z.writestr("cves.zip", inner.getvalue())

# ---------------------------------------------------------------------------------------------------------------------
# An ignore file for the sample projects (golden case ghsa-ignore): for ever, one version, expired, naming nothing, and
# two lines left out (no id, no date)
write("ignore/cvescanner-ignore.csv", """# the sample's reviewed findings
id,package,version,until,reason
CVE-2021-44228,,,,"Not exposed: JNDI lookups disabled, see SEC-12"
GHSA-xvch-5gv4-984h,minimist,1.2.5,2999-12-31,Development tool only
cve-2021-23337,lodash,4.17.15,,Upgrade planned
CVE-2020-36518,,,2020-01-01,Accepted for the 2019 release
CVE-2099-0001,,,,Names nothing
,axios,,,no id
CVE-2022-1471,,,soon,not a date
""")

# ---------------------------------------------------------------------------------------------------------------------
# Components off-the-shelf: a project naming them (inventory, SBOMs, manifests, binaries), a mock NVD feed (JSON 2.0,
# one file for the year), a mock CVE List
write("cots-projects/inventory/cots.csv", """# the sample's components off-the-shelf: name,version[,vendor][,cpe]
name,version,vendor,cpe
GDAL,3.4.1
ffmpeg,4.4.2
libfoo,1.0,acme
renamed,,,cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*
libbar,2.0
zlib,
""")

def nvd(id, matches, status="Analyzed", v31=None, v40=None, desc="Test NVD description. More text."):
    metrics = {}
    if v31: metrics["cvssMetricV31"] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": v31[0], "baseScore": v31[1]}}]
    if v40: metrics["cvssMetricV40"] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "4.0", "vectorString": v40[0], "baseScore": v40[1]}}]
    return {"cve": {"id": id, "sourceIdentifier": "test", "published": "2024-05-01T10:00:00.000", "vulnStatus": status,
                    "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics,
                    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}]}}

def cpe(vendor, product, version="*", **bounds):
    return dict({"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", "matchCriteriaId": "X"}, **bounds)

records = [
    nvd("CVE-2024-1001", [cpe("osgeo", "gdal", versionStartIncluding="3.0.0", versionEndExcluding="3.4.2")],
        v31=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8), desc="Heap overflow in GDAL's reader. More text."),
    nvd("CVE-2024-1002", [cpe("ffmpeg", "ffmpeg", "4.4.2")],
        v40=("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5)),
    nvd("CVE-2024-1003", [cpe("openssl", "openssl", versionEndExcluding="1.1.1l")],
        v31=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5)),
    nvd("CVE-2024-1004", [cpe("osgeo", "gdal")], status="Rejected"),
    nvd("CVE-2024-1005", [cpe("someoneelse", "gdal", versionEndExcluding="9.0")]),
    nvd("CVE-2024-1006", [cpe("bar_project", "libbar", versionEndExcluding="3.0")],
        v31=("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 4.4)),
    nvd("CVE-2024-1007", [cpe("ffmpeg", "ffmpeg", versionEndExcluding="4.0")]),
]
records.append(nvd("CVE-2024-1008", [cpe("libpng", "libpng", versionEndExcluding="1.6.38")],
                   v31=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 6.5)))
write("cots-projects/sbom/bom.cdx.json", json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"component": {"type": "application", "name": "sample-app", "version": "1.0"}},
    "components": [
        {"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        {"type": "library", "name": "core", "version": "1.0.0", "purl": "pkg:npm/%40scope/core@1.0.0"},
        {"type": "library", "name": "libpng", "version": "1.6.37", "cpe": "cpe:2.3:a:libpng:libpng:1.6.37:*:*:*:*:*:*:*",
         "components": [{"type": "library", "name": "zlib", "version": "1.2.11"}]},
        {"type": "library", "name": "<b>unnamed</b>"},
    ]}, indent=2))
write("cots-projects/sbom/app.spdx.json", json.dumps({
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "sample",
    "packages": [
        {"SPDXID": "SPDXRef-1", "name": "FFmpeg", "versionInfo": "4.4.2",
         "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                           "referenceLocator": "cpe:2.3:a:ffmpeg:ffmpeg:4.4.2:*:*:*:*:*:*:*"}]},
        {"SPDXID": "SPDXRef-2", "name": "lodash", "versionInfo": "4.17.15",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:npm/lodash@4.17.15"}]},
        {"SPDXID": "SPDXRef-3", "name": "something", "versionInfo": "NOASSERTION"},
    ]}, indent=2))
records.append(nvd("CVE-2024-1009", [cpe("haxx", "libcurl", versionStartIncluding="7.73.0", versionEndExcluding="7.80.0")],
                   v31=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5)))
records.append(nvd("CVE-2024-1010", [cpe("sqlite", "sqlite", versionEndExcluding="3.37.0")],
                   v31=("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5)))
records.append(nvd("CVE-2024-1011", [cpe("libtiff", "libtiff", "4.3.0")],
                   v31=("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5)))
write("cots-projects/manifests/libtiff-4.pc", """prefix=/usr
libdir=${prefix}/lib
Name: libtiff
Description: Tag Image File Format (TIFF) library.
Version: 4.3.0
Libs: -L${libdir} -ltiff
""")
write("cots-projects/manifests/vcpkg.json", json.dumps({
    "name": "sample", "version": "1.0", "builtin-baseline": "0123456789abcdef",
    "dependencies": ["libxml2", {"name": "sqlite3", "version>=": "3.36.0"}, {"name": "gdal"}],
    "overrides": [{"name": "gdal", "version": "3.4.1#2"}]}, indent=2))
write("cots-projects/manifests/conanfile.txt", """[requires]
libcurl/7.79.1
zlib/[>=1.2.11 <2]

[generators]
CMakeDeps
""")
write("cots-projects/manifests/conan.lock", json.dumps({
    "version": "0.5", "requires": ["openssl/1.1.1k#a1b2c3%1650000000.0"], "build_requires": [], "python_requires": []}, indent=2))

def pad4(b):
    return b + b"\0" * (-len(b) % 4)

def vs_block(key, value=b"", wtype=1, children=b""):
    """A block of a version resource (VS_VERSIONINFO): wLength, wValueLength, wType, key, value, children."""
    import struct
    body = pad4(struct.pack("<HHH", 0, 0, 0) + (key + "\0").encode("utf-16-le"))
    body = pad4(body + value) + children
    value_length = len(value) // 2 if wtype == 1 else len(value)
    return struct.pack("<HHH", len(body), value_length, wtype) + body[6:]

def pe_dll(strings):
    """A minimal 64-bit PE DLL holding only a version resource with these strings: never meant to run."""
    import struct
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, 0x00030004, 0x00010000, 0x00030004, 0x00010000, 0x3F, 0, 4, 2, 0, 0, 0)
    table = b"".join(pad4(vs_block(k, (v + "\0").encode("utf-16-le"))) for k, v in strings.items())
    blob = vs_block("VS_VERSION_INFO", fixed, 0,
                    pad4(vs_block("StringFileInfo", b"", 1, pad4(vs_block("040904B0", b"", 1, table)))))
    def directory(entry_id, target):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", entry_id, target)
    rsrc = directory(16, 0x80000000 | 0x18) + directory(1, 0x80000000 | 0x30) + directory(0x409, 0x48)
    rsrc += struct.pack("<IIII", 0x1000 + 0x58, len(blob), 0, 0) + blob
    raw = len(rsrc) + (-len(rsrc) % 0x200)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into("<II", optional, 112 + 2 * 8, 0x1000, len(rsrc))
    section = b".rsrc\0\0\0" + struct.pack("<IIIIIIHHI", len(rsrc), 0x1000, raw, 0x200, 0, 0, 0, 0, 0x40000040)
    head = dos + coff + bytes(optional) + section
    return head + b"\0" * (0x200 - len(head)) + rsrc + b"\0" * (raw - len(rsrc))

binaries = os.path.join(out, "cots-projects/binaries")
os.makedirs(os.path.join(binaries, "linux"), exist_ok=True)
with open(os.path.join(binaries, "gdal304.dll"), "wb") as f:
    f.write(pe_dll({"CompanyName": "OSGeo", "FileDescription": "GDAL", "FileVersion": "3.4.1.0",
                    "ProductName": "GDAL", "ProductVersion": "3.4.1"}))
for name in ("avcodec-58.dll", "avformat-58.dll", "ffmpeg-4.4.2.exe", "libssl-1_1-x64.dll", "unrelated.dll", "linux/libgdal.so.30"):
    open(os.path.join(binaries, name), "wb").close()
feed = {"resultsPerPage": len(records), "startIndex": 0, "totalResults": len(records), "format": "NVD_CVE",
        "version": "2.0", "timestamp": "2026-11-21T00:00:00.000", "vulnerabilities": records}
with zipfile.ZipFile(os.path.join(out, "db/nvdcve-2.0-2024.json.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("nvdcve-2.0-2024.json", json.dumps(feed))
cots_cves = [
    cve("CVE-2024-2001", [{"vendor": "OSGeo", "product": "GDAL", "versions": [{"version": "0", "lessThan": "3.5.0", "status": "affected"}]}],
        title="GDAL out-of-bounds read", metrics=v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H", 8.1)),
    cve("CVE-2024-1001", [{"vendor": "OSGeo", "product": "GDAL", "versions": [{"version": "3.0.0", "lessThan": "3.4.2", "status": "affected"}]}]),
    cve("CVE-2024-2002", [{"vendor": "n/a", "product": "libbar", "versions": [{"version": "0", "lessThan": "2.5", "status": "affected"}]}]),
]
with zipfile.ZipFile(os.path.join(out, "db/cots-cvelist.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for r in cots_cves:
        z.writestr(f"cves/2024/{r['cveMetadata']['cveId']}.json", json.dumps(r, indent=2))
# ---------------------------------------------------------------------------------------------------------------------
# An installed product (golden case installed): a fat jar and a WAR in an EAR-less layout, an installed node_modules,
# a Python site-packages, a native library holding its version string; and a database of its own
def jar_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in entries:
            z.writestr(name, content)
    return buf.getvalue()

def pom_properties(g, a, v):
    return f"#Generated by Maven\ngroupId={g}\nartifactId={a}\nversion={v}\n"

log4j_jar = jar_bytes([("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
                        pom_properties("org.apache.logging.log4j", "log4j-core", "2.14.1"))])
plain_jar = jar_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Title: plain-lib\nImplementation-Version: 1.0\n"),
                       ("a/B.class", "x")])
text_jar = jar_bytes([("META-INF/maven/org.apache.commons/commons-text/pom.properties",
                       pom_properties("org.apache.commons", "commons-text", "1.9"))])
os.makedirs(os.path.join(out, "installed/app"), exist_ok=True)
os.makedirs(os.path.join(out, "installed/web"), exist_ok=True)
with open(os.path.join(out, "installed/app/app.jar"), "wb") as f:
    f.write(jar_bytes([("META-INF/maven/com.example/app/pom.properties", pom_properties("com.example", "app", "1.0")),
                       ("BOOT-INF/lib/log4j-core-2.14.1.jar", log4j_jar), ("BOOT-INF/lib/plain-1.0.jar", plain_jar)]))
with open(os.path.join(out, "installed/web/shop.war"), "wb") as f:
    f.write(jar_bytes([("WEB-INF/lib/commons-text-1.9.jar", text_jar)]))
# jars without Maven coordinates, checked by their name: one whose OSGi name gives its group, one known by its artifactId
os.makedirs(os.path.join(out, "installed/lib"), exist_ok=True)
with open(os.path.join(out, "installed/lib/commons-text-1.9.jar"), "wb") as f:
    f.write(jar_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nBundle-SymbolicName: org.apache.commons.commons-text\nBundle-Version: 1.9\n")]))
with open(os.path.join(out, "installed/lib/log4j-core-2.14.1.jar"), "wb") as f:
    f.write(jar_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nBundle-SymbolicName: org.apache.logging.log4j.core\nBundle-Version: 2.14.1\n")]))
write("installed/app/node_modules/minimist/package.json", '{"name":"minimist","version":"1.2.5"}')
write("installed/app/node_modules/lodash/package.json", '{"name":"lodash","version":"4.17.20"}')
write("installed/venv/lib/python3.11/site-packages/requests-2.25.0.dist-info/METADATA",
      "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\nSummary: Python HTTP for Humans.\n")
os.makedirs(os.path.join(out, "installed/native"), exist_ok=True)
with open(os.path.join(out, "installed/native/libcrypto.so.1.1"), "wb") as f:
    f.write(b"\x7fELF\x00\x01" + b"OpenSSL 1.1.1k  25 Mar 2021" + b"\x00\xff")
installed_db = [r for r in maven + npm if r["id"] in ("GHSA-jfh8-c2jp-5v3q", "GHSA-599f-7c49-w659", "GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h")]
installed_db.append(osv("GHSA-j8r2-6x86-q33q", "PyPI", "Requests", [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}], ["CVE-2023-32681"], sev="MODERATE"))
with zipfile.ZipFile(os.path.join(out, "db/installed.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for r in installed_db:
        z.writestr(f"advisories/{r['id']}.json", json.dumps(r, indent=2))
    z.writestr("cves/2021/CVE-2021-3711.json", json.dumps(cve("CVE-2021-3711", [{"vendor": "OpenSSL", "product": "OpenSSL",
        "versions": [{"version": "1.1.1", "lessThan": "1.1.1l", "status": "affected"}]}], title="SM2 decryption buffer overflow",
        metrics=v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)), indent=2))

print("fixtures written to", out)
