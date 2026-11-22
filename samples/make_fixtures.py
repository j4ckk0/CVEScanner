#!/usr/bin/env python3
"""Writes CVEScanner's samples: the projects cli/GoldenTest scans, and the made-up databases it scans them with.

Usage: python3 samples/make_fixtures.py OUTDIR    (the repository's: samples)
Writes in OUTDIR:
  projects/  Maven, Gradle, npm, yarn            cots-projects/  inventory, SBOMs, manifests, binaries
  ignore/    an ignore file                      db/  OSV.dev exports, GitHub Advisory Database, CVE List, NVD
  m2/        a local Maven repository, its poms only (--maven-repo)
  gradle-cache/  Gradle's cache, its poms only (--gradle-cache)    projects-gradle-lock/  a build with its lockfile
  python-projects/  requirements, Poetry, uv, Pipenv projects      db/pypi.zip  PyPI advisories
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
# jars without Maven coordinates, checked by their name: one whose OSGi name tells its group, one known by its name alone
os.makedirs(os.path.join(out, "installed/lib"), exist_ok=True)
with open(os.path.join(out, "installed/lib/commons-text-1.9.jar"), "wb") as f:
    f.write(jar_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nBundle-SymbolicName: org.apache.commons.commons-text\nBundle-Version: 1.9\n")]))
with open(os.path.join(out, "installed/lib/log4j-core-2.14.1.jar"), "wb") as f:
    f.write(jar_bytes([("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Title: Apache Log4j Core\nImplementation-Version: 2.14.1\n")]))
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

# ------------------------------------------------------------------ a local Maven repository (m2/), for --maven-repo
# what log4j-core and jackson-databind of projects/maven bring: guava through log4j-core (its failureaccess excluded),
# snakeyaml through guava, its version from a BOM guava's parent imports; commons-text optional, junit for tests only,
# neither followed; checker-qual and jackson's own poms missing; a version range left unresolved
def m2_pom(g, a, v, body):
    deps_xml = body
    write(f"m2/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom",
          f'<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n'
          f'  <groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>\n{deps_xml}</project>\n')

def m2_dep(g, a, v=None, extra=""):
    return (f"    <dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>"
            + (f"<version>{v}</version>" if v else "") + extra + "</dependency>\n")

def m2_deps(*deps):
    return "  <dependencies>\n" + "".join(deps) + "  </dependencies>\n"

def m2_parent(g, a, v):
    return f"  <parent><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></parent>\n"

def m2_managed(*deps):
    return "  <dependencyManagement>\n" + m2_deps(*deps) + "  </dependencyManagement>\n"

m2_pom("org.apache.logging.log4j", "log4j", "2.14.1",
       "  <packaging>pom</packaging>\n  <properties><commons-text.version>1.9</commons-text.version></properties>\n")
m2_pom("org.apache.logging.log4j", "log4j-core", "2.14.1", m2_parent("org.apache.logging.log4j", "log4j", "2.14.1") + m2_deps(
    m2_dep("org.apache.logging.log4j", "log4j-api", "${project.version}"),
    m2_dep("org.apache.commons", "commons-text", "${commons-text.version}", "<optional>true</optional>"),
    m2_dep("com.google.guava", "guava", "31.0-jre",
           "<exclusions><exclusion><groupId>com.google.guava</groupId><artifactId>failureaccess</artifactId></exclusion></exclusions>"),
    m2_dep("junit", "junit", "4.13", "<scope>test</scope>")))
m2_pom("org.apache.logging.log4j", "log4j-api", "2.14.1", "")
m2_pom("com.google.guava", "guava-parent", "31.0-jre", "  <packaging>pom</packaging>\n" + m2_managed(
    m2_dep("org.example", "example-bom", "1.0", "<type>pom</type><scope>import</scope>")))
m2_pom("com.google.guava", "guava", "31.0-jre", m2_parent("com.google.guava", "guava-parent", "31.0-jre") + m2_deps(
    m2_dep("com.google.guava", "failureaccess", "1.0.1"),
    m2_dep("org.checkerframework", "checker-qual", "3.12.0"),
    m2_dep("org.yaml", "snakeyaml"),
    m2_dep("org.example", "ranged", "[1.0,2.0)")))
m2_pom("org.example", "example-bom", "1.0", "  <packaging>pom</packaging>\n" + m2_managed(m2_dep("org.yaml", "snakeyaml", "1.33")))
m2_pom("org.yaml", "snakeyaml", "1.33", "")
m2_pom("com.fasterxml.jackson.core", "jackson-databind", "2.9.8", m2_deps(
    m2_dep("com.fasterxml.jackson.core", "jackson-annotations", "2.9.0"),
    m2_dep("com.fasterxml.jackson.core", "jackson-core", "2.9.8")))

# ------------------------------------------------------------------ Gradle's cache (gradle-cache/), for --gradle-cache
# what projects/gradle's declarations bring: guava raises snakeyaml to 2.0 (the highest asked wins) and brings
# jackson-databind 2.9.8; checker-qual's pom and commons-text's are missing
def gradle_pom(g, a, v, body=""):
    write(f"gradle-cache/files-2.1/{g}/{a}/{v}/5f1c0b2e9d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b/{a}-{v}.pom",
          f'<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n'
          f'  <groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>\n{body}</project>\n')

gradle_pom("com.google.guava", "guava", "31.1-jre", m2_deps(
    m2_dep("com.google.guava", "failureaccess", "1.0.1"),
    m2_dep("org.checkerframework", "checker-qual", "3.12.0"),
    m2_dep("org.yaml", "snakeyaml", "2.0"),
    m2_dep("com.fasterxml.jackson.core", "jackson-databind", "2.9.8")))
gradle_pom("com.google.guava", "failureaccess", "1.0.1")
gradle_pom("org.yaml", "snakeyaml", "1.33")
gradle_pom("org.yaml", "snakeyaml", "2.0")
gradle_pom("com.fasterxml.jackson.core", "jackson-databind", "2.9.8")

# a locked Gradle build (projects-gradle-lock/): its gradle.lockfile gives the versions, the transitive ones included
write("projects-gradle-lock/build.gradle", """plugins { id 'java' }
dependencies {
    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    testImplementation 'junit:junit:4.13'
}
dependencyLocking { lockAllConfigurations() }
""")
write("projects-gradle-lock/gradle.lockfile", """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.apache.logging.log4j:log4j-api:2.14.1=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
org.hamcrest:hamcrest-core:1.3=testCompileClasspath,testRuntimeClasspath
org.yaml:snakeyaml:1.33=runtimeClasspath,testRuntimeClasspath
empty=annotationProcessor,testAnnotationProcessor
""")

# ------------------------------------------------------------------ Python projects (python-projects/) and db/pypi.zip
# requirements with -r, markers, hashes, URLs; a Poetry project and a uv project with their lockfiles; a Pipenv one; a
# pyproject whose range a requirements pin replaces; a virtual environment, skipped
write("python-projects/reqs/requirements.txt", """# the application's requirements
-r base.txt
Django>=3.1,<3.2 ; python_version >= "3.8"
PyYAML==5.3.1 \\
    --hash=sha256:06a0d7ba600ce0b2d2fe2e78453a01e4ae6d2e5a2ec4b9cfc0b1b2f2c3c4d5e6
git+https://github.com/example/tool.git#egg=tool
mypkg @ https://example.org/mypkg-1.0-py3-none-any.whl
-e ./local#egg=local
urllib3<2
--index-url https://pypi.org/simple
""")
write("python-projects/reqs/base.txt", "requests==2.25.0  # pinned for the old API\n")
write("python-projects/poetry/pyproject.toml", """[tool.poetry]
name = "poetry-app"
version = "0.1.0"
description = ""

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.25"
jinja2 = { version = "2.11.2" }

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
""")
write("python-projects/poetry/poetry.lock", """# This file is automatically @generated by Poetry 1.8.3 and should not be changed by hand.

[[package]]
name = "jinja2"
version = "2.11.2"
description = "A very fast and expressive template engine."
optional = false
python-versions = ">=2.7, !=3.0.*"
files = [
    {file = "Jinja2-2.11.2-py2.py3-none-any.whl", hash = "sha256:f0a4641d3cf955324a89c04f3d94663aa4d638abe8f733ecd3582848e1c37035"},
]

[package.dependencies]
MarkupSafe = ">=0.23"

[[package]]
name = "markupsafe"
version = "1.1.1"
description = "Safely add untrusted strings to HTML/XML markup."
optional = false
python-versions = ">=2.7"
files = []

[[package]]
name = "pytest"
version = "7.0.0"
description = "pytest: simple powerful testing with Python"
optional = false
python-versions = ">=3.6"
files = []

[[package]]
name = "requests"
version = "2.25.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=2.7"
files = []

[package.dependencies]
urllib3 = ">=1.21.1,<1.27"

[[package]]
name = "urllib3"
version = "1.26.4"
description = "HTTP library with thread-safe connection pooling."
optional = false
python-versions = ">=2.7"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.9"
content-hash = "2f1c0b"
""")
write("python-projects/uv/pyproject.toml", """[project]
name = "uv-app"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "pyyaml==5.3.1",
    "requests>=2.25",   # what it asks; uv.lock says what it got
]

[dependency-groups]
dev = ["pytest>=7"]
""")
write("python-projects/uv/uv.lock", """version = 1
requires-python = ">=3.10"

[[package]]
name = "pytest"
version = "7.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pyyaml"
version = "5.3.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.25.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "uv-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "pyyaml" },
    { name = "requests" },
]
""")
write("python-projects/pipenv/Pipfile", """[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
django = "==3.1.0"

[dev-packages]
pytest = "*"
""")
write("python-projects/pipenv/Pipfile.lock", json.dumps({
    "_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6, "requires": {}, "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}]},
    "default": {"asgiref": {"hashes": [], "version": "==3.3.1"}, "django": {"hashes": [], "index": "pypi", "version": "==3.1.0"},
                "pytz": {"hashes": [], "version": "==2021.1"}, "sqlparse": {"hashes": [], "version": "==0.4.1"}},
    "develop": {"pytest": {"hashes": [], "index": "pypi", "version": "==7.0.0"},
                "localpkg": {"editable": True, "path": "."}}}, indent=4) + "\n")
write("python-projects/pinned-pyproject/pyproject.toml", """[project]
name = "pinned"
version = "1.0"
dependencies = ["Jinja2>=2.10,<3", "requests"]
""")
write("python-projects/pinned-pyproject/requirements.txt", "jinja2==2.11.2\n")
write("python-projects/poetry/.venv-like/pyvenv.cfg", "home = /usr/bin\n")
write("python-projects/poetry/.venv-like/lib/python3.11/site-packages/requirements.txt", "evil==1.0\n")
write("python-projects/poetry/venv/pyvenv.cfg", "home = /usr/bin\n")
write("python-projects/poetry/venv/requirements.txt", "evil==1.0\n")

pypi = [
    osv("GHSA-j8r2-6x86-q33q", "PyPI", "requests", [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}], ["CVE-2023-32681"], sev="MODERATE"),
    osv("GHSA-q2q7-5pp4-w6pg", "PyPI", "urllib3", [{"introduced": "0"}, {"fixed": "1.26.5"}], ["CVE-2021-33503"], sev="HIGH"),
    osv("GHSA-8q59-q68h-6hv4", "PyPI", "PyYAML", [{"introduced": "0"}, {"fixed": "5.4"}], ["CVE-2020-14343"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    osv("GHSA-g3rq-g295-4j3m", "PyPI", "Jinja2", [{"introduced": "0"}, {"fixed": "2.11.3"}], ["CVE-2020-28493"], sev="MODERATE"),
    osv("GHSA-68w8-qjq3-2gfm", "PyPI", "Django", [{"introduced": "3.1"}, {"fixed": "3.1.13"}], ["CVE-2021-35042"], sev="CRITICAL"),
]
with zipfile.ZipFile(os.path.join(out, "db/pypi.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for r in pypi:
        z.writestr(f"advisories/github-reviewed/2021/06/{r['id']}/{r['id']}.json", json.dumps(r, indent=2))

print("fixtures written to", out)

# ------------------------------------------------------------------ db/examples.zip: the examples' packages
# A made-up database (GitHub Advisory Database layout) with an advisory for each vulnerable package examples/ declares
# or ships, so that every example shows findings without a real database: a CVE of each, mostly the one
# examples/README.md names, the records' text made up. The components off-the-shelf (cots-app) are in
# db/cots-cvelist.zip and the NVD feed.
def ex(n, eco, name, introduced, fixed, cve, sev):
    return osv(f"GHSA-exam-ple{n:02d}-test", eco, name, [{"introduced": introduced}, {"fixed": fixed}], [cve], sev=sev)

examples = [
    # maven-webapp
    ex(1, "Maven", "org.apache.logging.log4j:log4j-core", "2.0-beta9", "2.15.0", "CVE-2021-44228", "CRITICAL"),
    ex(2, "Maven", "org.apache.commons:commons-text", "1.5", "1.10.0", "CVE-2022-42889", "CRITICAL"),
    ex(3, "Maven", "org.springframework:spring-beans", "5.3.0", "5.3.18", "CVE-2022-22965", "CRITICAL"),
    ex(4, "Maven", "org.springframework:spring-webmvc", "5.3.0", "5.3.18", "CVE-2022-22965", "CRITICAL"),
    ex(5, "Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.0", "2.9.9.1", "CVE-2019-12384", "MODERATE"),
    ex(6, "Maven", "org.yaml:snakeyaml", "0", "2.0", "CVE-2022-1471", "HIGH"),
    ex(7, "Maven", "commons-collections:commons-collections", "3.0", "3.2.2", "CVE-2015-7501", "CRITICAL"),
    ex(8, "Maven", "ch.qos.logback:logback-classic", "0", "1.2.13", "CVE-2023-6378", "HIGH"),
    ex(9, "Maven", "com.h2database:h2", "1.4.198", "2.0.206", "CVE-2021-42392", "CRITICAL"),
    # gradle-app
    ex(10, "Maven", "com.google.guava:guava", "1.0", "32.0.0-android", "CVE-2023-2976", "HIGH"),
    ex(11, "Maven", "io.netty:netty-codec-http", "0", "4.1.71.Final", "CVE-2021-43797", "MODERATE"),
    ex(12, "Maven", "com.google.protobuf:protobuf-java", "3.21.0", "3.21.7", "CVE-2022-3171", "HIGH"),
    ex(13, "Maven", "com.thoughtworks.xstream:xstream", "0", "1.4.18", "CVE-2021-39139", "HIGH"),
    ex(14, "Maven", "commons-io:commons-io", "0", "2.7", "CVE-2021-29425", "MODERATE"),
    ex(15, "Maven", "org.apache.httpcomponents:httpclient", "0", "4.5.13", "CVE-2020-13956", "MODERATE"),
    ex(16, "Maven", "junit:junit", "4.7", "4.13.1", "CVE-2020-15250", "MODERATE"),
    # npm-app
    ex(17, "npm", "lodash", "0", "4.17.21", "CVE-2021-23337", "HIGH"),
    ex(18, "npm", "axios", "0", "0.21.1", "CVE-2020-28168", "MODERATE"),
    ex(19, "npm", "follow-redirects", "0", "1.14.7", "CVE-2022-0155", "HIGH"),
    ex(20, "npm", "jquery", "1.2.0", "3.5.0", "CVE-2020-11022", "MODERATE"),
    ex(21, "npm", "moment", "1.0.1", "2.29.2", "CVE-2022-24785", "HIGH"),
    ex(22, "npm", "node-fetch", "0", "2.6.7", "CVE-2022-0235", "HIGH"),
    ex(23, "npm", "json5", "2.0.0", "2.2.2", "CVE-2022-46175", "HIGH"),
    ex(24, "npm", "semver", "0", "5.7.2", "CVE-2022-25883", "MODERATE"),
    ex(25, "npm", "minimist", "0", "1.2.6", "CVE-2021-44906", "CRITICAL"),
    # yarn-app
    ex(26, "npm", "async", "2.0.0", "2.6.4", "CVE-2021-43138", "HIGH"),
    ex(27, "npm", "glob-parent", "0", "5.1.2", "CVE-2020-28469", "HIGH"),
    ex(28, "npm", "marked", "1.1.0", "4.0.10", "CVE-2022-21680", "HIGH"),
    ex(29, "npm", "shell-quote", "0", "1.7.3", "CVE-2021-42740", "CRITICAL"),
    ex(30, "npm", "ua-parser-js", "0", "0.7.24", "CVE-2021-27292", "HIGH"),
    ex(31, "npm", "ws", "7.0.0", "7.4.6", "CVE-2021-32640", "MODERATE"),
    ex(32, "npm", "lodash", "0", "4.17.12", "CVE-2019-10744", "CRITICAL"),
    # installed-app: the jars, node_modules and site-packages it ships
    ex(33, "Maven", "org.apache.struts:struts2-core", "2.0.0", "2.5.26", "CVE-2020-17530", "CRITICAL"),
    ex(34, "Maven", "org.apache.tomcat.embed:tomcat-embed-core", "9.0.0", "9.0.43", "CVE-2021-25122", "HIGH"),
    ex(35, "Maven", "commons-fileupload:commons-fileupload", "0", "1.3.3", "CVE-2016-1000031", "CRITICAL"),
    ex(36, "npm", "qs", "6.7.0", "6.7.3", "CVE-2022-24999", "HIGH"),
    ex(37, "npm", "node-forge", "0", "1.3.0", "CVE-2022-24771", "HIGH"),
    ex(38, "npm", "jsonwebtoken", "0", "9.0.0", "CVE-2022-23529", "HIGH"),
    ex(39, "npm", "express", "0", "4.19.2", "CVE-2024-29041", "MODERATE"),
    ex(40, "PyPI", "django", "3.1", "3.1.6", "CVE-2021-3281", "MODERATE"),
    ex(41, "PyPI", "pillow", "0", "8.1.1", "CVE-2021-25289", "CRITICAL"),
    ex(42, "PyPI", "requests", "2.3.0", "2.31.0", "CVE-2023-32681", "MODERATE"),
    ex(43, "PyPI", "urllib3", "0", "1.26.5", "CVE-2021-33503", "HIGH"),
    ex(44, "PyPI", "jinja2", "0", "2.11.3", "CVE-2020-28493", "MODERATE"),
    ex(45, "PyPI", "pyyaml", "0", "5.4", "CVE-2020-14343", "CRITICAL"),
    ex(46, "npm", "axios", "0", "0.21.2", "CVE-2021-3749", "HIGH"),
]
with zipfile.ZipFile(os.path.join(out, "db/examples.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("advisory-database-main/README.md", "# GitHub Advisory Database (made up for the examples)")
    for r in examples:
        z.writestr(f"advisory-database-main/advisories/github-reviewed/2021/12/{r['id']}/{r['id']}.json", json.dumps(r, indent=2))
