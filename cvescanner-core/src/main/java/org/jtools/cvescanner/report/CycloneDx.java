package org.jtools.cvescanner.report;

/*-
 * #%L
 * CVEScanner
 * %%
 * Copyright (C) 2026 jtools.org
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import static java.nio.charset.StandardCharsets.UTF_8;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanResult;

/**
 * bom.cdx.json: the scan as a CycloneDX 1.6 SBOM, for the tools that read one. Its components are every dependency
 * found, named by their package URL; its vulnerabilities the findings reported, with their base and environmental
 * ratings, and those set aside, analysed "not_affected" (a VEX false_positive kept) with the entry's reason. The
 * same scan gives the same document but for its timestamp: its serial number is made from its content.
 */
final class CycloneDx {

    /** A record's publication: a date and a time, its zone said or not (NVD's are UTC, unsaid). */
    private static final Pattern DATE_TIME = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})?");

    private CycloneDx() {}

    static String bom(ScanResult r, Ignores.Split split, Environment env) {
        var components = new LinkedHashMap<String, Map<String, Object>>();   // by bom-ref: a package version once, its files listed
        for (Dependency d : r.dependencies()) {
            var c = components.computeIfAbsent(ref(d.ecosystem(), d.name(), d.version()), ref -> component(ref, d));
            @SuppressWarnings("unchecked")
            var properties = (List<Map<String, Object>>) c.get("properties");
            var file = property("cvescanner:file", d.file());
            if (!properties.contains(file)) properties.add(file);
        }
        var vulnerabilities = new ArrayList<Map<String, Object>>();
        for (Finding f : split.active()) vulnerabilities.add(vulnerability(f, env, null));
        for (IgnoredFinding i : split.ignored()) vulnerabilities.add(vulnerability(i.finding(), env, i));

        var content = new LinkedHashMap<String, Object>();
        content.put("components", List.copyOf(components.values()));
        content.put("vulnerabilities", vulnerabilities);
        String serial = "urn:uuid:" + UUID.nameUUIDFromBytes(Json.write(content).getBytes(UTF_8));

        var tool = new LinkedHashMap<String, Object>();
        tool.put("type", "application");
        tool.put("name", "CVEScanner");
        String version = version();
        if (version != null) tool.put("version", version);
        var scanned = new LinkedHashMap<String, Object>();
        scanned.put("type", "application");
        scanned.put("bom-ref", "scanned");
        scanned.put("name", r.root().getFileName() == null ? r.root().toString() : r.root().getFileName().toString());
        var metadata = new LinkedHashMap<String, Object>();
        metadata.put("timestamp", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
        metadata.put("tools", ordered("components", List.of(tool)));
        metadata.put("component", scanned);

        var bom = new LinkedHashMap<String, Object>();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", "1.6");
        bom.put("serialNumber", serial);
        bom.put("version", 1);
        bom.put("metadata", metadata);
        bom.putAll(content);
        return Json.write(bom);
    }

    private static Map<String, Object> component(String ref, Dependency d) {
        var c = new LinkedHashMap<String, Object>();
        c.put("type", "library");
        c.put("bom-ref", ref);
        String name = d.name();
        int slash = name.indexOf('/'), colon = name.indexOf(':');
        if (d.ecosystem() == Ecosystem.NPM && name.startsWith("@") && slash > 0) {
            c.put("group", name.substring(0, slash));
            c.put("name", name.substring(slash + 1));
        } else if (d.ecosystem() != Ecosystem.NPM && colon > 0) {
            c.put("group", name.substring(0, colon));
            c.put("name", name.substring(colon + 1));
        } else {
            c.put("name", name);
        }
        c.put("version", d.version());
        String purl = purl(d.ecosystem(), name, d.version());
        if (purl != null) c.put("purl", purl);
        if (d.ecosystem() == Ecosystem.COTS && colon > 0)
            c.put("cpe", "cpe:2.3:a:" + cpe(name.substring(0, colon)) + ":" + cpe(name.substring(colon + 1)) + ":" + cpe(d.version())
                    + ":*:*:*:*:*:*:*");
        var properties = new ArrayList<Map<String, Object>>();
        properties.add(property("cvescanner:ecosystem", d.ecosystem().id()));
        properties.add(property("cvescanner:scope", d.scope()));
        if (d.approximate()) properties.add(property("cvescanner:approximate", "true"));
        c.put("properties", properties);
        return c;
    }

    private static Map<String, Object> vulnerability(Finding f, Environment env, IgnoredFinding ignored) {
        var v = new LinkedHashMap<String, Object>();
        v.put("id", f.id());
        v.put("source", source(f.id(), f.url()));
        var references = new ArrayList<Map<String, Object>>();
        for (String other : f.cves().isEmpty() ? f.aliases() : concat(f.cves(), f.aliases()))
            if (!other.equals(f.id()) && references.stream().noneMatch(m -> m.get("id").equals(other)))
                references.add(ordered("id", other, "source", source(other, null)));
        if (!references.isEmpty()) v.put("references", references);
        var ratings = new ArrayList<Map<String, Object>>();
        var base = new LinkedHashMap<String, Object>();
        if (f.cvss() != null) base.put("score", f.cvss());
        base.put("severity", severity(f.score().baseSeverity().name()));
        base.put("method", method(f.score().version()));
        if (f.score().baseVector() != null) base.put("vector", f.score().baseVector());
        ratings.add(base);
        if (f.envScore() != null) {
            var environmental = new LinkedHashMap<String, Object>();
            environmental.put("score", f.envScore());
            environmental.put("severity", severity(f.severity().name()));
            environmental.put("method", method(f.score().version()));
            if (f.score().envVector() != null) environmental.put("vector", f.score().envVector());
            environmental.put("justification", "environmental score: " + env.name(I18nLanguage.ENGLISH));
            ratings.add(environmental);
        }
        v.put("ratings", ratings);
        if (!f.summary().isBlank()) v.put("description", f.summary());
        if (!f.fixedIn().isEmpty()) v.put("recommendation", "Upgrade to " + f.fixedIn());
        v.put("advisories", List.of(ordered("url", f.url())));
        var published = DATE_TIME.matcher(f.published());
        if (published.matches()) v.put("published", published.group(2) == null ? f.published() + "Z" : f.published());
        if (ignored != null) {
            var analysis = new LinkedHashMap<String, Object>();
            // a VEX document's false_positive stays one; an ignore file's entry, and the rest, say it does not apply
            analysis.put("state", ignored.rule().fromVex() && ignored.rule().reason().startsWith("false_positive") ? "false_positive" : "not_affected");
            analysis.put("detail", ignored.rule().reason() + (ignored.rule().until() == null ? ""
                    : " (set aside until " + ignored.rule().until() + ")"));
            v.put("analysis", analysis);
        }
        v.put("affects", List.of(ordered("ref", ref(f.ecosystem(), f.pkg(), f.version()))));
        var properties = new ArrayList<Map<String, Object>>();
        properties.add(property("cvescanner:match", f.basis().name()));
        properties.add(property("cvescanner:file", f.file()));
        v.put("properties", properties);
        return v;
    }

    /** Where an id comes from: a CVE from NVD, a GitHub advisory from GitHub, the others from OSV.dev. */
    private static Map<String, Object> source(String id, String url) {
        var s = new LinkedHashMap<String, Object>();
        if (id.startsWith("CVE-")) {
            s.put("name", "NVD");
            s.put("url", "https://nvd.nist.gov/vuln/detail/" + id);
        } else if (id.startsWith("GHSA-")) {
            s.put("name", "GitHub");
            s.put("url", "https://github.com/advisories/" + id);
        } else {
            s.put("name", "OSV");
            s.put("url", url != null && url.startsWith("https://osv.dev/") ? url : "https://osv.dev/vulnerability/" + id);
        }
        return s;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        var all = new ArrayList<>(a);
        all.addAll(b);
        return all;
    }

    /** An object whose keys keep their order, so that the same scan writes the same text (Map.of keeps none). */
    private static Map<String, Object> ordered(Object... keysAndValues) {
        var m = new LinkedHashMap<String, Object>();
        for (int i = 0; i < keysAndValues.length; i += 2) m.put((String) keysAndValues[i], keysAndValues[i + 1]);
        return m;
    }

    private static Map<String, Object> property(String name, String value) {
        var p = new LinkedHashMap<String, Object>();
        p.put("name", name);
        p.put("value", value);
        return p;
    }

    private static String severity(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    /** The CVSS version as CycloneDX names its methods; "other" for an advisory's rating without a vector. */
    private static String method(String version) {
        if (version == null) return "other";
        return switch (version) {
            case "4.0" -> "CVSSv4";
            case "3.1" -> "CVSSv31";
            case "3.0" -> "CVSSv3";
            case "2.0" -> "CVSSv2";
            default -> "other";
        };
    }

    /** A component's reference: its package URL, or ecosystem:name@version when it has none. */
    static String ref(Ecosystem eco, String name, String version) {
        String purl = purl(eco, name, version);
        return purl != null ? purl : eco.id().toLowerCase(Locale.ROOT) + ":" + name + "@" + version;
    }

    /**
     * The package URL (purl): pkg:maven/group/artifact@1.0, pkg:npm/%40scope/name@1.0, pkg:pypi/name@1.0,
     * pkg:generic/product@1.0 for a component off-the-shelf; null for a jar known by its artifactId alone.
     */
    static String purl(Ecosystem eco, String name, String version) {
        String v = "@" + encode(version);
        return switch (eco) {
            case MAVEN -> {
                int colon = name.indexOf(':');
                yield colon > 0 ? "pkg:maven/" + encode(name.substring(0, colon)) + "/" + encode(name.substring(colon + 1)) + v : null;
            }
            case NPM -> {
                int slash = name.indexOf('/');
                yield name.startsWith("@") && slash > 0 ? "pkg:npm/" + encode(name.substring(0, slash)) + "/" + encode(name.substring(slash + 1)) + v
                        : "pkg:npm/" + encode(name) + v;
            }
            case PYPI -> "pkg:pypi/" + encode(Ecosystem.pep503(name)) + v;
            case COTS -> "pkg:generic/" + encode(Ecosystem.product(name)) + v;
        };
    }

    /** A purl segment: letters, digits and .-_~ as they are, every other byte percent-encoded (@ as %40, + as %2B). */
    private static String encode(String s) {
        var sb = new StringBuilder();
        for (byte b : s.getBytes(UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || ".-_~".indexOf(c) >= 0) sb.append(c);
            else sb.append('%').append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    /** A CPE 2.3 value: lower case, its special characters escaped. */
    private static String cpe(String s) {
        return s.toLowerCase(Locale.ROOT).replaceAll("([^a-z0-9._-])", "\\\\$1");
    }

    /** The program's version, as its module or its jar's manifest says it; null when run from the classes. */
    private static String version() {
        Module module = CycloneDx.class.getModule();
        if (module.isNamed() && module.getDescriptor().rawVersion().isPresent()) return module.getDescriptor().rawVersion().get();
        return CycloneDx.class.getPackage().getImplementationVersion();
    }
}
