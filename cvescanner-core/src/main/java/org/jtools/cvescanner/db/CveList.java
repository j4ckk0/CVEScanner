package org.jtools.cvescanner.db;

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


import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Scoring;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;
import org.jtools.cvescanner.version.Versions;

/**
 * CVE List (CVE JSON 5) support. CVE records describe products in free text (vendor/product), so a record is
 * matched to a dependency when it names the package (packageName, or product equal to "group:artifact"), or,
 * flagged as a name match, when the product equals the npm name / Maven artifactId (and the vendor appears in
 * the groupId).
 */
public final class CveList {
    public record Info(String id, String summary, String details, String published, Rating rating) {}

    public record Rule(Info info, String vendor, String product, String packageName, String collectionUrl,
                String defaultStatus, List<Map<String, Object>> versions) {
        List<String> keys() {
            var k = new ArrayList<String>();
            if (meaningful(product)) k.add(normalize(product));
            if (meaningful(packageName)) k.add(normalize(packageName));
            return k;
        }
    }

    private static final Set<String> PLACEHOLDERS = Set.of("n/a", "na", "unknown", "unspecified", "*", "-", "");
    private static final Set<String> VENDOR_NOISE = Set.of("software", "foundation", "inc", "the", "project", "team",
            "llc", "ltd", "corp", "corporation", "company", "group", "open", "source", "community", "org", "com", "net", "and");
    private static final Pattern CONSTRAINT = Pattern.compile("(>=|<=|>|<|=)\\s*v?([0-9][^\\s,<>=|]*)");

    private CveList() {}

    static boolean meaningful(String s) { return s != null && !PLACEHOLDERS.contains(s.strip().toLowerCase(Locale.ROOT)); }

    static String normalize(String s) { return s.strip().toLowerCase(Locale.ROOT); }

    static List<String> keysFor(Dependency d) {
        String name = normalize(d.name());
        if (d.ecosystem().equals(VulnDb.COTS)) return List.of(VulnDb.product(d));
        if (!d.ecosystem().equals("Maven")) return List.of(name);
        return List.of(name, name.replace(':', '/'), name.substring(name.indexOf(':') + 1));
    }

    static List<Rule> rules(Map<String, Object> rec) {
        var meta = Json.obj(rec.get("cveMetadata"));
        String id = Json.str(meta, "cveId");
        if (id == null || "REJECTED".equalsIgnoreCase(Json.str(meta, "state"))) return List.of();
        var containers = Json.obj(rec.get("containers"));
        var cna = Json.obj(containers.get("cna"));
        String description = Json.arr(cna.get("descriptions")).stream().map(Json::obj)
                .filter(m -> Objects.requireNonNullElse(Json.str(m, "lang"), "en").toLowerCase(Locale.ROOT).startsWith("en"))
                .map(m -> Json.str(m, "value")).filter(Objects::nonNull).findFirst().orElse("");
        String title = Json.str(cna, "title");
        String summary = meaningful(title) ? title.strip() : firstSentence(description);
        var rating = rating(containers);
        var info = new Info(id, summary, description, Objects.requireNonNullElse(Json.str(meta, "datePublished"), ""), rating);
        var out = new ArrayList<Rule>();
        for (Object a : Json.arr(cna.get("affected"))) {
            var aff = Json.obj(a);
            out.add(new Rule(info, Json.str(aff, "vendor"), Json.str(aff, "product"), Json.str(aff, "packageName"),
                    Json.str(aff, "collectionURL"), Json.str(aff, "defaultStatus"),
                    Json.arr(aff.get("versions")).stream().map(Json::obj).toList()));
        }
        return out;
    }

    static String firstSentence(String s) {
        s = s.replaceAll("\\s+", " ").strip();
        int dot = s.indexOf(". ");
        if (dot > 0 && dot < 200) return s.substring(0, dot + 1);
        return s.length() <= 200 ? s : s.substring(0, 199) + "…";
    }

    /** CVSS data from cna.metrics and adp[].metrics: best v3.x / v4.0 vectors, else a reported score or rating. */
    private static Rating rating(Map<String, Object> containers) {
        var metrics = new ArrayList<Object>(Json.arr(Json.obj(containers.get("cna")).get("metrics")));
        for (Object adp : Json.arr(containers.get("adp"))) metrics.addAll(Json.arr(Json.obj(adp).get("metrics")));
        String v3 = null, v4 = null, text = null;
        Double reported3 = null, reported4 = null, reported2 = null;
        for (Object o : metrics) {
            var m = Json.obj(o);
            for (String key : List.of("cvssV3_1", "cvssV3_0")) {
                var c = Json.obj(m.get(key));
                if (Json.str(c, "vectorString") != null) v3 = Osv.higher(v3, Json.str(c, "vectorString"));
                reported3 = max(reported3, number(c.get("baseScore")));
                if (text == null) text = Json.str(c, "baseSeverity");
            }
            var c4 = Json.obj(m.get("cvssV4_0"));
            if (Json.str(c4, "vectorString") != null) v4 = Osv.higher(v4, Json.str(c4, "vectorString"));
            reported4 = max(reported4, number(c4.get("baseScore")));
            reported2 = max(reported2, number(Json.obj(m.get("cvssV2_0")).get("baseScore")));
            if (text == null) text = Json.str(c4, "baseSeverity");
            if (text == null) text = Json.str(Json.obj(Json.obj(m.get("other")).get("content")), "text");
        }
        // a score without a usable vector can still be shown (but not adjusted to the environment)
        Double reported = v3 == null && v4 == null ? (reported3 != null ? reported3 : reported4 != null ? reported4 : reported2) : null;
        return new Rating(text == null ? Severity.UNKNOWN : Severity.fromRating(text), reported, v3, v4);
    }

    private static Double max(Double a, Double b) {
        if (a == null) return b;
        if (b == null) return a;
        return Math.max(a, b);
    }

    private static Double number(Object o) { return o instanceof Number n ? n.doubleValue() : null; }

    /** Returns how this CVE affected-entry relates to the dependency, or null if it doesn't apply. */
    public static MatchBasis basis(Dependency d, Rule r) {
        boolean maven = d.ecosystem().equals("Maven");
        String name = normalize(d.name());
        if (meaningful(r.packageName())) {
            String pn = normalize(r.packageName());
            String url = Objects.requireNonNullElse(r.collectionUrl(), "").toLowerCase(Locale.ROOT);
            boolean registryOk = url.isEmpty() || (maven ? url.contains("maven") : url.contains("npm"));
            return registryOk && (pn.equals(name) || (maven && pn.equals(name.replace(':', '/')))) ? MatchBasis.CVE_PACKAGE : null;
        }
        if (!meaningful(r.product())) return null;
        String product = normalize(r.product());
        if (d.ecosystem().equals(VulnDb.COTS)) {
            // the record's vendor is free text ("The OpenSSL Project"): a word of it in the component's CPE vendor will do
            if (!product.equals(VulnDb.product(d))) return null;
            int colon = d.name().indexOf(':');
            return colon > 0 && vendorMatchesGroup(r.vendor(), normalize(d.name().substring(0, colon)))
                    ? MatchBasis.CVE_PACKAGE : MatchBasis.CVE_NAME;
        }
        if (!maven) return product.equals(name) ? MatchBasis.CVE_NAME : null;
        if (product.equals(name) || product.equals(name.replace(':', '/'))) return MatchBasis.CVE_PACKAGE;
        String group = name.substring(0, name.indexOf(':')), artifact = name.substring(name.indexOf(':') + 1);
        return product.equals(artifact) && artifact.length() >= 4 && vendorMatchesGroup(r.vendor(), group) ? MatchBasis.CVE_NAME : null;
    }

    private static boolean vendorMatchesGroup(String vendor, String group) {
        if (!meaningful(vendor)) return false;
        for (String w : normalize(vendor).split("[^a-z0-9]+"))
            if (w.length() >= 3 && !VENDOR_NOISE.contains(w) && group.contains(w)) return true;
        return false;
    }

    private static String clean(String s) {
        if (s == null) return null;
        s = s.strip();
        return s.length() > 1 && (s.charAt(0) == 'v' || s.charAt(0) == 'V') && Character.isDigit(s.charAt(1)) ? s.substring(1) : s;
    }

    private static boolean startsWithDigit(String s) { return s != null && !s.isEmpty() && Character.isDigit(s.charAt(0)); }

    /** Whether version v falls in this CVE version entry; null if the entry can't be evaluated. */
    static Boolean contains(String eco, String v, Map<String, Object> e) {
        String base = clean(Json.str(e, "version")), lt = clean(Json.str(e, "lessThan")), lte = clean(Json.str(e, "lessThanOrEqual"));
        if (lt != null || lte != null) {
            String upper = lt != null ? lt : lte;
            if (!upper.equals("*") && !startsWithDigit(upper)) return null;          // e.g. "log4j-core*"
            boolean lowerOk;
            if (base == null || !meaningful(base) || base.equals("0")) lowerOk = true;
            else if (!startsWithDigit(base)) return null;
            else lowerOk = Versions.compare(eco, v, base) >= 0;
            boolean upperOk = upper.equals("*") || (lt != null ? Versions.compare(eco, v, lt) < 0 : Versions.compare(eco, v, lte) <= 0);
            return lowerOk && upperOk;
        }
        if (base == null) return null;
        if (base.matches(".*[<>=].*")) {                                         // e.g. ">= 2.0.0, < 2.15.0"
            var m = CONSTRAINT.matcher(base);
            boolean any = false, ok = true;
            while (m.find()) {
                any = true;
                int c = Versions.compare(eco, v, m.group(2));
                ok &= switch (m.group(1)) {
                    case ">=" -> c >= 0;
                    case ">" -> c > 0;
                    case "<=" -> c <= 0;
                    case "<" -> c < 0;
                    default -> c == 0;
                };
            }
            return any ? ok : null;
        }
        return startsWithDigit(base) ? Versions.compare(eco, v, base) == 0 : null;
    }

    public static boolean affected(String eco, String version, Rule r) {
        boolean affected = false, unaffectedListed = false;
        for (var e : r.versions()) {
            String status = Objects.requireNonNullElse(Json.str(e, "status"), "affected").toLowerCase(Locale.ROOT);
            Boolean inside = contains(eco, version, e);
            if (inside == null) continue;
            if (status.equals("unaffected")) {
                unaffectedListed = true;
                if (inside) return false;
            } else if (status.equals("affected") && inside) {
                affected = true;
            }
        }
        return affected || (unaffectedListed && "affected".equalsIgnoreCase(r.defaultStatus()));
    }

    static String fixedVersion(String eco, String v, Rule r) {
        var candidates = new ArrayList<String>();
        for (var e : r.versions()) {
            String status = Objects.requireNonNullElse(Json.str(e, "status"), "affected").toLowerCase(Locale.ROOT);
            String base = clean(Json.str(e, "version")), lt = clean(Json.str(e, "lessThan"));
            boolean inside = Boolean.TRUE.equals(contains(eco, v, e));
            if (status.equals("affected") && inside && startsWithDigit(lt)) candidates.add(lt);
            if (status.equals("affected") && inside && base != null && base.contains("<")) {
                var m = CONSTRAINT.matcher(base);
                while (m.find()) if (m.group(1).equals("<")) candidates.add(m.group(2));
            }
            if (status.equals("unaffected") && startsWithDigit(base) && Versions.compare(eco, base, v) > 0) candidates.add(base);
        }
        return Versions.nearestFix(eco, v, candidates);
    }

    public static Finding toFinding(Dependency d, Rule r, MatchBasis basis) {
        var i = r.info();
        Phrase note = basis == MatchBasis.CVE_PACKAGE
                ? (meaningful(r.packageName()) ? Phrase.of("match.note.packageNamed", r.packageName().strip()) : Phrase.of("match.note.package"))
                : (meaningful(r.vendor()) ? Phrase.of("match.note.nameVendor", r.product().strip(), r.vendor().strip())
                                          : Phrase.of("match.note.name", r.product().strip()));
        var f = new Finding(Severity.UNKNOWN, null, d.ecosystem(), d.name(), d.version(), d.approximate(), d.scope(), d.file(),
                i.id(), List.of(i.id()), List.of(), fixedVersion(d.ecosystem(), d.version(), r), i.summary(), i.details(),
                i.published(), "https://www.cve.org/CVERecord?id=" + i.id(), basis, note, i.rating());
        return Scoring.apply(f, Environment.NONE, true);
    }
}
