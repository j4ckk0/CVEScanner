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

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Scoring;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.json.JsonStream;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;
import org.jtools.cvescanner.version.Versions;

/**
 * NVD's CVE feeds (JSON 2.0, https://nvd.nist.gov/feeds/json/cve/2.0/): the products a CVE affects, as CPEs
 * (cpe:2.3:a:vendor:product:version…) with version ranges — what components off-the-shelf (GDAL, FFmpeg…) are checked
 * against. A feed is read as a stream, a record at a time (JsonStream); only the records naming a product of the scan
 * are parsed.
 */
public final class NvdFeed {

    /** One vulnerable CPE of a CVE: its vendor and product, its version ("*" for a range), and the range's bounds. */
    public record Rule(CveList.Info info, String cpe, String vendor, String product, String version,
                       String startIncluding, String startExcluding, String endIncluding, String endExcluding) {}

    private static final Pattern CPE_PRODUCT = Pattern.compile("cpe:2\\.3:[aho]:([^:\"]+):([^:\"]+):");

    private NvdFeed() {}

    /**
     * Reads a feed, handing over the rules of the products asked for (lower case). Returns the number of records read,
     * and adds to used the ids of those that gave a rule.
     */
    static int read(Reader feed, Set<String> products, Consumer<Rule> sink, Set<String> used, Runnable onRecord)
            throws IOException {
        int[] records = {0};
        JsonStream.forEachElement(feed, "vulnerabilities", text -> {
            records[0]++;
            onRecord.run();
            if (!mentions(text, products)) return;
            List<Rule> rules;
            try {
                rules = rules(Json.obj(Json.obj(Json.parse(text)).get("cve")));
            } catch (RuntimeException _) {
                return;   // a record of a shape not foreseen: left out, the feed's others read
            }
            for (Rule rule : rules) {
                if (products.contains(rule.product())) {
                    sink.accept(rule);
                    used.add(rule.info().id());
                }
            }
        });
        return records[0];
    }

    /** Whether the record's text names one of these products in a CPE: the cheap test before it is parsed. */
    private static boolean mentions(String text, Set<String> products) {
        Matcher m = CPE_PRODUCT.matcher(text);
        while (m.find()) if (products.contains(unescape(m.group(2)))) return true;
        return false;
    }

    /** The rules of a record (its "cve" object): one per vulnerable CPE; none for a rejected CVE. */
    static List<Rule> rules(Map<String, Object> cve) {
        String id = Json.str(cve, "id");
        if (id == null || "Rejected".equalsIgnoreCase(Json.str(cve, "vulnStatus"))) return List.of();
        String description = Json.arr(cve.get("descriptions")).stream().map(Json::obj)
                .filter(m -> Objects.requireNonNullElse(Json.str(m, "lang"), "en").toLowerCase(Locale.ROOT).startsWith("en"))
                .map(m -> Json.str(m, "value")).filter(Objects::nonNull).findFirst().orElse("");
        var info = new CveList.Info(id, CveList.firstSentence(description), description,
                Objects.requireNonNullElse(Json.str(cve, "published"), ""), rating(Json.obj(cve.get("metrics"))));
        var out = new ArrayList<Rule>();
        for (Object configuration : Json.arr(cve.get("configurations")))
            for (Object node : Json.arr(Json.obj(configuration).get("nodes")))
                for (Object match : Json.arr(Json.obj(node).get("cpeMatch"))) {
                    var m = Json.obj(match);
                    String criteria = Json.str(m, "criteria");
                    if (!Boolean.TRUE.equals(m.get("vulnerable")) || criteria == null) continue;
                    String[] parts = splitCpe(criteria);
                    if (parts.length < 6) continue;
                    out.add(new Rule(info, criteria, unescape(parts[3]), unescape(parts[4]), unescape(parts[5]),
                            Json.str(m, "versionStartIncluding"), Json.str(m, "versionStartExcluding"),
                            Json.str(m, "versionEndIncluding"), Json.str(m, "versionEndExcluding")));
                }
        return out;
    }

    /** A CPE 2.3 name's fields: split on the colons a backslash does not escape. */
    static String[] splitCpe(String cpe) {
        var parts = new ArrayList<String>();
        var field = new StringBuilder();
        for (int i = 0; i < cpe.length(); i++) {
            char c = cpe.charAt(i);
            if (c == '\\' && i + 1 < cpe.length()) {
                field.append(c).append(cpe.charAt(++i));
            } else if (c == ':') {
                parts.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        parts.add(field.toString());
        return parts.toArray(String[]::new);
    }

    /** A CPE field as a name: its escapes removed, in lower case ("node\.js" → "node.js"). */
    static String unescape(String field) {
        return field.replace("\\", "").toLowerCase(Locale.ROOT);
    }

    /** Whether the version falls in the rule: its CPE's own version, or its range ("*" and no bound: every version). */
    public static boolean affected(String version, Rule r) {
        String eco = "COTS";
        if (!r.version().equals("*") && !r.version().equals("-")) return Versions.compare(eco, version, r.version()) == 0;
        if (r.startIncluding() != null && Versions.compare(eco, version, r.startIncluding()) < 0) return false;
        if (r.startExcluding() != null && Versions.compare(eco, version, r.startExcluding()) <= 0) return false;
        if (r.endIncluding() != null && Versions.compare(eco, version, r.endIncluding()) > 0) return false;
        if (r.endExcluding() != null && Versions.compare(eco, version, r.endExcluding()) >= 0) return false;
        return !r.version().equals("-");
    }

    /**
     * How the rule names the component: by vendor and product (CPE), by product only when the component's vendor is
     * not known (CPE_PRODUCT, to check); null when the vendors differ — another product of the same name.
     */
    public static MatchBasis basis(Dependency d, Rule r) {
        int colon = d.name().indexOf(':');
        if (colon < 0) return MatchBasis.CPE_PRODUCT;
        return d.name().substring(0, colon).toLowerCase(Locale.ROOT).equals(r.vendor()) ? MatchBasis.CPE : null;
    }

    public static Finding toFinding(Dependency d, Rule r, MatchBasis basis) {
        var i = r.info();
        Phrase note = basis == MatchBasis.CPE ? Phrase.of("match.note.cpe", r.cpe())
                : Phrase.of("match.note.cpeProduct", r.product(), r.vendor());
        String fixed = r.endExcluding() != null ? Versions.nearestFix("COTS", d.version(), List.of(r.endExcluding())) : "";
        var f = new Finding(Severity.UNKNOWN, null, d.ecosystem(), d.name(), d.version(), d.approximate(), d.scope(), d.file(),
                i.id(), List.of(i.id()), List.of(), fixed, i.summary(), i.details(), i.published(),
                "https://nvd.nist.gov/vuln/detail/" + i.id(), basis, note, i.rating());
        return Scoring.apply(f, Environment.NONE, true);
    }

    /** CVSS data from the record's metrics: the best v4.0 and v3.x vectors, else a reported score, and a rating. */
    private static Rating rating(Map<String, Object> metrics) {
        String v3 = null, v4 = null, text = null;
        Double reported = null;
        for (String key : List.of("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")) {
            for (Object o : Json.arr(metrics.get(key))) {
                var m = Json.obj(o);
                var data = Json.obj(m.get("cvssData"));
                String vector = Json.str(data, "vectorString");
                if (vector != null && key.equals("cvssMetricV40")) v4 = Osv.higher(v4, vector);
                else if (vector != null && !key.equals("cvssMetricV2")) v3 = Osv.higher(v3, vector);
                if (data.get("baseScore") instanceof Number n && (reported == null || n.doubleValue() > reported))
                    reported = n.doubleValue();
                String severity = Json.str(data, "baseSeverity");   // v3.x and v4.0 in cvssData, v2 beside it
                if (severity == null) severity = Json.str(m, "baseSeverity");
                if (text == null) text = severity;
            }
        }
        return new Rating(text == null ? Severity.UNKNOWN : Severity.fromRating(text),
                v3 == null && v4 == null ? reported : null, v3, v4);
    }
}
