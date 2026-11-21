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
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.jtools.cvescanner.cvss.Cvss;
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

public final class Osv {
    public record Match(Map<String, Object> vuln, Map<String, Object> affected) {}

    private Osv() {}

    private static String eventVersion(Map<String, Object> e) {
        for (String k : List.of("introduced", "fixed", "last_affected", "limit"))
            if (e.get(k) instanceof String s) return s;
        return "0";
    }

    static boolean inRange(String eco, String version, List<Object> events) {
        var evs = new ArrayList<Map<String, Object>>();
        for (Object o : events) evs.add(Json.obj(o));
        evs.sort((a, b) -> {
            String va = eventVersion(a), vb = eventVersion(b);
            if (va.equals("0") || vb.equals("0")) return Boolean.compare(!va.equals("0"), !vb.equals("0"));
            return Versions.compare(eco, va, vb);
        });
        boolean affected = false;
        for (var e : evs) {
            if (e.get("introduced") instanceof String intro) {
                if (intro.equals("0") || Versions.compare(eco, version, intro) >= 0) affected = true;
            } else if (e.get("fixed") instanceof String fixed) {
                if (Versions.compare(eco, version, fixed) >= 0) affected = false;
            } else if (e.get("last_affected") instanceof String last) {
                if (Versions.compare(eco, version, last) > 0) affected = false;
            }
        }
        return affected;
    }

    public static boolean isAffected(String eco, String version, Map<String, Object> affected) {
        if (Json.arr(affected.get("versions")).contains(version)) return true;
        for (Object r : Json.arr(affected.get("ranges"))) {
            var range = Json.obj(r);
            String type = Json.str(range, "type");
            if (("ECOSYSTEM".equals(type) || "SEMVER".equals(type)) && inRange(eco, version, Json.arr(range.get("events"))))
                return true;
        }
        return false;
    }

    static String nextFixed(String eco, String version, Map<String, Object> affected) {
        return Versions.nearestFix(eco, version, Json.arr(affected.get("ranges")).stream()
                .flatMap(r -> Json.arr(Json.obj(r).get("events")).stream())
                .map(e -> Json.str(Json.obj(e), "fixed")).toList());
    }

    /** CVSS data of an advisory: the highest-scoring v3.x and v4.0 vectors, plus the textual rating. */
    static Rating ratingOf(Map<String, Object> vuln, Map<String, Object> affected) {
        var all = new ArrayList<Object>(Json.arr(affected.get("severity")));
        all.addAll(Json.arr(vuln.get("severity")));
        String v3 = null, v4 = null;
        for (Object o : all) {
            var s = Json.obj(o);
            String type = Json.str(s, "type"), vector = Json.str(s, "score");
            if (vector == null) continue;
            if ("CVSS_V3".equals(type)) v3 = higher(v3, vector);
            else if ("CVSS_V4".equals(type)) v4 = higher(v4, vector);
        }
        Severity rating = Severity.UNKNOWN;
        String ds = Json.str(Json.obj(vuln.get("database_specific")), "severity");
        if (ds != null) rating = Severity.fromRating(ds);
        if (rating == Severity.UNKNOWN && String.valueOf(vuln.get("id")).startsWith("MAL-")) rating = Severity.CRITICAL; // malicious pkg
        return new Rating(rating, null, v3, v4);
    }

    /** Of two vectors, the valid one with the higher base score. */
    static String higher(String current, String candidate) {
        Double c = Cvss.baseScore(candidate);
        if (c == null) return current;
        Double cur = current == null ? null : Cvss.baseScore(current);
        return cur == null || c > cur ? candidate : current;
    }

    public static Finding toFinding(Dependency d, Match m) {
        var v = m.vuln();
        String id = Json.str(v, "id");
        var aliases = Json.arr(v.get("aliases")).stream().filter(String.class::isInstance).map(String.class::cast).toList();
        var cves = Stream.concat(Stream.of(id), aliases.stream()).filter(x -> x.startsWith("CVE-")).distinct().sorted().toList();
        String details = Objects.requireNonNullElse(Json.str(v, "details"), "");
        String summary = Json.str(v, "summary");
        if (summary == null || summary.isBlank()) summary = details.lines().findFirst().orElse("");
        var f = new Finding(Severity.UNKNOWN, null, d.ecosystem(), d.name(), d.version(), d.approximate(),
                d.scope(), d.file(), id, cves, aliases, nextFixed(d.ecosystem(), d.version(), m.affected()),
                summary.strip(), details, Objects.requireNonNullElse(Json.str(v, "published"), ""),
                "https://osv.dev/vulnerability/" + id, MatchBasis.ADVISORY,
                Phrase.of("match.note.advisory"), ratingOf(v, m.affected()));
        return Scoring.apply(f, Environment.NONE, true);
    }
}
