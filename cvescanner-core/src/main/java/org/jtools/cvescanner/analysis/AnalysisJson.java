package org.jtools.cvescanner.analysis;

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

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.VexStatement;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Unresolved;

/**
 * The records of a scan as the analysis file's JSON writes them, and back: each as an object of its fields, an enum by
 * its name, a date as ISO writes it, a null as null. A phrase is its key and its arguments, each a number, a phrase or
 * a text, so that it is said in the language of wherever it is read.
 */
final class AnalysisJson {
    private AnalysisJson() {}

    /** A field of an object that is not as it should be: the file is not one this program wrote. */
    static final class Malformed extends RuntimeException {
        Malformed(String what) { super(what); }
    }

    // ------------------------------------------------------------------------------------------- dependencies
    static Map<String, Object> dependency(Dependency d) {
        var m = new LinkedHashMap<String, Object>();
        m.put("ecosystem", d.ecosystem().id());
        m.put("name", d.name());
        m.put("version", d.version());
        m.put("file", d.file());
        m.put("scope", d.scope());
        m.put("approximate", d.approximate());
        m.put("bundle", d.bundle());
        m.put("parents", d.parents());   // null when its file does not record them, not the same as none
        return m;
    }

    static Dependency dependency(Object o) {
        var m = Json.obj(o);
        return new Dependency(ecosystem(m), required(m, "name"), required(m, "version"), required(m, "file"), required(m, "scope"),
                flag(m, "approximate"), text(m, "bundle"), m.get("parents") == null ? null : texts(m, "parents"));
    }

    static Map<String, Object> unresolved(Unresolved u) {
        var m = new LinkedHashMap<String, Object>();
        m.put("ecosystem", u.ecosystem().id());
        m.put("name", u.name());
        m.put("declared", u.declared());
        m.put("file", u.file());
        m.put("reason", phrase(u.reason()));
        return m;
    }

    static Unresolved unresolved(Object o) {
        var m = Json.obj(o);
        return new Unresolved(ecosystem(m), required(m, "name"), required(m, "declared"), required(m, "file"), phrase(m.get("reason")));
    }

    // ----------------------------------------------------------------------------------------------- findings
    static Map<String, Object> finding(Finding f) {
        var m = new LinkedHashMap<String, Object>();
        m.put("severity", f.severity().name());
        var s = f.score();
        if (s != null) {   // scored for no environment: where it is read, for its own
            var score = new LinkedHashMap<String, Object>();
            score.put("version", s.version());
            score.put("baseVector", s.baseVector());
            score.put("base", s.base());
            score.put("baseSeverity", s.baseSeverity() == null ? null : s.baseSeverity().name());
            score.put("envVector", s.envVector());
            score.put("env", s.env());
            m.put("score", score);
        }
        m.put("ecosystem", f.ecosystem().id());
        m.put("package", f.pkg());
        m.put("version", f.version());
        m.put("approximate", f.approximate());
        m.put("scope", f.scope());
        m.put("file", f.file());
        m.put("id", f.id());
        m.put("cves", f.cves());
        m.put("aliases", f.aliases());
        m.put("fixedIn", f.fixedIn());
        m.put("summary", f.summary());
        m.put("details", f.details());
        m.put("published", f.published());
        m.put("url", f.url());
        m.put("basis", f.basis() == null ? null : f.basis().name());
        m.put("basisNote", f.basisNote() == null ? null : phrase(f.basisNote()));
        var r = f.rating();
        if (r != null) {
            var rating = new LinkedHashMap<String, Object>();
            rating.put("severity", r.severity() == null ? null : r.severity().name());
            rating.put("score", r.score());
            rating.put("cvss3", r.cvss3());
            rating.put("cvss4", r.cvss4());
            m.put("rating", rating);
        }
        return m;
    }

    static Finding finding(Object o) {
        var m = Json.obj(o);
        var s = m.get("score") == null ? null : Json.obj(m.get("score"));
        var score = s == null ? null : new Score(text(s, "version"), text(s, "baseVector"), number(s, "base"), severity(s, "baseSeverity"),
                text(s, "envVector"), number(s, "env"));
        var r = m.get("rating") == null ? null : Json.obj(m.get("rating"));
        var rating = r == null ? null : new Rating(severity(r, "severity"), number(r, "score"), text(r, "cvss3"), text(r, "cvss4"));
        String basis = text(m, "basis");
        Severity severity = severity(m, "severity");
        if (severity == null) throw new Malformed("a finding without its severity");
        return new Finding(severity, score, ecosystem(m), required(m, "package"), required(m, "version"), flag(m, "approximate"),
                required(m, "scope"), required(m, "file"), required(m, "id"), texts(m, "cves"), texts(m, "aliases"), text(m, "fixedIn"),
                text(m, "summary"), text(m, "details"), text(m, "published"), text(m, "url"),
                basis == null ? null : enumOf(MatchBasis.class, basis), m.get("basisNote") == null ? null : phrase(m.get("basisNote")), rating);
    }

    // ------------------------------------------------------------------------------------- ignore file, VEX
    static Map<String, Object> rule(IgnoreRule r) {
        var m = new LinkedHashMap<String, Object>();
        m.put("id", r.id());
        m.put("package", r.pkg());
        m.put("version", r.version());
        m.put("until", r.until() == null ? null : r.until().toString());
        m.put("reason", r.reason());
        m.put("line", r.line());
        m.put("source", r.source());
        return m;
    }

    static IgnoreRule rule(Object o) {
        var m = Json.obj(o);
        String until = text(m, "until");
        try {
            return new IgnoreRule(text(m, "id"), text(m, "package"), text(m, "version"), until == null ? null : LocalDate.parse(until),
                    text(m, "reason"), (int) whole(m, "line"), text(m, "source"));
        } catch (java.time.format.DateTimeParseException e) {
            throw new Malformed("until " + until);
        }
    }

    static Map<String, Object> statement(VexStatement v) {
        var m = new LinkedHashMap<String, Object>();
        m.put("id", v.id());
        m.put("package", v.pkg());
        m.put("version", v.version());
        m.put("state", v.state());
        m.put("justification", v.justification());
        m.put("detail", v.detail());
        m.put("source", v.source());
        return m;
    }

    static VexStatement statement(Object o) {
        var m = Json.obj(o);
        return new VexStatement(text(m, "id"), text(m, "package"), text(m, "version"), text(m, "state"), text(m, "justification"),
                text(m, "detail"), text(m, "source"));
    }

    // ------------------------------------------------------------------------------------------------ phrases
    static Map<String, Object> phrase(Phrase p) {
        var m = new LinkedHashMap<String, Object>();
        m.put("key", p.key());
        var args = new ArrayList<Object>();
        for (Object a : p.arguments()) {
            args.add(switch (a) {
                case null -> null;
                case Number n -> n;
                case Phrase nested -> phrase(nested);
                default -> a.toString();   // a path, a date: as said
            });
        }
        m.put("args", args);
        return m;
    }

    static Phrase phrase(Object o) {
        var m = Json.obj(o);
        String key = text(m, "key");
        if (key == null) throw new Malformed("a phrase without its key");
        var args = new ArrayList<Object>();
        for (Object a : Json.arr(m.get("args"))) args.add(a instanceof Map<?, ?> ? phrase(a) : a);
        return new Phrase(key, args);
    }

    // ------------------------------------------------------------------------------------------------ fields
    /** A text as written, null too. */
    static String text(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v == null || v instanceof String) return (String) v;
        throw new Malformed(key + " is not a text");
    }

    /** A text every record of its kind has. */
    static String required(Map<String, Object> m, String key) {
        String v = text(m, key);
        if (v == null) throw new Malformed("no " + key);
        return v;
    }

    static boolean flag(Map<String, Object> m, String key) {
        return Boolean.TRUE.equals(m.get(key));
    }

    static List<String> texts(Map<String, Object> m, String key) {
        var list = new ArrayList<String>();
        for (Object v : Json.arr(m.get(key))) {
            if (!(v instanceof String s)) throw new Malformed(key + " holds something not a text");
            list.add(s);
        }
        return List.copyOf(list);
    }

    static Double number(Map<String, Object> m, String key) {
        return m.get(key) instanceof Number n ? n.doubleValue() : null;
    }

    static long whole(Map<String, Object> m, String key) {
        return m.get(key) instanceof Number n ? n.longValue() : 0;
    }

    private static Ecosystem ecosystem(Map<String, Object> m) {
        Ecosystem e = Ecosystem.of(required(m, "ecosystem"));
        if (e == null) throw new Malformed("ecosystem " + m.get("ecosystem"));
        return e;
    }

    private static Severity severity(Map<String, Object> m, String key) {
        String name = text(m, key);
        return name == null ? null : enumOf(Severity.class, name);
    }

    static <E extends Enum<E>> E enumOf(Class<E> type, String name) {
        try {
            return Enum.valueOf(type, name);
        } catch (IllegalArgumentException e) {
            throw new Malformed(type.getSimpleName() + " " + name);
        }
    }
}
