package org.jtools.cvescanner.model;

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


import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.Phrase;

/**
 * One vulnerability affecting one dependency. {@code severity} is the effective severity: environmental when an
 * environment is applied and a CVSS vector is available, otherwise the base severity. {@code rating} holds the raw
 * CVSS data from the advisory; {@code score} the values computed by {@link Scoring} for the current environment.
 */
public record Finding(Severity severity, Score score, String ecosystem, String pkg, String version, boolean approximate,
               String scope, String file, String id, List<String> cves, List<String> aliases, String fixedIn,
               String summary, String details, String published, String url, MatchBasis basis, Phrase basisNote,
               Rating rating) {

    public Double cvss() { return score.base(); }

    public Double envScore() { return score.env(); }

    public Finding rescored(Severity effective, Score newScore) {
        return new Finding(effective, newScore, ecosystem, pkg, version, approximate, scope, file, id, cves, aliases,
                fixedIn, summary, details, published, url, basis, basisNote, rating);
    }

    public static final Comparator<Finding> ORDER = Comparator.comparing(Finding::severity).reversed()
            .thenComparing(Finding::pkg).thenComparing(Finding::id).thenComparing(Finding::file);

    public String cveText() { return String.join(", ", cves); }

    public String displayVersion() { return approximate ? version + " ≈" : version; }

    public String publishedDate() { return published.length() >= 10 ? published.substring(0, 10) : published; }

    /** How many findings of each severity, every severity counted, none left out. */
    public static Map<Severity, Long> countBySeverity(List<Finding> findings) {
        var m = new EnumMap<Severity, Long>(Severity.class);
        for (var s : Severity.values()) m.put(s, 0L);
        findings.forEach(x -> m.merge(x.severity(), 1L, Long::sum));
        return m;
    }
}
