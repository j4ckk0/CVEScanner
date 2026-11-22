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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.Phrase;

/**
 * Which findings are reported: the window's filters and the command line's options, one rule for both. An empty set
 * of ecosystems, a null severity, no search words: no filter on that.
 *
 * @param searchWords words that must all be found, whatever their case, in the ecosystem, the package, its version,
 *                    the advisory, its CVEs and aliases, the file, the scope or the summary
 * @param hideTransitive the findings of the indirect dependencies, those another package brings, left out
 */
public record FindingFilter(Severity minSeverity, Set<Ecosystem> ecosystems, boolean cveOnly, boolean hideApproximate,
                            boolean hideNameMatches, boolean hideTransitive, List<String> searchWords) {

    public static final FindingFilter NONE = new FindingFilter(null, Set.of(), false, false, false, false, List.of());

    public FindingFilter {
        ecosystems = Set.copyOf(ecosystems);
        searchWords = searchWords.stream().map(w -> w.toLowerCase(Locale.ROOT)).filter(w -> !w.isBlank()).toList();
    }

    public boolean test(Finding f) {
        if (minSeverity != null && f.severity().compareTo(minSeverity) < 0) return false;
        if (!ecosystems.isEmpty() && !ecosystems.contains(f.ecosystem())) return false;
        if (cveOnly && f.cves().isEmpty()) return false;
        if (hideNameMatches && f.basis().byName()) return false;
        if (hideApproximate && f.approximate()) return false;
        if (hideTransitive && Dependency.isTransitive(f.scope())) return false;
        if (searchWords.isEmpty()) return true;
        String text = String.join("\u0001", f.ecosystem().id(), f.pkg(), f.version(), f.id(), String.join(" ", f.cves()),
                String.join(" ", f.aliases()), f.file(), f.scope(), f.summary()).toLowerCase(Locale.ROOT);
        return searchWords.stream().allMatch(text::contains);
    }

    public boolean active() {
        return !equals(NONE);
    }

    /** What it keeps, as a report says it: one phrase per filter set. */
    public List<Phrase> describe() {
        var out = new ArrayList<Phrase>();
        if (minSeverity != null) out.add(Phrase.of("reportFilter.minSeverity", minSeverity.name()));
        if (!ecosystems.isEmpty())
            out.add(Phrase.of("reportFilter.ecosystems", String.join(", ", ecosystems.stream().sorted().map(Ecosystem::id).toList())));
        if (cveOnly) out.add(Phrase.of("filter.cveOnly"));
        if (hideApproximate) out.add(Phrase.of("reportFilter.hideApproximate"));
        if (hideNameMatches) out.add(Phrase.of("reportFilter.hideNameMatches"));
        if (hideTransitive) out.add(Phrase.of("reportFilter.hideTransitive"));
        if (!searchWords.isEmpty()) out.add(Phrase.of("reportFilter.search", String.join(" ", searchWords)));
        return out;
    }
}
