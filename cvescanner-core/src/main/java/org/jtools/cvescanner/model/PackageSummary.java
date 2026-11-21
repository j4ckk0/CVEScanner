package org.jtools.cvescanner.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

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


/**
 * A vulnerable package version and its findings together: {@code fixedIn} is the lowest version that fixes every one
 * of them that has a fix, empty when none has; {@code someUnfixed} when some have none.
 */
public record PackageSummary(Severity worst, Ecosystem ecosystem, String pkg, String version, boolean approximate,
                      String fixedIn, boolean someUnfixed, int vulnerabilities, String advisories, String files) {
    public String displayVersion() { return approximate ? version + " ≈" : version; }

    /** The version to upgrade to, said: "2.15.0", "2.15.0 (some unfixed)", "no fix". */
    public String upgradeTo(I18nLanguage language) {
        if (fixedIn.isEmpty()) return I18n.text(language, "upgrade.noFix");
        return someUnfixed ? I18n.text(language, "upgrade.someUnfixed", fixedIn) : fixedIn;
    }

    public String upgradeTo() { return upgradeTo(I18n.language()); }

    /**
     * Findings grouped by package version, the worst first: the lowest version fixing every finding that has a fix, the
     * advisories, the files.
     */
    public static List<PackageSummary> of(List<Finding> findings) {
        record Key(Ecosystem eco, String pkg, String version) {}
        final class Agg {
            final Set<String> ids = new HashSet<>(), files = new TreeSet<>(), labels = new TreeSet<>();
            final List<String> fixes = new ArrayList<>();
            Severity worst = Severity.UNKNOWN;
            boolean approximate;
        }
        var map = new LinkedHashMap<Key, Agg>();
        for (var f : findings) {
            var a = map.computeIfAbsent(new Key(f.ecosystem(), f.pkg(), f.version()), _ -> new Agg());
            a.ids.add(f.id());
            if (f.cves().isEmpty()) a.labels.add(f.id()); else a.labels.addAll(f.cves());
            a.files.add(f.file());
            a.fixes.add(f.fixedIn());
            if (f.severity().compareTo(a.worst) > 0) a.worst = f.severity();
            a.approximate |= f.approximate();
        }
        var out = new ArrayList<PackageSummary>();
        map.forEach((k, a) -> {
            var fixed = a.fixes.stream().filter(s -> !s.isEmpty()).max(k.eco().versionOrder());
            boolean someUnfixed = a.fixes.stream().anyMatch(String::isEmpty);
            out.add(new PackageSummary(a.worst, k.eco(), k.pkg(), k.version(), a.approximate, fixed.orElse(""), someUnfixed, a.ids.size(),
                    String.join(", ", a.labels), String.join(", ", a.files)));
        });
        out.sort(Comparator.comparing(PackageSummary::worst).reversed()
                .thenComparing(Comparator.comparingInt(PackageSummary::vulnerabilities).reversed())
                .thenComparing(PackageSummary::pkg));
        return out;
    }
}
