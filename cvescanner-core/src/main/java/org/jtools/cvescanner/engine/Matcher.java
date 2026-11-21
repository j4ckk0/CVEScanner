package org.jtools.cvescanner.engine;

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
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import org.jtools.cvescanner.db.CveList;
import org.jtools.cvescanner.db.NvdFeed;
import org.jtools.cvescanner.db.Osv;
import org.jtools.cvescanner.db.VulnDb;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;

/**
 * Which vulnerabilities affect a dependency, and which database says so. The sources in order: the advisories (GitHub,
 * OSV), exact by package; then NVD, for a component off-the-shelf; then the CVE List. A CVE a source has reported is
 * not reported again by the next, and within a source a CVE matched both by name and exactly is reported once, exactly.
 */
final class Matcher {

    private Matcher() {}

    static List<Finding> findings(Dependency d, VulnDb.Index index) {
        var findings = new ArrayList<Finding>();
        var covered = new HashSet<String>();
        var seen = new HashSet<String>();
        for (var m : index.osvFor(d)) {
            String id = Json.str(m.vuln(), "id");
            if (seen.contains(id) || !Osv.isAffected(d.ecosystem(), d.version(), m.affected())) continue;
            seen.add(id);
            var f = Osv.toFinding(d, m);
            findings.add(f);
            covered.add(f.id());
            covered.addAll(f.cves());
        }
        findings.addAll(best(index.nvdFor(d), covered, r -> r.info().id(), r -> NvdFeed.basis(d, r),
                r -> NvdFeed.affected(d.version(), r), MatchBasis.CPE_PRODUCT, (r, basis) -> NvdFeed.toFinding(d, r, basis)));
        findings.addAll(best(index.cveFor(d), covered, r -> r.info().id(), r -> CveList.basis(d, r),
                r -> CveList.affected(d.ecosystem(), d.version(), r), MatchBasis.CVE_NAME, (r, basis) -> CveList.toFinding(d, r, basis)));
        return findings;
    }

    /**
     * A source's findings: one per CVE not covered yet, matched exactly rather than by name (the weak basis) when the
     * source does both; the CVEs reported are then covered.
     */
    private static <R> Collection<Finding> best(List<R> rules, Set<String> covered, Function<R, String> id,
                                                Function<R, MatchBasis> basisOf, Predicate<R> affected, MatchBasis weak,
                                                BiFunction<R, MatchBasis, Finding> finding) {
        var best = new LinkedHashMap<String, Finding>();
        for (R rule : rules) {
            String cve = id.apply(rule);
            if (covered.contains(cve)) continue;
            var basis = basisOf.apply(rule);
            if (basis == null || !affected.test(rule)) continue;
            var previous = best.get(cve);
            if (previous == null || (previous.basis() == weak && basis != weak)) best.put(cve, finding.apply(rule, basis));
        }
        covered.addAll(best.keySet());
        return best.values();
    }
}
