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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.junit.jupiter.api.Test;

class DependenciesCsvTest {

    private static Dependency dep(String name, String version, String file, String scope, List<String> parents) {
        return new Dependency(Ecosystem.NPM, name, version, file, scope, false, null, parents);
    }

    private static Finding finding(String name, String version, String file, Severity severity, String id) {
        return new Finding(severity, new Score(null, null, null, severity, null, null), Ecosystem.NPM, name, version, false,
                "transitive", file, id, List.of(), List.of(), "", "summary", "details", "", "https://example.org/" + id,
                MatchBasis.ADVISORY, Phrase.of("match.note.advisory"), new Rating(severity, null, null, null));
    }

    @Test
    void eachDependencyFollowedByWhatItBringsItsPathAndItsWorstFinding() {
        var deps = List.of(
                dep("b", "1.0.0", "x/package-lock.json", "transitive", List.of("a@1.0.0")),
                dep("a", "1.0.0", "x/package-lock.json", "direct", List.of()),
                dep("z", "2.0.0", "x/package-lock.json", "direct", List.of()),
                dep("c", "1.0.0", "x/package-lock.json", "transitive", List.of("a@1.0.0", "b@1.0.0")),
                dep("q", "3.0.0", "x/package-lock.json", "transitive", null),
                dep("a", "1.0.0", "a/package-lock.json", "direct", List.of()));
        var findings = List.of(finding("c", "1.0.0", "x/package-lock.json", Severity.MEDIUM, "GHSA-2"),
                finding("c", "1.0.0", "x/package-lock.json", Severity.CRITICAL, "GHSA-1"),
                finding("c", "1.0.0", "other/package-lock.json", Severity.LOW, "GHSA-3"));
        assertEquals("""
                ecosystem,package,version,file,scope,depth,path,findings,worst_severity,advisories
                npm,a,1.0.0,a/package-lock.json,direct,0,a 1.0.0,0,,
                npm,a,1.0.0,x/package-lock.json,direct,0,a 1.0.0,0,,
                npm,b,1.0.0,x/package-lock.json,transitive,1,a 1.0.0 > b 1.0.0,0,,
                npm,c,1.0.0,x/package-lock.json,transitive,2,a 1.0.0 > b 1.0.0 > c 1.0.0,2,CRITICAL,GHSA-1;GHSA-2
                npm,z,2.0.0,x/package-lock.json,direct,0,z 2.0.0,0,,
                npm,q,3.0.0,x/package-lock.json,transitive,,q 3.0.0,0,,
                """, Reports.dependenciesCsv(deps, findings),
                "files in order; b's row before c's though c found later; q, its parents not recorded, last");
        // b left out (a filter): c goes under a, its nearest parent listed, its path still in full
        String withoutB = Reports.dependenciesCsv(deps.stream().filter(d -> !d.name().equals("b")).toList(), findings);
        assertEquals("npm,c,1.0.0,x/package-lock.json,transitive,2,a 1.0.0 > b 1.0.0 > c 1.0.0,2,CRITICAL,GHSA-1;GHSA-2",
                withoutB.lines().toList().get(3));
    }
}
