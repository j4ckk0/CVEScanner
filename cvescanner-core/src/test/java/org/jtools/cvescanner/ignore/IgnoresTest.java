package org.jtools.cvescanner.ignore;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Which findings an ignore file's entries set aside, and which entries have expired or set nothing aside. */
class IgnoresTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 11, 21);

    @TempDir
    Path dir;

    static Finding finding(String pkg, String version, String id, List<String> cves, List<String> aliases) {
        return new Finding(Severity.HIGH, new Score(null, null, null, Severity.HIGH, null, null), "Maven", pkg, version, false,
                "compile", "pom.xml", id, cves, aliases, "", "summary", "details", "", "https://example.org/" + id,
                MatchBasis.ADVISORY, Phrase.of("match.note.advisory"), new Rating(Severity.HIGH, null, null, null));
    }

    private static Ignores ignores(IgnoreRule... rules) {
        return new Ignores(Path.of("/scan/cvescanner-ignore.csv"), "cvescanner-ignore.csv", List.of(rules), true);
    }

    private static IgnoreRule rule(String id, String pkg, String version, LocalDate until, int line) {
        return new IgnoreRule(id, pkg, version, until, "reviewed", line);
    }

    @Test
    void anEntryNamesAFindingByItsIdItsCvesOrItsAliasesWhateverTheCase() {
        var f = finding("g:a", "1.0", "GHSA-aaaa", List.of("CVE-2021-1"), List.of("OSV-9"));
        assertTrue(rule("ghsa-AAAA", "", "", null, 1).matches(f));
        assertTrue(rule("cve-2021-1", "", "", null, 1).matches(f));
        assertTrue(rule("OSV-9", "", "", null, 1).matches(f));
        assertFalse(rule("CVE-2021-2", "", "", null, 1).matches(f));
    }

    @Test
    void anEmptyPackageOrVersionIsAnyAGivenOneMustBeTheFindings() {
        var f = finding("g:a", "1.0", "GHSA-aaaa", List.of("CVE-2021-1"), List.of());
        assertTrue(rule("CVE-2021-1", "G:A", "", null, 1).matches(f));
        assertTrue(rule("CVE-2021-1", "g:a", "1.0", null, 1).matches(f));
        assertFalse(rule("CVE-2021-1", "g:b", "", null, 1).matches(f));
        assertFalse(rule("CVE-2021-1", "g:a", "1.1", null, 1).matches(f));
    }

    @Test
    void anEntryAppliesUpToItsDayIncludedThenExpires() {
        var f = finding("g:a", "1.0", "GHSA-aaaa", List.of("CVE-2021-1"), List.of());
        var lastDay = ignores(rule("CVE-2021-1", "", "", TODAY, 1)).split(List.of(f), TODAY);
        assertEquals(1, lastDay.ignored().size());
        assertTrue(lastDay.expired().isEmpty());

        var dayAfter = ignores(rule("CVE-2021-1", "", "", TODAY.minusDays(1), 1)).split(List.of(f), TODAY);
        assertEquals(List.of(f), dayAfter.active());
        assertEquals(1, dayAfter.expired().size());
        assertTrue(dayAfter.unused().isEmpty(), "an expired entry is said expired, not unused");
        assertEquals("ignore.warning.expired", dayAfter.warnings().getFirst().key());
    }

    @Test
    void theFirstEntryNamingAFindingSetsItAsideAndAnEntryNamingNoneIsSaid() {
        var log4j = finding("org.apache.logging.log4j:log4j-core", "2.14.1", "GHSA-jfh8", List.of("CVE-2021-44228"), List.of());
        var other = finding("g:a", "1.0", "GHSA-bbbb", List.of(), List.of());
        var first = rule("CVE-2021-44228", "", "", null, 3);
        var second = rule("GHSA-jfh8", "", "", null, 4);
        var none = rule("CVE-2099-1", "", "", null, 5);
        var split = ignores(first, second, none).split(List.of(log4j, other), TODAY);
        assertEquals(List.of(other), split.active());
        assertEquals(1, split.ignored().size());
        assertSame(first, split.ignored().getFirst().rule());
        assertEquals(List.of(second, none), split.unused());
        assertEquals(List.of("ignore.warning.unused", "ignore.warning.unused"),
                split.warnings().stream().map(Phrase::key).toList());
    }

    @Test
    void aFilterKeepsTheFindingsItPassesOnBothSides() {
        var withCve = finding("g:a", "1.0", "GHSA-aaaa", List.of("CVE-2021-1"), List.of());
        var without = finding("g:b", "1.0", "GHSA-bbbb", List.of(), List.of());
        var split = ignores(rule("GHSA-bbbb", "", "", null, 1)).split(List.of(withCve, without), TODAY)
                .filter(f -> !f.cves().isEmpty());
        assertEquals(List.of(withCve), split.active());
        assertTrue(split.ignored().isEmpty());
        assertTrue(split.unused().isEmpty(), "the entry did set a finding aside, before the filter");
    }

    @Test
    void anEntryMadeFromAFindingNamesItsFirstCveAtTheScopeChosen() {
        var f = finding("g:a", "1.0", "GHSA-aaaa", List.of("CVE-2021-1", "CVE-2021-2"), List.of());
        var version = IgnoreRule.forFinding(f, IgnoreRule.Scope.VERSION, " why ", null);
        assertEquals(new IgnoreRule("CVE-2021-1", "g:a", "1.0", null, "why", 0), version);
        assertEquals(new IgnoreRule("CVE-2021-1", "g:a", "", TODAY, "why", 0),
                IgnoreRule.forFinding(f, IgnoreRule.Scope.PACKAGE, "why", TODAY));
        assertEquals(new IgnoreRule("GHSA-bbbb", "", "", null, "", 0), IgnoreRule.forFinding(
                finding("g:b", "2.0", "GHSA-bbbb", List.of(), List.of()), IgnoreRule.Scope.EVERYWHERE, "", null));
        for (var scope : IgnoreRule.Scope.values()) assertTrue(IgnoreRule.forFinding(f, scope, "", null).matches(f), scope.name());
    }

    @Test
    void theFoldersOwnFileIsReadWhenThereIsOneANamedOneMustBeThere() throws IOException {
        var warnings = new ArrayList<Phrase>();
        var none = Ignores.load(dir, null, warnings::add);
        assertFalse(none.read());
        assertEquals(dir.resolve(IgnoreFile.NAME).toAbsolutePath().normalize(), none.file(), "where the window would write it");

        Files.writeString(dir.resolve(IgnoreFile.NAME), "CVE-2021-1,,,,why\n");
        var own = Ignores.load(dir, null, warnings::add);
        assertTrue(own.read());
        assertEquals("cvescanner-ignore.csv", own.shown());
        assertEquals(1, own.rules().size());

        assertSame(Ignores.NONE, Ignores.load(dir, Ignores.DISABLED, warnings::add));
        assertThrows(IOException.class, () -> Ignores.load(dir, dir.resolve("missing.csv"), warnings::add));
        assertTrue(warnings.isEmpty(), warnings.toString());
    }
}
