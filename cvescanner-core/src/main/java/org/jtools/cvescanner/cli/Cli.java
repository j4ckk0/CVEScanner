package org.jtools.cvescanner.cli;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.Scoring;
import org.jtools.cvescanner.report.Reports;

public final class Cli {
    private Cli() {}

    /**
     * Scans, writes the reports in the language in use, says the counts; 0, 1 on an error, 2 past --fail-on. The findings
     * the ignore file sets aside are out of the counts and of --fail-on.
     */
    public static int run(Options o) {
        I18nLanguage language = I18n.language();
        ScanListener l = new ScanListener() {
            public void status(String m) { System.err.println("==> " + m.replace("…", "...")); }
            public void warn(Phrase m) { System.err.println(I18n.text("cli.warning", m)); }
        };
        try {
            if (!Files.isDirectory(o.scanDir)) throw new IOException(I18n.text("error.scanDirMissing", o.scanDir));
            var r = Engine.scan(o.scanDir, o.dbFiles, o.ignoreChoice(), o.mode(), l);
            var scored = Scoring.applyAll(r.findings(), o.environment, o.preferV4);
            // set apart before --cve-only, so that an entry naming a finding without a CVE is not said to set none aside
            var split = r.ignores().split(scored, LocalDate.now());
            split.warnings().forEach(l::warn);
            if (o.cveOnly) split = split.filter(f -> !f.cves().isEmpty());
            var findings = split.active();
            var written = Reports.writeAll(r, split, o.outDir, o.cveOnly ? Phrase.of("filter.cveOnly") : null,
                    o.environment, o.preferV4, language);
            var counts = Finding.countBySeverity(findings);
            System.out.println("\n" + "=".repeat(60) + "\n " + I18n.text("cli.complete") + "\n" + "=".repeat(60));
            System.out.printf("  %-11s: %s%n", I18n.text("cli.scoring"), Reports.scoringText(o.preferV4, language));
            System.out.printf("  %-11s: %s%n%n", I18n.text("cli.environment"), o.environment.describe(language));
            for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN))
                System.out.printf("  %-9s %d%n", s.label(language).toUpperCase(language.locale()), counts.get(s));
            System.out.printf("  %-9s %s%n", I18n.text("cli.total"),
                    I18n.text("cli.total.detail", findings.size(), findings.stream().map(Finding::id).distinct().count()));
            if (r.ignores().read())
                System.out.printf("  %-9s %s%n", I18n.text("cli.ignored"), I18n.text("cli.ignored.detail", split.ignored().size(), r.ignores().shown()));
            System.out.println();
            for (Path p : written) System.out.println("  " + p.toAbsolutePath());
            if (o.failOn != null && findings.stream().anyMatch(f -> f.severity().compareTo(o.failOn) >= 0)) {
                System.out.println("\n" + I18n.text("cli.fail", o.failOn.label(language).toUpperCase(language.locale())));
                return 2;
            }
            return 0;
        } catch (IOException e) {
            System.err.println(I18n.text("cli.error", e.getMessage().replace("\n\n", " ")));
            return 1;
        }
    }
}
