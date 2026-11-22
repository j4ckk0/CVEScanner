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
import java.util.List;
import org.jtools.cvescanner.analysis.AnalysisFile;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Scoring;
import org.jtools.cvescanner.report.Reports;

public final class Cli {
    private Cli() {}

    /**
     * The findings scored, those the ignore file sets aside apart, then those the filters keep. Set apart before the
     * filters, so that an entry naming a finding a filter drops is not said to set none aside.
     */
    private static Ignores.Split split(Options o, ScanResult r, ScanListener l) {
        var scored = Scoring.applyAll(r.findings(), o.environment, o.preferV4);
        var split = r.ignores().split(scored, o.today);
        split.warnings().forEach(l::warn);
        return o.filter().active() ? split.filter(o.filter()::test) : split;
    }

    /**
     * Scans, writes the reports in the language in use, says the counts; 0, 1 on an error, 2 past --fail-on, 3 when a
     * fix confirmed by --yes could not be applied. The findings the ignore file sets aside, and those the filters drop,
     * are out of the counts and of --fail-on. With --apply-fixes and --yes, the reports are those of a new scan.
     * --ignore-add, --ignore-remove and --ignore-list edit or list the ignore file instead, and scan nothing.
     * --from-analysis re-checks an analysis made elsewhere instead of scanning (--as-scanned: its findings as they were);
     * --export-analysis writes the scan as one too.
     */
    public static int run(Options o) {
        if (o.ignoreEdit()) return CliIgnore.run(o, System.out, System.err);
        I18nLanguage language = I18n.language();
        ScanListener l = new ScanListener() {
            public void status(String m) { System.err.println("==> " + m.replace("…", "...")); }
            public void warn(Phrase m) { System.err.println(I18n.text("cli.warning", m)); }
        };
        try {
            ScanResult r;
            if (o.fromAnalysis != null) {   // made on another computer: as it was, or checked again against these databases
                var analysis = AnalysisFile.read(o.fromAnalysis);
                r = o.asScanned ? analysis : Engine.recheck(analysis, o.dbFiles, o.scanOptions(), l);
            } else {
                if (!Files.isDirectory(o.scanDir)) throw new IOException(I18n.text("error.scanDirMissing", o.scanDir));
                r = Engine.scan(o.scanDir, o.dbFiles, o.scanOptions(), l);
            }
            var split = split(o, r, l);
            CliFixes.Result fixes = null;
            if (o.applyFixes) {
                fixes = CliFixes.run(o, r.root(), split.active(), System.out);
                if (fixes.applied() > 0) {   // the reports say the projects as they are now
                    r = Engine.scan(o.scanDir, o.dbFiles, o.scanOptions(), l);
                    split = split(o, r, l);
                }
            }
            var findings = split.active();
            var written = new java.util.ArrayList<>(Reports.writeAll(r, split, o.outDir, o.filter().describe(), o.environment, o.preferV4,
                    language, o.hideTransitive));
            if (o.exportAnalysis != null) {
                AnalysisFile.write(r, o.exportAnalysis);
                written.add(o.exportAnalysis);
            }
            var counts = Finding.countBySeverity(findings);
            System.out.println("\n" + "=".repeat(60) + "\n " + I18n.text("cli.complete") + "\n" + "=".repeat(60));
            System.out.printf("  %-11s: %s%n", I18n.text("cli.scoring"), Reports.scoringText(o.preferV4, language));
            System.out.printf("  %-11s: %s%n%n", I18n.text("cli.environment"), o.environment.describe(language));
            for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN))
                System.out.printf("  %-9s %d%n", s.label(language).toUpperCase(language.locale()), counts.get(s));
            System.out.printf("  %-9s %s%n", I18n.text("cli.total"),
                    I18n.text("cli.total.detail", findings.size(), findings.stream().map(Finding::id).distinct().count()));
            if (r.ignores().said()) {
                var by = new java.util.ArrayList<String>();
                if (r.ignores().read()) by.add(r.ignores().shown());
                by.addAll(r.ignores().vexSources());
                System.out.printf("  %-9s %s%n", I18n.text("cli.ignored"), I18n.text("cli.ignored.detail", split.ignored().size(), String.join(", ", by)));
            }
            System.out.println();
            for (Path p : written) System.out.println("  " + p.toAbsolutePath());
            if (o.failOn != null && findings.stream().anyMatch(f -> f.severity().compareTo(o.failOn) >= 0)) {
                System.out.println("\n" + I18n.text("cli.fail", o.failOn.label(language).toUpperCase(language.locale())));
                return 2;
            }
            return fixes != null && fixes.failed() > 0 ? 3 : 0;
        } catch (IOException e) {
            System.err.println(I18n.text("cli.error", e.getMessage().replace("\n\n", " ")));
            return 1;
        }
    }
}
