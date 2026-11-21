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
import org.jtools.cvescanner.cvss.Scoring;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanListener;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.Severity;
import org.jtools.cvescanner.report.Reports;

public final class Cli {
    private Cli() {}

    public static int run(Options o) {
        ScanListener l = new ScanListener() {
            public void status(String m) { System.err.println("==> " + m.replace("…", "...")); }
            public void warn(String m) { System.err.println("WARNING: " + m); }
        };
        try {
            if (!Files.isDirectory(o.scanDir)) throw new IOException("scan directory '" + o.scanDir + "' does not exist");
            var r = Engine.scan(o.scanDir, o.cacheDir, o.dbFiles.isEmpty() && !o.skipDownload, o.dbFiles, l);
            var scored = Scoring.applyAll(r.findings(), o.environment, o.preferV4);
            var findings = o.cveOnly ? scored.stream().filter(f -> !f.cves().isEmpty()).toList() : scored;
            var written = Reports.writeAll(r, findings, o.outDir, o.cveOnly ? "only vulnerabilities with a CVE ID" : null,
                    o.environment, o.preferV4);
            var counts = Reports.counts(findings);
            System.out.println("\n" + "=".repeat(60) + "\n Vulnerability scan complete\n" + "=".repeat(60));
            System.out.println("  Scoring    : " + Reports.scoringText(o.preferV4));
            System.out.println("  Environment: " + o.environment.describe() + "\n");
            for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN))
                System.out.printf("  %-9s %d%n", s.name(), counts.get(s));
            System.out.printf("  %-9s %d findings, %d unique advisories%n%n", "TOTAL", findings.size(),
                    findings.stream().map(Finding::id).distinct().count());
            for (Path p : written) System.out.println("  " + p.toAbsolutePath());
            if (o.failOn != null && findings.stream().anyMatch(f -> f.severity().compareTo(o.failOn) >= 0)) {
                System.out.println("\nFAIL: findings at or above " + o.failOn + " severity.");
                return 2;
            }
            return 0;
        } catch (IOException e) {
            System.err.println("ERROR: " + e.getMessage().replace("\n\n", " "));
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 1;
        }
    }
}
