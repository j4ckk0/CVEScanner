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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.model.Severity;

public final class Options {
    public static final String USAGE = """
            Usage: cvescanner.sh | cvescanner.bat [options] [DIR]      (or: java -jar cvescanner.jar ...)

              DIR / -d, --dir DIR   Directory to scan (default: current directory)
              -o, --out DIR         Report output directory for --no-gui (default: ./cve-report)
                  --db-dir DIR      Load every *.zip in DIR as a database (used by the launchers: database/)
                  --db FILE         Load the database from a zip file (repeatable; at least one is needed).
                                    Accepts the GitHub Advisory Database zip, the CVE List (cvelistV5)
                                    zip, and OSV.dev ecosystem zips
                  --cve-only        Only report vulnerabilities that have a CVE ID
                  --env PRESET      Environment for the environmental CVSS score:
                                    none (default), internet, internal, airgapped, devci
                  --reach R         Override reachability: internet | internal | local
                  --cr / --ir / --ar V   Override the confidentiality / integrity / availability
                                    requirement: L | M | H | X (not defined)
                  --cvss 4|3        Preferred CVSS version when an advisory has both (default 4)
                  --no-gui          Run headless and write report.md, findings.csv, findings.json
                  --fail-on LEVEL   With --no-gui: exit 2 if a finding is >= LOW|MEDIUM|HIGH|CRITICAL
              -h, --help            Show this help
            """;

    public Path scanDir = Path.of(".");
    public boolean dirGiven;
    public Path outDir = Path.of("cve-report");
    public boolean cveOnly, noGui, help;
    Severity failOn;
    public final List<Path> dbFiles = new ArrayList<>();
    public Path dbDir;
    public Environment environment = Environment.NONE;
    public boolean environmentGiven;
    public boolean preferV4 = true, cvssGiven;

    public static Options parse(String[] args) {
        var o = new Options();
        Environment preset = Environment.NONE;
        Reach reach = null;
        Requirement cr = null, ir = null, ar = null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-d", "--dir" -> { o.scanDir = Path.of(value(args, ++i, a)); o.dirGiven = true; }
                case "-o", "--out" -> o.outDir = Path.of(value(args, ++i, a));
                case "--db" -> o.dbFiles.add(Path.of(value(args, ++i, a)));
                case "--db-dir" -> o.dbDir = Path.of(value(args, ++i, a));
                case "--env" -> { preset = Environment.preset(value(args, ++i, a)); o.environmentGiven = true; }
                case "--reach" -> { reach = Reach.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--cr" -> { cr = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--ir" -> { ir = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--ar" -> { ar = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--cvss" -> {
                    String v = value(args, ++i, a);
                    if (!v.equals("4") && !v.equals("3")) throw new IllegalArgumentException("--cvss must be 4 or 3");
                    o.preferV4 = v.equals("4");
                    o.cvssGiven = true;
                }
                case "--cve-only" -> o.cveOnly = true;
                case "--no-gui" -> o.noGui = true;
                case "--fail-on" -> o.failOn = Severity.parseThreshold(value(args, ++i, a));
                case "-h", "--help" -> o.help = true;
                default -> {
                    if (a.startsWith("-")) throw new IllegalArgumentException("unknown option " + a);
                    o.scanDir = Path.of(a);
                    o.dirGiven = true;
                }
            }
        }
        o.environment = reach == null && cr == null && ir == null && ar == null ? preset
                : Environment.of(reach != null ? reach : preset.reach(), cr != null ? cr : preset.confidentiality(),
                                 ir != null ? ir : preset.integrity(), ar != null ? ar : preset.availability());
        if (o.dbDir != null && Files.isDirectory(o.dbDir)) {
            try (var files = Files.list(o.dbDir)) {
                files.filter(f -> f.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zip") && Files.isRegularFile(f))
                        .sorted().forEach(o.dbFiles::add);
            } catch (IOException e) {
                throw new IllegalArgumentException("cannot read " + o.dbDir + ": " + e.getMessage());
            }
        }
        return o;
    }

    private static String value(String[] args, int i, String opt) {
        if (i >= args.length) throw new IllegalArgumentException(opt + " needs a value");
        return args[i];
    }
}
