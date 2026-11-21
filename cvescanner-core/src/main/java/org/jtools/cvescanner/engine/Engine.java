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


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;
import org.jtools.cvescanner.db.CveList;
import org.jtools.cvescanner.db.Database;
import org.jtools.cvescanner.db.Osv;
import org.jtools.cvescanner.db.VulnDb;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.project.Collector;
import org.jtools.cvescanner.project.GradleScanner;
import org.jtools.cvescanner.project.MavenScanner;
import org.jtools.cvescanner.project.NpmScanner;
import org.jtools.cvescanner.project.ProjectFiles;

public final class Engine {
    public static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private Engine() {}

    /**
     * @param dbFiles database zips chosen by the user; when empty the OSV.dev cache is used (downloaded first if
     *                {@code download} is set)
     */
    public static ScanResult scan(Path dir, Path cache, boolean download, List<Path> dbFiles, ScanListener listener)
            throws IOException, InterruptedException {
        Path root = dir.toAbsolutePath().normalize();
        var warnings = new ArrayList<String>();
        ScanListener l = new ScanListener() {
            public void status(String m) { listener.status(m); }
            public void progress(double f) { listener.progress(f); }
            public void warn(String m) { warnings.add(m); listener.warn(m); }
        };

        l.status("Looking for project files in " + root + "…");
        l.progress(-1);
        var files = ProjectFiles.find(root);
        var col = new Collector(root);
        MavenScanner.scan(files.poms, col, l::warn);
        GradleScanner.scan(files.gradle, files.gradleProps, col);
        GradleScanner.scanCatalogs(files.catalogs, col);
        NpmScanner.scan(files.packageJsons, root, col, l::warn);

        var wanted = VulnDb.Wanted.of(col.deps);
        var index = new VulnDb.Index();
        if (!col.deps.isEmpty()) {
            List<Path> sources = new ArrayList<>(dbFiles);
            if (sources.isEmpty()) {
                for (String eco : new TreeSet<>(wanted.byEcosystem().keySet())) {
                    if (download) Database.update(eco, cache, l);
                    Path zip = Database.zipPath(cache, eco);
                    if (!Files.isRegularFile(zip))
                        throw new IOException("No vulnerability database loaded.\n\nChoose a database zip file (the GitHub "
                                + "Advisory Database or the CVE List from GitHub), or enable downloading from OSV.dev.");
                    sources.add(zip);
                }
            }
            index = VulnDb.load(sources, wanted, l);
        }

        l.status("Matching " + col.deps.size() + " dependencies against the database…");
        l.progress(-1);
        var findings = new ArrayList<Finding>();
        var seen = new HashSet<List<String>>();
        for (var d : col.deps) {
            var coveredCves = new HashSet<String>();
            for (var m : index.osvFor(d)) {
                var key = List.of(d.file(), d.scope(), d.ecosystem(), d.name(), d.version(), Json.str(m.vuln(), "id"));
                if (seen.contains(key) || !Osv.isAffected(d.ecosystem(), d.version(), m.affected())) continue;
                seen.add(key);
                var f = Osv.toFinding(d, m);
                findings.add(f);
                coveredCves.add(f.id());
                coveredCves.addAll(f.cves());
            }
            // CVE List records: skip CVEs already reported by an advisory, prefer package matches over name matches
            var best = new LinkedHashMap<String, Finding>();
            for (var rule : index.cveFor(d)) {
                String id = rule.info().id();
                if (coveredCves.contains(id)) continue;
                var basis = CveList.basis(d, rule);
                if (basis == null || !CveList.affected(d.ecosystem(), d.version(), rule)) continue;
                var previous = best.get(id);
                if (previous == null || (previous.basis() == MatchBasis.CVE_NAME && basis == MatchBasis.CVE_PACKAGE))
                    best.put(id, CveList.toFinding(d, rule, basis));
            }
            findings.addAll(best.values());
        }
        findings.sort(Finding.ORDER);
        var counts = new LinkedHashMap<String, Integer>();
        counts.put("pom.xml", files.poms.size());
        counts.put("Gradle build files", files.gradle.size());
        counts.put("version catalogs", files.catalogs.size());
        counts.put("package.json", files.packageJsons.size());
        return new ScanResult(root, List.copyOf(findings), List.copyOf(col.deps), List.copyOf(col.unresolved),
                index.sources, counts, List.copyOf(warnings));
    }
}
