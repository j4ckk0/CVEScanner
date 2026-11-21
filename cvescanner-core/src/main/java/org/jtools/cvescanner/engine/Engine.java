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
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import org.jtools.cvescanner.cots.InventoryReader;
import org.jtools.cvescanner.db.CveList;
import org.jtools.cvescanner.db.NvdFeed;
import org.jtools.cvescanner.db.Osv;
import org.jtools.cvescanner.db.VulnDb;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
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
     * @param dbFiles the database zips the user gave: the only source of vulnerability data, the program fetching none
     */
    public static ScanResult scan(Path dir, List<Path> dbFiles, ScanListener listener) throws IOException {
        Path root = dir.toAbsolutePath().normalize();
        var warnings = new ArrayList<Phrase>();
        ScanListener l = new ScanListener() {
            public void status(String m) { listener.status(m); }
            public void progress(double f) { listener.progress(f); }
            public void warn(Phrase m) { warnings.add(m); listener.warn(m); }
        };

        l.status(I18n.text("status.lookingFor", root));
        l.progress(-1);
        var files = ProjectFiles.find(root);
        var col = new Collector(root);
        MavenScanner.scan(files.poms, col, l::warn);
        GradleScanner.scan(files.gradle, files.gradleProps, col);
        GradleScanner.scanCatalogs(files.catalogs, col);
        NpmScanner.scan(files.packageJsons, root, col, l::warn);
        InventoryReader.scan(files.cotsInventories, col, l::warn);

        var wanted = VulnDb.Wanted.of(col.deps);
        var index = new VulnDb.Index();
        if (!col.deps.isEmpty()) {
            if (dbFiles.isEmpty())
                throw new IOException(I18n.text("error.noDatabase"));
            index = VulnDb.load(dbFiles, wanted, l);
        }

        l.status(I18n.text("status.matching", col.deps.size()));
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
            // NVD's CPEs, for a component off-the-shelf: by vendor and product rather than by product alone
            var bestNvd = new LinkedHashMap<String, Finding>();
            for (var rule : index.nvdFor(d)) {
                String id = rule.info().id();
                if (coveredCves.contains(id)) continue;
                var basis = NvdFeed.basis(d, rule);
                if (basis == null || !NvdFeed.affected(d.version(), rule)) continue;
                var previous = bestNvd.get(id);
                if (previous == null || (previous.basis() == MatchBasis.CPE_PRODUCT && basis == MatchBasis.CPE))
                    bestNvd.put(id, NvdFeed.toFinding(d, rule, basis));
            }
            findings.addAll(bestNvd.values());
            coveredCves.addAll(bestNvd.keySet());
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
        counts.put("files.pom", files.poms.size());
        counts.put("files.gradle", files.gradle.size());
        counts.put("files.catalogs", files.catalogs.size());
        counts.put("files.packageJson", files.packageJsons.size());
        // the files of components off-the-shelf, said only when there are some
        if (!files.cotsInventories.isEmpty()) counts.put("files.cotsInventories", files.cotsInventories.size());
        return new ScanResult(root, List.copyOf(findings), List.copyOf(col.deps), List.copyOf(col.unresolved),
                index.sources, counts, List.copyOf(warnings));
    }
}
