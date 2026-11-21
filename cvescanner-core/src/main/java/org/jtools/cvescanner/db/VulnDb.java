package org.jtools.cvescanner.db;

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


import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanListener;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Database loading from zip files: OSV / GitHub Advisory Database records and CVE List (CVE JSON 5) records.
 * Zips are streamed (never extracted) and nested zips are followed, so the cvelistV5 release asset works.
 * Only records that mention a package the project uses are parsed and kept.
 */
public final class VulnDb {
    private static final Pattern OSV_NAME = Pattern.compile("\"name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern CVE_NAME = Pattern.compile("\"(?:product|packageName)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    public record Wanted(Map<String, Set<String>> byEcosystem, Set<String> allNames, Set<String> cveKeys) {
        public static Wanted of(List<Dependency> deps) {
            var by = new HashMap<String, Set<String>>();
            var all = new HashSet<String>();
            var keys = new HashSet<String>();
            for (var d : deps) {
                by.computeIfAbsent(d.ecosystem(), _ -> new HashSet<>()).add(d.name());
                all.add(d.name());
                keys.addAll(CveList.keysFor(d));
            }
            return new Wanted(by, all, keys);
        }
    }

    public static final class Index {
        final Map<String, Map<String, List<Osv.Match>>> osv = new HashMap<>();
        final Map<String, List<CveList.Rule>> cve = new HashMap<>();
        public final Map<String, String> sources = new LinkedHashMap<>();

        public List<Osv.Match> osvFor(Dependency d) {
            return osv.getOrDefault(d.ecosystem(), Map.of()).getOrDefault(d.name(), List.of());
        }

        public List<CveList.Rule> cveFor(Dependency d) {
            var out = new LinkedHashSet<CveList.Rule>();
            for (String k : CveList.keysFor(d)) out.addAll(cve.getOrDefault(k, List.of()));
            return List.copyOf(out);
        }
    }

    private static final class Counts { int osv, cve, osvUsed, cveUsed, entries; }

    private interface EntryHandler { void accept(byte[] data) throws IOException; }

    private static final class CountingInputStream extends FilterInputStream {
        long count;

        CountingInputStream(InputStream in) { super(in); }

        @Override public int read() throws IOException {
            int b = super.read();
            if (b >= 0) count++;
            return b;
        }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) count += n;
            return n;
        }

        @Override public long skip(long n) throws IOException {
            long k = super.skip(n);
            count += k;
            return k;
        }
    }

    private VulnDb() {}

    public static Index load(List<Path> files, Wanted wanted, ScanListener l) throws IOException {
        var index = new Index();
        int total = 0;
        for (Path file : files) {
            if (!Files.isRegularFile(file)) throw new IOException("Database file not found: " + file);
            long size = Math.max(1, Files.size(file));
            var counts = new Counts();
            l.status("Reading " + file.getFileName() + "…");
            l.progress(0);
            try (var in = new CountingInputStream(new BufferedInputStream(Files.newInputStream(file), 1 << 16))) {
                readZip(in, data -> {
                    accept(data, wanted, index, counts);
                    if (++counts.entries % 500 == 0) {
                        l.progress((double) in.count / size);
                        l.status(String.format(Locale.ROOT, "Reading %s… %,d records", file.getFileName(), counts.entries));
                    }
                }, 0);
            } catch (ZipException e) {
                throw new IOException(file.getFileName() + " is not a readable zip file (" + e.getMessage() + ")", e);
            }
            String kind = counts.osv > 0 && counts.cve > 0 ? "advisories + CVE records"
                    : counts.cve > 0 ? "CVE List (CVE JSON 5)" : "OSV / GitHub advisories";
            total += counts.osv + counts.cve;
            if (counts.osv + counts.cve == 0)
                l.warn(file.getFileName() + " contains no OSV, GitHub advisory or CVE JSON 5 records");
            index.sources.put(file.getFileName().toString(), String.format(Locale.ROOT, "%s, %,d records (%,d relevant), file dated %s",
                    kind, counts.osv + counts.cve, counts.osvUsed + counts.cveUsed,
                    Engine.STAMP.format(Files.getLastModifiedTime(file).toInstant())));
        }
        if (total == 0)
            throw new IOException("The chosen database file(s) contain no vulnerability records.\n\nUse the GitHub Advisory "
                    + "Database zip, the CVE List (cvelistV5) zip, or an OSV.dev ecosystem zip.");
        return index;
    }

    private static void readZip(InputStream in, EntryHandler handler, int depth) throws IOException {
        var zis = new ZipInputStream(in);   // deliberately not closed: that would close the enclosing stream
        for (ZipEntry e; (e = zis.getNextEntry()) != null; ) {
            if (e.isDirectory()) continue;
            String name = e.getName().toLowerCase(Locale.ROOT);
            if (name.endsWith(".zip") && depth < 3) {
                readZip(new FilterInputStream(zis) {
                    @Override public void close() { /* keep the outer zip open */ }
                }, handler, depth + 1);
            } else if (name.endsWith(".json")) {
                handler.accept(zis.readAllBytes());
            }
        }
    }

    private static boolean mentions(Pattern p, String text, Set<String> keys, boolean normalize) {
        var m = p.matcher(text);
        while (m.find()) {
            String v = normalize ? CveList.normalize(m.group(1)) : m.group(1);
            if (keys.contains(v)) return true;
        }
        return false;
    }

    private static void accept(byte[] data, Wanted wanted, Index index, Counts counts) {
        String text = new String(data, UTF_8);
        if (text.contains("\"cveMetadata\"")) {                               // CVE List record
            counts.cve++;
            if (!mentions(CVE_NAME, text, wanted.cveKeys(), true)) return;
            Map<String, Object> rec;
            try { rec = Json.obj(Json.parse(text)); } catch (IllegalArgumentException _) { return; }
            boolean used = false;
            for (var rule : CveList.rules(rec))
                for (String key : rule.keys())
                    if (wanted.cveKeys().contains(key)) {
                        index.cve.computeIfAbsent(key, _ -> new ArrayList<>()).add(rule);
                        used = true;
                    }
            if (used) counts.cveUsed++;
        } else if (text.contains("\"affected\"") && text.contains("\"ecosystem\"")) {   // OSV / GitHub advisory
            counts.osv++;
            if (!mentions(OSV_NAME, text, wanted.allNames(), false)) return;
            Map<String, Object> vuln;
            try { vuln = Json.obj(Json.parse(text)); } catch (IllegalArgumentException _) { return; }
            if (vuln.get("withdrawn") != null || Json.str(vuln, "id") == null) return;
            boolean used = false;
            for (Object a : Json.arr(vuln.get("affected"))) {
                var aff = Json.obj(a);
                var pkg = Json.obj(aff.get("package"));
                String eco = Objects.requireNonNullElse(Json.str(pkg, "ecosystem"), "").split(":")[0];
                String name = Json.str(pkg, "name");
                if (name != null && wanted.byEcosystem().getOrDefault(eco, Set.of()).contains(name)) {
                    index.osv.computeIfAbsent(eco, _ -> new HashMap<>()).computeIfAbsent(name, _ -> new ArrayList<>())
                            .add(new Osv.Match(vuln, aff));
                    used = true;
                }
            }
            if (used) counts.osvUsed++;
        }
    }
}
