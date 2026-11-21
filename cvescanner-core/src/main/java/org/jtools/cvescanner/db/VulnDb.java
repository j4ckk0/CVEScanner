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
import java.io.InputStreamReader;
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
import org.jtools.cvescanner.cots.KnownProducts;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanListener;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Database loading from zip files: OSV / GitHub Advisory Database records, CVE List (CVE JSON 5) records and NVD feeds.
 * Zips are streamed (never extracted) and nested zips are followed, so the cvelistV5 release asset works.
 * Only records that mention a package the project uses are parsed and kept.
 */
public final class VulnDb {
    private static final Pattern OSV_NAME = Pattern.compile("\"name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern CVE_NAME = Pattern.compile("\"(?:product|packageName)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    /** What the scan looks for: packages by ecosystem, the CVE List's keys, and the products of the COTS components. */
    public record Wanted(Map<String, Set<String>> byEcosystem, Set<String> allNames, Set<String> cveKeys,
                         Set<String> cotsProducts) {
        public static Wanted of(List<Dependency> deps) {
            var by = new HashMap<String, Set<String>>();
            var all = new HashSet<String>();
            var keys = new HashSet<String>();
            var products = new HashSet<String>();
            for (var d : deps) {
                by.computeIfAbsent(d.ecosystem(), _ -> new HashSet<>()).add(d.name());
                all.add(d.name());
                keys.addAll(CveList.keysFor(d));
                if (d.ecosystem().equals(COTS)) products.addAll(KnownProducts.products(product(d)));
            }
            return new Wanted(by, all, keys, products);
        }
    }

    /** The ecosystem of the components off-the-shelf: their name vendor:product, or a product alone. */
    public static final String COTS = "COTS";

    /** A COTS component's product, in lower case: "gdal" for "osgeo:gdal" and for "gdal". */
    public static String product(Dependency d) {
        return d.name().substring(d.name().indexOf(':') + 1).toLowerCase(Locale.ROOT);
    }

    public static final class Index {
        final Map<String, Map<String, List<Osv.Match>>> osv = new HashMap<>();
        final Map<String, List<CveList.Rule>> cve = new HashMap<>();
        final Map<String, List<NvdFeed.Rule>> nvd = new HashMap<>();
        public final Map<String, Phrase> sources = new LinkedHashMap<>();

        /** The NVD rules of a COTS component's product. */
        public List<NvdFeed.Rule> nvdFor(Dependency d) {
            if (!d.ecosystem().equals(COTS)) return List.of();
            var rules = new ArrayList<NvdFeed.Rule>();
            for (String product : KnownProducts.products(product(d))) rules.addAll(nvd.getOrDefault(product, List.of()));
            return rules;
        }

        public List<Osv.Match> osvFor(Dependency d) {
            return osv.getOrDefault(d.ecosystem(), Map.of()).getOrDefault(d.name(), List.of());
        }

        public List<CveList.Rule> cveFor(Dependency d) {
            var out = new LinkedHashSet<CveList.Rule>();
            for (String k : CveList.keysFor(d)) out.addAll(cve.getOrDefault(k, List.of()));
            return List.copyOf(out);
        }
    }

    private static final class Counts { int osv, cve, nvd, osvUsed, cveUsed, nvdUsed, entries; }

    private interface EntryHandler { void accept(InputStream entry) throws IOException; }

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
            if (!Files.isRegularFile(file)) throw new IOException(I18n.text("error.dbNotFound", file));
            long size = Math.max(1, Files.size(file));
            var counts = new Counts();
            l.status(I18n.text("status.reading", file.getFileName()));
            l.progress(0);
            try (var in = new CountingInputStream(new BufferedInputStream(Files.newInputStream(file), 1 << 16))) {
                // the bar moves every 500 records; the count is said every 5,000, a line each on the command line
                Runnable onEntry = () -> {
                    if (++counts.entries % 500 == 0) l.progress((double) in.count / size);
                    if (counts.entries % 5000 == 0) l.status(I18n.text("status.readingCount", file.getFileName(), counts.entries));
                };
                readZip(in, entry -> {
                    // an NVD feed is one JSON file of the whole year: read as a stream, a record at a time
                    var head = new BufferedInputStream(entry, 1 << 16);
                    head.mark(4096);
                    String start = new String(head.readNBytes(2048), UTF_8);
                    head.reset();
                    if (start.contains("\"NVD_CVE\"")) {
                        var used = new HashSet<String>();
                        counts.nvd += NvdFeed.read(new InputStreamReader(head, UTF_8), wanted.cotsProducts(),
                                rule -> index.nvd.computeIfAbsent(rule.product(), _ -> new ArrayList<>()).add(rule), used, onEntry);
                        counts.nvdUsed += used.size();
                    } else {
                        accept(head.readAllBytes(), wanted, index, counts);
                        onEntry.run();
                    }
                }, 0);
            } catch (ZipException e) {
                throw new IOException(I18n.text("error.notZip", file.getFileName(), e.getMessage()), e);
            }
            Phrase kind = Phrase.of(counts.nvd > 0 ? "database.kind.nvd"
                    : counts.osv > 0 && counts.cve > 0 ? "database.kind.both"
                    : counts.cve > 0 ? "database.kind.cve" : "database.kind.osv");
            int records = counts.osv + counts.cve + counts.nvd;
            total += records;
            if (records == 0)
                l.warn(Phrase.of("warning.noRecords", file.getFileName().toString()));
            index.sources.put(file.getFileName().toString(), Phrase.of("database.description",
                    kind, records, counts.osvUsed + counts.cveUsed + counts.nvdUsed,
                    Engine.STAMP.format(Files.getLastModifiedTime(file).toInstant())));
        }
        if (total == 0)
            throw new IOException(I18n.text("error.noRecordsAtAll"));
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
                handler.accept(zis);
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
