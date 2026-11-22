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
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
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
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanResult;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Database loading from zip files: OSV / GitHub Advisory Database records, CVE List (CVE JSON 5) records and NVD feeds.
 * Zips are streamed (never extracted) and nested zips are followed, so the cvelistV5 release asset works.
 * Only records that mention a package the project uses are parsed and kept.
 */
public final class VulnDb {
    private static final Pattern OSV_NAME = Pattern.compile("\"name\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    /** A record's last change, in its first lines: OSV's "modified", the CVE List's "dateUpdated"; an NVD feed's "timestamp". */
    private static final Pattern RECORD_DATE = Pattern.compile("\"(?:modified|dateUpdated)\"\\s*:\\s*\"(\\d{4}-\\d{2}-\\d{2})");
    private static final Pattern FEED_DATE = Pattern.compile("\"timestamp\"\\s*:\\s*\"(\\d{4}-\\d{2}-\\d{2})");
    private static final Pattern CVE_NAME = Pattern.compile("\"(?:product|packageName)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    /**
     * What the scan looks for: packages by ecosystem, the CVE List's keys, and the products of the COTS components.
     *
     * @param mavenArtifacts the artifactIds of jars known by their name alone (no group): every group's advisories for
     *                       them are wanted
     */
    public record Wanted(Map<String, Set<String>> byEcosystem, Set<String> allNames, Set<String> cveKeys,
                         Set<String> cotsProducts, Set<String> mavenArtifacts) {
        public static Wanted of(List<Dependency> deps) {
            var by = new HashMap<String, Set<String>>();
            var all = new HashSet<String>();
            var keys = new HashSet<String>();
            var products = new HashSet<String>();
            var artifacts = new HashSet<String>();
            for (var d : deps) {
                if (d.ecosystem() == Ecosystem.MAVEN && !d.name().contains(":")) artifacts.add(d.name());
                by.computeIfAbsent(d.ecosystem().id(), _ -> new HashSet<>()).add(d.ecosystem().matchName(d.name()));
                all.add(d.name());
                all.add(d.ecosystem().matchName(d.name()));
                keys.addAll(CveList.keysFor(d));
                if (d.ecosystem() == Ecosystem.COTS) products.addAll(KnownProducts.products(Ecosystem.product(d.name())));
            }
            return new Wanted(by, all, keys, products, artifacts);
        }

        /** What either wants. */
        public Wanted union(Wanted o) {
            var by = new HashMap<String, Set<String>>();
            byEcosystem.forEach((k, v) -> by.computeIfAbsent(k, _ -> new HashSet<>()).addAll(v));
            o.byEcosystem.forEach((k, v) -> by.computeIfAbsent(k, _ -> new HashSet<>()).addAll(v));
            return new Wanted(by, union(allNames, o.allNames), union(cveKeys, o.cveKeys), union(cotsProducts, o.cotsProducts),
                    union(mavenArtifacts, o.mavenArtifacts));
        }

        private static Set<String> union(Set<String> a, Set<String> b) {
            var out = new HashSet<>(a);
            out.addAll(b);
            return out;
        }

        /** Whether everything this wants, that wanted too: a part read for it holds all this needs. */
        public boolean within(Wanted other) {
            for (var e : byEcosystem.entrySet())
                if (!other.byEcosystem.getOrDefault(e.getKey(), Set.of()).containsAll(e.getValue())) return false;
            return other.cveKeys.containsAll(cveKeys) && other.cotsProducts.containsAll(cotsProducts)
                    && other.mavenArtifacts.containsAll(mavenArtifacts);
        }
    }

    /**
     * One database file read for some names: its records for them, and what the file holds whatever the names (its
     * kind, its record count, its newest record's date). Read from the zip, or from the index cache (IndexCache).
     */
    static final class Part {
        final Map<String, Map<String, List<Osv.Match>>> osv = new HashMap<>();
        final Map<String, List<CveList.Rule>> cve = new HashMap<>();
        final Map<String, List<NvdFeed.Rule>> nvd = new HashMap<>();
        String kind;
        int records;
        String newest;   // yyyy-MM-dd, null when its records are not dated
        boolean nvdFeed;

        /** How many of its records these names use: an OSV record, a CVE List record, an NVD record, once each. */
        int used(Wanted w) {
            var ids = new HashSet<String>();
            osv.forEach((eco, byName) -> byName.forEach((name, matches) -> {
                boolean wanted = w.byEcosystem().getOrDefault(eco, Set.of()).contains(name)
                        || (eco.equals(Ecosystem.MAVEN.id()) && w.mavenArtifacts().contains(name));
                if (wanted) matches.forEach(m -> ids.add("osv " + Json.str(m.vuln(), "id")));
            }));
            cve.forEach((key, rules) -> { if (w.cveKeys().contains(key)) rules.forEach(r -> ids.add("cve " + r.info().id())); });
            nvd.forEach((product, rules) -> { if (w.cotsProducts().contains(product)) rules.forEach(r -> ids.add("nvd " + r.info().id())); });
            return ids.size();
        }

        void addTo(Index index) {
            osv.forEach((eco, byName) -> byName.forEach((name, matches) ->
                    index.osv.computeIfAbsent(eco, _ -> new HashMap<>()).computeIfAbsent(name, _ -> new ArrayList<>()).addAll(matches)));
            cve.forEach((k, rules) -> index.cve.computeIfAbsent(k, _ -> new ArrayList<>()).addAll(rules));
            nvd.forEach((k, rules) -> index.nvd.computeIfAbsent(k, _ -> new ArrayList<>()).addAll(rules));
        }
    }

    public static final class Index {
        final Map<String, Map<String, List<Osv.Match>>> osv = new HashMap<>();
        final Map<String, List<CveList.Rule>> cve = new HashMap<>();
        final Map<String, List<NvdFeed.Rule>> nvd = new HashMap<>();
        public final Map<String, Phrase> sources = new LinkedHashMap<>();
        /** Each database file's newest record, when its records are dated: how old the data is, not the file. */
        public final Map<String, LocalDate> newest = new LinkedHashMap<>();
        /** The NVD feeds among them: one database split by year, whose old years change seldom. */
        public final Set<String> nvdFeeds = new LinkedHashSet<>();

        /** The NVD rules of a COTS component's product. */
        public List<NvdFeed.Rule> nvdFor(Dependency d) {
            if (d.ecosystem() != Ecosystem.COTS) return List.of();
            var rules = new ArrayList<NvdFeed.Rule>();
            for (String product : KnownProducts.products(Ecosystem.product(d.name()))) rules.addAll(nvd.getOrDefault(product, List.of()));
            return rules;
        }

        public List<Osv.Match> osvFor(Dependency d) {
            return osv.getOrDefault(d.ecosystem().id(), Map.of()).getOrDefault(d.ecosystem().matchName(d.name()), List.of());
        }

        public List<CveList.Rule> cveFor(Dependency d) {
            var out = new LinkedHashSet<CveList.Rule>();
            for (String k : CveList.keysFor(d)) out.addAll(cve.getOrDefault(k, List.of()));
            return List.copyOf(out);
        }
    }

    private static final class Counts {
        int osv, cve, nvd, entries;
        String newest;   // yyyy-MM-dd, compared as text

        void dated(Pattern date, String text) {
            var m = date.matcher(text.length() > 4096 ? text.substring(0, 4096) : text);
            while (m.find()) if (newest == null || m.group(1).compareTo(newest) > 0) newest = m.group(1);
        }
    }

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
        return load(files, wanted, l, null);
    }

    /**
     * The index of these database files for the names wanted.
     *
     * @param cacheDir where each file's part is kept between scans (IndexCache); null for none
     */
    public static Index load(List<Path> files, Wanted wanted, ScanListener l, Path cacheDir) throws IOException {
        var index = new Index();
        int total = 0;
        for (Path file : files) {
            if (!Files.isRegularFile(file)) throw new IOException(I18n.text("error.dbNotFound", file));
            Part part = null;
            Wanted covered = null;
            if (cacheDir != null) {
                var cached = IndexCache.read(cacheDir, file);
                if (cached != null && wanted.within(cached.covered())) part = cached.part();
                else if (cached != null) covered = cached.covered();
            }
            if (part == null) {
                // read for the names wanted and those the cache had: a project scanned before stays served
                Wanted reading = covered == null ? wanted : covered.union(wanted);
                part = read(file, reading, l);
                // a file read to no record at all is no database, or a damaged one: nothing kept of it
                if (cacheDir != null && part.records > 0) IndexCache.write(cacheDir, file, reading, part);
            } else {
                l.status(I18n.text("status.reading", file.getFileName()));
            }
            part.addTo(index);
            total += part.records;
            if (part.records == 0)
                l.warn(Phrase.of("warning.noRecords", file.getFileName().toString()));
            String name = file.getFileName().toString();
            String fileDate = ScanResult.TIMESTAMP_UTC.format(Files.getLastModifiedTime(file).toInstant());
            int used = part.used(wanted);
            LocalDate newest = date(part.newest);
            if (newest != null) index.newest.put(name, newest);
            if (part.nvdFeed) index.nvdFeeds.add(name);
            Phrase kind = Phrase.of(part.kind);
            index.sources.put(name, newest == null ? Phrase.of("database.description", kind, part.records, used, fileDate)
                    : Phrase.of("database.descriptionNewest", kind, part.records, used, fileDate, newest.toString()));
        }
        if (total == 0)
            throw new IOException(I18n.text("error.noRecordsAtAll"));
        return index;
    }

    /** A database file read from its zip, for the names wanted. */
    private static Part read(Path file, Wanted wanted, ScanListener l) throws IOException {
        var part = new Part();
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
                    counts.dated(FEED_DATE, start);
                    counts.nvd += NvdFeed.read(new InputStreamReader(head, UTF_8), wanted.cotsProducts(),
                            rule -> part.nvd.computeIfAbsent(rule.product(), _ -> new ArrayList<>()).add(rule), new HashSet<>(), onEntry);
                } else {
                    indexRecord(head.readAllBytes(), wanted, part, counts);
                    onEntry.run();
                }
            }, 0);
        } catch (ZipException e) {
            throw new IOException(I18n.text("error.notZip", file.getFileName(), e.getMessage()), e);
        }
        part.kind = counts.nvd > 0 ? "database.kind.nvd" : counts.osv > 0 && counts.cve > 0 ? "database.kind.both"
                : counts.cve > 0 ? "database.kind.cve" : "database.kind.osv";
        part.records = counts.osv + counts.cve + counts.nvd;
        part.newest = counts.newest;
        part.nvdFeed = counts.nvd > 0;
        return part;
    }

    private static LocalDate date(String text) {
        if (text == null) return null;
        try {
            return LocalDate.parse(text);
        } catch (DateTimeParseException _) {
            return null;   // a month 13: no date then
        }
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
            if (keys.contains(v) || (!normalize && keys.contains(Ecosystem.pep503(v)))) return true;   // a Python name, as written
        }
        return false;
    }

    /** Whether the record names group:artifact for one of these artifactIds. */
    private static boolean mentionsArtifact(String text, Set<String> artifacts) {
        if (artifacts.isEmpty()) return false;
        var m = OSV_NAME.matcher(text);
        while (m.find()) {
            String v = m.group(1);
            int colon = v.indexOf(':');
            if (colon > 0 && artifacts.contains(v.substring(colon + 1))) return true;
        }
        return false;
    }

    private static void indexRecord(byte[] data, Wanted wanted, Part index, Counts counts) {
        String text = new String(data, UTF_8);
        if (text.contains("\"cveMetadata\"")) {                               // CVE List record
            counts.cve++;
            counts.dated(RECORD_DATE, text);
            if (!mentions(CVE_NAME, text, wanted.cveKeys(), true)) return;
            Map<String, Object> rec;
            try { rec = Json.obj(Json.parse(text)); } catch (IllegalArgumentException _) { return; }
            for (var rule : CveList.rules(rec))
                for (String key : rule.keys())
                    if (wanted.cveKeys().contains(key)) index.cve.computeIfAbsent(key, _ -> new ArrayList<>()).add(rule);
        } else if (text.contains("\"affected\"") && text.contains("\"ecosystem\"")) {   // OSV / GitHub advisory
            counts.osv++;
            counts.dated(RECORD_DATE, text);
            if (!mentions(OSV_NAME, text, wanted.allNames(), false) && !mentionsArtifact(text, wanted.mavenArtifacts())) return;
            Map<String, Object> vuln;
            try { vuln = Json.obj(Json.parse(text)); } catch (IllegalArgumentException _) { return; }
            if (vuln.get("withdrawn") != null || Json.str(vuln, "id") == null) return;
            for (Object a : Json.arr(vuln.get("affected"))) {
                var aff = Json.obj(a);
                var pkg = Json.obj(aff.get("package"));
                String eco = Objects.requireNonNullElse(Json.str(pkg, "ecosystem"), "").split(":")[0];
                String name = Json.str(pkg, "name");
                if (name != null && Ecosystem.PYPI.id().equals(eco)) name = Ecosystem.pep503(name);
                if (name != null && wanted.byEcosystem().getOrDefault(eco, Set.of()).contains(name)) {
                    index.osv.computeIfAbsent(eco, _ -> new HashMap<>()).computeIfAbsent(name, _ -> new ArrayList<>())
                            .add(new Osv.Match(vuln, aff));
                }
                // a jar known by its artifactId alone: the advisory of any group:artifactId, under that artifactId
                String artifact = name != null && Ecosystem.MAVEN.id().equals(eco) ? name.substring(name.indexOf(':') + 1) : null;
                if (artifact != null && name.contains(":") && wanted.mavenArtifacts().contains(artifact)) {
                    index.osv.computeIfAbsent(eco, _ -> new HashMap<>()).computeIfAbsent(artifact, _ -> new ArrayList<>())
                            .add(new Osv.Match(vuln, aff));
                }
            }
        }
    }
}
