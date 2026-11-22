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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.json.Json;

/**
 * The index of a database file kept between scans, beside the program: the file's records for every name scanned so
 * far, and what the file holds (its kind, its record count, its newest date). Valid while the file keeps its path, size
 * and modification time, and the program its cache format; a scan wanting a name not covered reads the zip again, for
 * the names wanted and those covered. A cache file that cannot be read is ignored; one that cannot be written, left.
 */
final class IndexCache {

    /** Raised when what is kept changes: a cache of another format is read again from the zip. */
    private static final int FORMAT = 1;

    /** A file's part as kept, and the names it was read for. */
    record Cached(VulnDb.Part part, VulnDb.Wanted covered) {}

    private IndexCache() {}

    /** The part kept for this database file; null when there is none, or it is not for the file as it is now. */
    static Cached read(Path cacheDir, Path db) {
        Path file = cacheDir.resolve(name(db));
        if (!Files.isRegularFile(file)) return null;
        try (InputStream in = new GZIPInputStream(Files.newInputStream(file))) {
            var doc = Json.obj(Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
            if (!Long.valueOf(FORMAT).equals(doc.get("format")) || !String.valueOf(version()).equals(doc.get("program"))
                    || !db.toAbsolutePath().normalize().toString().equals(doc.get("file")) || !fingerprint(db).equals(doc.get("fingerprint")))
                return null;
            return new Cached(part(doc), covered(Json.obj(doc.get("covered"))));
        } catch (IOException | RuntimeException _) {
            return null;   // unreadable, of a shape not foreseen: the zip is read again
        }
    }

    /** The part kept for this database file, read for these names; nothing kept when the folder cannot be written in. */
    static void write(Path cacheDir, Path db, VulnDb.Wanted covered, VulnDb.Part part) {
        try {
            Files.createDirectories(cacheDir);
            var doc = new LinkedHashMap<String, Object>();
            doc.put("format", FORMAT);
            doc.put("program", String.valueOf(version()));
            doc.put("file", db.toAbsolutePath().normalize().toString());
            doc.put("fingerprint", fingerprint(db));
            doc.put("covered", covered(covered));
            doc.put("kind", part.kind);
            doc.put("records", part.records);
            doc.put("newest", part.newest);
            doc.put("nvdFeed", part.nvdFeed);
            store(part, doc);
            var bytes = new ByteArrayOutputStream();
            try (var gz = new GZIPOutputStream(bytes)) {
                gz.write(Json.write(doc).getBytes(StandardCharsets.UTF_8));
            }
            // written whole, then moved into place: a scan stopped halfway, or two at once, leave no half file
            Path tmp = Files.createTempFile(cacheDir, "index", ".tmp");
            Files.write(tmp, bytes.toByteArray());
            try {
                Files.move(tmp, cacheDir.resolve(name(db)), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException _) {
                Files.move(tmp, cacheDir.resolve(name(db)), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException | RuntimeException _) {
            // no cache: the next scan reads the zip, as this one did
        }
    }

    /** The cache file of a database file: named by its path, which no other file shares. */
    private static String name(Path db) {
        try {
            var sha = MessageDigest.getInstance("SHA-1").digest(db.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8));
            var sb = new StringBuilder();
            for (byte b : sha) sb.append(String.format("%02x", b));
            return sb + ".json.gz";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String fingerprint(Path db) throws IOException {
        return Files.size(db) + "/" + Files.getLastModifiedTime(db).toMillis();
    }

    private static String version() {
        return IndexCache.class.getPackage().getImplementationVersion();
    }

    // ------------------------------------------------------------------------------------------- names covered

    private static Map<String, Object> covered(VulnDb.Wanted w) {
        var m = new LinkedHashMap<String, Object>();
        var by = new LinkedHashMap<String, Object>();
        new java.util.TreeMap<>(w.byEcosystem()).forEach((k, v) -> by.put(k, List.copyOf(new TreeSet<>(v))));
        m.put("byEcosystem", by);
        m.put("allNames", List.copyOf(new TreeSet<>(w.allNames())));
        m.put("cveKeys", List.copyOf(new TreeSet<>(w.cveKeys())));
        m.put("cotsProducts", List.copyOf(new TreeSet<>(w.cotsProducts())));
        m.put("mavenArtifacts", List.copyOf(new TreeSet<>(w.mavenArtifacts())));
        return m;
    }

    private static VulnDb.Wanted covered(Map<String, Object> m) {
        var by = new HashMap<String, Set<String>>();
        Json.obj(m.get("byEcosystem")).forEach((k, v) -> by.put(k, strings(v)));
        return new VulnDb.Wanted(by, strings(m.get("allNames")), strings(m.get("cveKeys")), strings(m.get("cotsProducts")),
                strings(m.get("mavenArtifacts")));
    }

    private static Set<String> strings(Object list) {
        var out = new HashSet<String>();
        for (Object o : Json.arr(list)) out.add(String.valueOf(o));
        return out;
    }

    // ------------------------------------------------------------------------------------------- records

    /** The records written once each: an OSV record shared by its matches, an Info by its rules. */
    private static void store(VulnDb.Part part, Map<String, Object> doc) {
        var vulns = new ArrayList<Object>();
        var vulnIndex = new IdentityHashMap<Map<String, Object>, Integer>();
        var osv = new ArrayList<Object>();
        part.osv.forEach((eco, byName) -> byName.forEach((name, matches) -> {
            for (Osv.Match m : matches) {
                int v = vulnIndex.computeIfAbsent(m.vuln(), x -> { vulns.add(x); return vulns.size() - 1; });
                osv.add(List.of(eco, name, v, Json.arr(m.vuln().get("affected")).indexOf(m.affected())));
            }
        }));
        var infos = new ArrayList<Object>();
        var infoIndex = new IdentityHashMap<CveList.Info, Integer>();
        var cve = new ArrayList<Object>();
        part.cve.forEach((key, rules) -> {
            for (CveList.Rule r : rules) {
                var m = new LinkedHashMap<String, Object>();
                m.put("key", key);
                m.put("info", infoIndex.computeIfAbsent(r.info(), i -> { infos.add(info(i)); return infos.size() - 1; }));
                m.put("vendor", r.vendor());
                m.put("product", r.product());
                m.put("packageName", r.packageName());
                m.put("collectionUrl", r.collectionUrl());
                m.put("defaultStatus", r.defaultStatus());
                m.put("versions", r.versions());
                cve.add(m);
            }
        });
        var nvd = new ArrayList<Object>();
        part.nvd.forEach((product, rules) -> {
            for (NvdFeed.Rule r : rules) {
                var m = new LinkedHashMap<String, Object>();
                m.put("info", infoIndex.computeIfAbsent(r.info(), i -> { infos.add(info(i)); return infos.size() - 1; }));
                m.put("cpe", r.cpe());
                m.put("vendor", r.vendor());
                m.put("product", r.product());
                m.put("version", r.version());
                m.put("startIncluding", r.startIncluding());
                m.put("startExcluding", r.startExcluding());
                m.put("endIncluding", r.endIncluding());
                m.put("endExcluding", r.endExcluding());
                nvd.add(m);
            }
        });
        doc.put("vulns", vulns);
        doc.put("osv", osv);
        doc.put("infos", infos);
        doc.put("cve", cve);
        doc.put("nvd", nvd);
    }

    @SuppressWarnings("unchecked")
    private static VulnDb.Part part(Map<String, Object> doc) {
        var part = new VulnDb.Part();
        part.kind = Json.str(doc, "kind");
        part.records = ((Number) doc.get("records")).intValue();
        part.newest = Json.str(doc, "newest");
        part.nvdFeed = Boolean.TRUE.equals(doc.get("nvdFeed"));
        var vulns = Json.arr(doc.get("vulns"));
        for (Object o : Json.arr(doc.get("osv"))) {
            var e = Json.arr(o);
            var vuln = (Map<String, Object>) vulns.get(((Number) e.get(2)).intValue());
            var affected = Json.obj(Json.arr(vuln.get("affected")).get(((Number) e.get(3)).intValue()));
            part.osv.computeIfAbsent((String) e.get(0), _ -> new HashMap<>()).computeIfAbsent((String) e.get(1), _ -> new ArrayList<>())
                    .add(new Osv.Match(vuln, affected));
        }
        var infos = new ArrayList<CveList.Info>();
        for (Object o : Json.arr(doc.get("infos"))) infos.add(info(Json.obj(o)));
        for (Object o : Json.arr(doc.get("cve"))) {
            var m = Json.obj(o);
            var versions = new ArrayList<Map<String, Object>>();
            for (Object v : Json.arr(m.get("versions"))) versions.add(Json.obj(v));
            part.cve.computeIfAbsent(Json.str(m, "key"), _ -> new ArrayList<>()).add(new CveList.Rule(infos.get(((Number) m.get("info")).intValue()),
                    Json.str(m, "vendor"), Json.str(m, "product"), Json.str(m, "packageName"), Json.str(m, "collectionUrl"),
                    Json.str(m, "defaultStatus"), versions));
        }
        for (Object o : Json.arr(doc.get("nvd"))) {
            var m = Json.obj(o);
            var rule = new NvdFeed.Rule(infos.get(((Number) m.get("info")).intValue()), Json.str(m, "cpe"), Json.str(m, "vendor"),
                    Json.str(m, "product"), Json.str(m, "version"), Json.str(m, "startIncluding"), Json.str(m, "startExcluding"),
                    Json.str(m, "endIncluding"), Json.str(m, "endExcluding"));
            part.nvd.computeIfAbsent(rule.product(), _ -> new ArrayList<>()).add(rule);
        }
        return part;
    }

    private static Map<String, Object> info(CveList.Info i) {
        var m = new LinkedHashMap<String, Object>();
        m.put("id", i.id());
        m.put("summary", i.summary());
        m.put("details", i.details());
        m.put("published", i.published());
        if (i.rating() != null) {
            var r = new LinkedHashMap<String, Object>();
            r.put("severity", i.rating().severity() == null ? null : i.rating().severity().name());
            r.put("score", i.rating().score());
            r.put("cvss3", i.rating().cvss3());
            r.put("cvss4", i.rating().cvss4());
            m.put("rating", r);
        }
        return m;
    }

    private static CveList.Info info(Map<String, Object> m) {
        Rating rating = null;
        if (m.get("rating") instanceof Map<?, ?> raw) {
            var r = Json.obj(raw);
            String severity = Json.str(r, "severity");
            rating = new Rating(severity == null ? null : Severity.valueOf(severity),
                    r.get("score") instanceof Number n ? n.doubleValue() : null, Json.str(r, "cvss3"), Json.str(r, "cvss4"));
        }
        return new CveList.Info(Json.str(m, "id"), Json.str(m, "summary"), Json.str(m, "details"), Json.str(m, "published"), rating);
    }
}
