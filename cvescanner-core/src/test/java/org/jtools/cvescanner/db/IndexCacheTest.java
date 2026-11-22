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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IndexCacheTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final ScanListener QUIET = new ScanListener() { public void status(String m) { } };

    @TempDir
    Path dir;

    private ScanResult scan(Path project, List<Path> dbs, Path cache) throws IOException {
        return Engine.scan(project, dbs, new ScanOptions(null, ScanMode.SOURCES, 0, LocalDate.of(2026, 11, 21), List.of(), null, null, cache), QUIET);
    }

    /** What a scan reports: its findings and its databases' descriptions. */
    private static String said(ScanResult r) {
        var sb = new StringBuilder();
        r.findings().stream().map(f -> f.id() + " " + f.pkg() + " " + f.version() + " " + f.file() + " " + f.fixedIn()).sorted()
                .forEach(l -> sb.append(l).append('\n'));
        r.snapshots().forEach((k, v) -> sb.append(k).append(": ").append(v.key()).append(v.arguments()).append('\n'));
        return sb.toString();
    }

    private Path copy(String db) throws IOException {
        Path to = dir.resolve(Path.of(db).getFileName());
        Files.copy(SAMPLES.resolve(db), to);
        return to;
    }

    /** The zip's bytes all zero, its size and time kept: read from the zip, it is no zip at all. */
    private static void spoil(Path zip) throws IOException {
        FileTime time = Files.getLastModifiedTime(zip);
        Files.write(zip, new byte[(int) Files.size(zip)]);
        Files.setLastModifiedTime(zip, time);
    }

    @Test
    void theSameFindingsWithoutTheCacheAndFromIt() throws IOException {
        var dbs = List.of(copy("db/advisory-database-main.zip"), copy("db/2026-11-19_all_CVEs_at_midnight.zip.zip"));
        Path project = SAMPLES.resolve("projects");
        String without = said(scan(project, dbs, null));
        Path cache = dir.resolve("cache");
        assertEquals(without, said(scan(project, dbs, cache)), "first scan, the cache written");
        assertEquals(without, said(scan(project, dbs, cache)), "second scan, from the cache");
    }

    @Test
    void aScanOfNamesCoveredReadsNoZipANewNameReadsItAgain() throws IOException {
        Path db = copy("db/advisory-database-main.zip");
        Path cache = dir.resolve("cache");
        Path npm = SAMPLES.resolve("projects/npm-lock"), maven = SAMPLES.resolve("projects/maven");
        String npmFirst = said(scan(npm, List.of(db), cache));
        byte[] zip = Files.readAllBytes(db);
        FileTime time = Files.getLastModifiedTime(db);
        spoil(db);
        assertEquals(npmFirst, said(scan(npm, List.of(db), cache)), "the zip not opened: the cache covers the names");
        assertThrows(IOException.class, () -> scan(maven, List.of(db), cache), "new names: the zip read again");
        assertNotNull(IndexCache.read(cache, db), "a read giving no record keeps nothing: the npm cache stays");
        Files.write(db, zip);
        Files.setLastModifiedTime(db, time);
        String mavenFirst = said(scan(maven, List.of(db), cache));
        spoil(db);
        assertEquals(npmFirst, said(scan(npm, List.of(db), cache)), "the cache now covers both projects");
        assertEquals(mavenFirst, said(scan(maven, List.of(db), cache)));
    }

    @Test
    void aChangedZipOrAnUnreadableCacheIsReadAgain() throws IOException {
        Path db = copy("db/advisory-database-main.zip");
        // a minute's start: the 2 seconds added below leave the date the description shows, to the minute, as it was
        Files.setLastModifiedTime(db, FileTime.from(Instant.parse("2026-11-20T10:00:00Z")));
        Path cache = dir.resolve("cache");
        Path project = SAMPLES.resolve("projects/npm-lock");
        String first = said(scan(project, List.of(db), cache));
        assertNotNull(IndexCache.read(cache, db));
        Files.setLastModifiedTime(db, FileTime.fromMillis(Files.getLastModifiedTime(db).toMillis() + 2000));
        assertNull(IndexCache.read(cache, db), "the zip changed: its cache no longer holds");
        scan(project, List.of(db), cache);
        try (var files = Files.list(cache)) {
            for (Path f : files.toList()) Files.writeString(f, "not gzip");
        }
        assertEquals(first, said(scan(project, List.of(db), cache)), "an unreadable cache: the zip read, the cache written again");
        assertNotNull(IndexCache.read(cache, db));
    }
}
