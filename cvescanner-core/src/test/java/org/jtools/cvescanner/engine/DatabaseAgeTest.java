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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A database is as old as its newest record, not as its file: older than the limit, the scan says so. */
class DatabaseAgeTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 11, 21);

    @TempDir
    Path dir;

    private Path database() throws IOException {
        Path zip = dir.resolve("osv.zip");
        try (var out = new ZipOutputStream(Files.newOutputStream(zip))) {
            for (String[] r : List.of(new String[]{"GHSA-aaaa", "2026-09-01T10:00:00Z"}, new String[]{"GHSA-bbbb", "2026-08-01T10:00:00Z"})) {
                out.putNextEntry(new ZipEntry(r[0] + ".json"));
                out.write(("{\"id\":\"" + r[0] + "\",\"modified\":\"" + r[1] + "\",\"affected\":[{\"package\":{\"ecosystem\":\"npm\","
                        + "\"name\":\"other\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]}]}").getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
            }
        }
        return zip;
    }

    private List<Phrase> warnings(int maxAge) throws IOException {
        Path project = Files.createDirectories(dir.resolve("p"));
        Files.writeString(project.resolve("package.json"), "{\"dependencies\":{\"lodash\":\"4.17.21\"}}");
        var r = Engine.scan(project, List.of(database()), new ScanOptions(null, ScanMode.SOURCES, maxAge, TODAY),
                new ScanListener() { public void status(String m) { } });
        assertEquals("database.descriptionNewest", r.snapshots().get("osv.zip").key(), "its newest record said, whatever the limit");
        assertEquals("2026-09-01", r.snapshots().get("osv.zip").arguments().get(4));
        return r.warnings().stream().filter(w -> w.key().equals("warning.dbOld")).toList();
    }

    @Test
    void olderThanTheLimitItIsSaidWithItsDateAndDays() throws IOException {
        var old = warnings(30);
        assertEquals(List.of(Phrase.of("warning.dbOld", "osv.zip", "2026-09-01", 81L, 30)), old);
        assertTrue(warnings(81).isEmpty(), "81 days is not more than 81");
        assertTrue(warnings(0).isEmpty(), "0: never");
    }

    /** A copy of the sample NVD feed, its timestamp changed. */
    private Path nvdFeed(String name, String timestamp) throws IOException {
        Path sample = Path.of("..", "samples", "db", "nvdcve-2.0-2024.json.zip");
        String feed;
        try (var in = new java.util.zip.ZipInputStream(Files.newInputStream(sample))) {
            in.getNextEntry();
            feed = new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("2026-11-21T00:00:00.000", timestamp);
        }
        Path zip = dir.resolve(name);
        try (var out = new ZipOutputStream(Files.newOutputStream(zip))) {
            out.putNextEntry(new ZipEntry(name.replace(".zip", "")));
            out.write(feed.getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
        }
        return zip;
    }

    private List<Phrase> nvdWarnings(Path... feeds) throws IOException {
        Path project = Files.createDirectories(dir.resolve("c"));
        Files.writeString(project.resolve("cots.csv"), "GDAL,3.4.1\n");
        var r = Engine.scan(project, List.of(feeds), new ScanOptions(null, ScanMode.SOURCES, 30, TODAY),
                new ScanListener() { public void status(String m) { } });
        return r.warnings().stream().filter(w -> w.key().equals("warning.dbOld")).toList();
    }

    @Test
    void theNvdFeedsAreAsOldAsTheirNewestRecordTakenTogether() throws IOException {
        Path old2003 = nvdFeed("nvdcve-2.0-2003.json.zip", "2026-09-01T00:00:00.000");
        Path fresh = nvdFeed("nvdcve-2.0-2026.json.zip", "2026-11-20T00:00:00.000");
        assertTrue(nvdWarnings(old2003, fresh).isEmpty(), "an old year that has not changed: the feeds are fresh");
        Path old2026 = nvdFeed("nvdcve-2.0-2026.json.zip", "2026-10-01T00:00:00.000");
        assertEquals(List.of(Phrase.of("warning.dbOld", Phrase.of("database.nvdFeeds", 2), "2026-10-01", 51L, 30)),
                nvdWarnings(old2003, old2026), "all old: said once, for the feeds");
        assertEquals("nvdcve-2.0-2003.json.zip", nvdWarnings(old2003).getFirst().arguments().getFirst(), "one feed alone: by its name");
    }
}
