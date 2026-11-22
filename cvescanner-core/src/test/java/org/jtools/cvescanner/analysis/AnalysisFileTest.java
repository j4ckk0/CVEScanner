package org.jtools.cvescanner.analysis;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A scan written to an analysis file reads back as it was; a file not one, a later one's or damaged is said so. */
class AnalysisFileTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final ScanListener QUIET = new ScanListener() { public void status(String m) { } };
    private static final Instant EXPORTED = Instant.parse("2026-11-23T10:15:00Z");

    @TempDir
    Path dir;

    /** A database whose newest record is dated, as the samples' are not: said old past its age. */
    static Path dated(Path dir) throws IOException {
        Path zip = dir.resolve("dated.zip");
        try (var out = new ZipOutputStream(Files.newOutputStream(zip))) {
            out.putNextEntry(new ZipEntry("GHSA-aaaa.json"));
            out.write(("{\"id\":\"GHSA-aaaa\",\"modified\":\"2026-09-01T10:00:00Z\",\"affected\":[{\"package\":{\"ecosystem\":\"npm\","
                    + "\"name\":\"other\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]}]}").getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
        }
        return zip;
    }

    /** The samples with their ignore file and VEX document, past their databases' age: warnings of every kind. */
    private ScanResult samples() throws IOException {
        return Engine.scan(SAMPLES.resolve("projects"), List.of(SAMPLES.resolve("db/advisory-database-main.zip"), dated(dir)),
                new ScanOptions(SAMPLES.resolve("ignore/cvescanner-ignore.csv"), ScanMode.SOURCES, 1, LocalDate.of(2030, 1, 1),
                        List.of(SAMPLES.resolve("vex/product.vex.json"))), QUIET);
    }

    private static List<String> said(List<Phrase> phrases) {
        return phrases.stream().map(Phrase::text).toList();
    }

    private static <K> Map<K, String> said(Map<K, Phrase> phrases, Function<Phrase, String> text) {
        var out = new java.util.LinkedHashMap<K, String>();
        phrases.forEach((k, p) -> out.put(k, text.apply(p)));
        return out;
    }

    @Test
    void aScanReadsBackAsItWas() throws Exception {
        var scan = samples();
        assertTrue(scan.warnings().stream().anyMatch(w -> w.key().equals("warning.dbOld")), "a warning with numbers: " + scan.warnings());
        assertTrue(scan.ignores().read() && !scan.ignores().vex().isEmpty(), "the ignore file and the VEX document read");
        Path file = dir.resolve("samples" + AnalysisFile.EXTENSION);
        AnalysisFile.write(scan, file, EXPORTED);
        var back = AnalysisFile.read(file);

        assertEquals(scan.findings(), back.findings());
        assertEquals(scan.dependencies(), back.dependencies());
        assertEquals(scan.unresolved().stream().map(u -> u.name() + " " + u.reason().text()).toList(),
                back.unresolved().stream().map(u -> u.name() + " " + u.reason().text()).toList());
        assertEquals(said(scan.warnings()), said(back.warnings()));
        assertEquals(said(scan.snapshots(), Phrase::text), said(back.snapshots(), Phrase::text));
        assertEquals(scan.fileCounts(), back.fileCounts());
        assertEquals(scan.ignores().rules(), back.ignores().rules());
        assertEquals(scan.ignores().vex(), back.ignores().vex());
        assertEquals(scan.ignores().shown(), back.ignores().shown());
        assertTrue(back.ignores().read());
        assertNull(back.ignores().file(), "the ignore file is on the other computer");
        assertEquals(scan.root(), back.root());
        assertEquals(scan.mode(), back.mode());
        assertEquals(scan.mavenRepository(), back.mavenRepository());
        // the days of warning.dbOld, a number still: the window reads it as one
        var days = back.warnings().stream().filter(w -> w.key().equals("warning.dbOld")).findFirst().orElseThrow().arguments().get(2);
        assertTrue(days instanceof Number, "the days: " + days);

        var from = back.imported();
        assertEquals(file.toAbsolutePath().normalize().toString(), from.file());
        assertEquals(EXPORTED, from.exportedAt());
        assertEquals(scan.root().toString(), from.root());
        assertFalse(from.rechecked());
    }

    @Test
    void parentsNotRecordedStayNotRecorded() throws Exception {
        var scan = Engine.scan(SAMPLES.resolve("projects-gradle-lock"), List.of(SAMPLES.resolve("db/advisory-database-main.zip")),
                new ScanOptions(null, ScanMode.SOURCES, 0, LocalDate.of(2026, 11, 23)), QUIET);
        assertTrue(scan.dependencies().stream().anyMatch(d -> d.parents() == null), "a Gradle lockfile records no parents");
        Path file = dir.resolve("gradle.cvescan");
        AnalysisFile.write(scan, file, EXPORTED);
        assertEquals(scan.dependencies(), AnalysisFile.read(file).dependencies());
    }

    @Test
    void anAnalysisPassedOnKeepsWhereItWasMade() throws Exception {
        Path first = dir.resolve("first.cvescan"), second = dir.resolve("second.cvescan");
        AnalysisFile.write(samples(), first, EXPORTED);
        AnalysisFile.write(AnalysisFile.read(first), second, EXPORTED.plusSeconds(3600));
        var back = AnalysisFile.read(second);
        assertEquals(EXPORTED, back.imported().exportedAt(), "when the scan was first exported");
        assertEquals(SAMPLES.resolve("projects").toString(), back.imported().root());
    }

    @Test
    void aLaterFormatIsRefused() throws Exception {
        Path file = zip("analysis.json", "{\"format\": \"cvescanner-analysis\", \"formatVersion\": 2, \"program\": \"9.0\"}");
        var e = assertThrows(IOException.class, () -> AnalysisFile.read(file));
        assertTrue(e.getMessage().contains("9.0"), e.getMessage());
    }

    @Test
    void whatIsNotOneIsSaidSo() throws Exception {
        Path text = Files.writeString(dir.resolve("notes.cvescan"), "not a zip");
        assertTrue(assertThrows(IOException.class, () -> AnalysisFile.read(text)).getMessage().contains("not an analysis file"));
        Path other = zip("other.json", "{}");
        assertTrue(assertThrows(IOException.class, () -> AnalysisFile.read(other)).getMessage().contains("not an analysis file"));
        Path foreign = zip("analysis.json", "{\"format\": \"something else\"}");
        assertTrue(assertThrows(IOException.class, () -> AnalysisFile.read(foreign)).getMessage().contains("not an analysis file"));
    }

    @Test
    void aDamagedOneIsSaidSo() throws Exception {
        Path broken = zip("analysis.json", "{\"format\": \"cvescanner-analysis\", ");
        assertTrue(assertThrows(IOException.class, () -> AnalysisFile.read(broken)).getMessage().contains("damaged"));
        Path noSeverity = zip("analysis.json", """
                {"format": "cvescanner-analysis", "formatVersion": 1, "exportedAt": "2026-11-23T10:15:00Z", "root": "/x",
                 "mode": "SOURCES", "findings": [{"ecosystem": "npm", "package": "a", "version": "1", "scope": "", "file": "f", "id": "X"}]}""");
        var e = assertThrows(IOException.class, () -> AnalysisFile.read(noSeverity));
        assertTrue(e.getMessage().contains("damaged") && e.getMessage().contains("severity"), e.getMessage());
    }

    @Test
    void tooLargeOnceUnzippedIsNotRead() throws Exception {
        Path big = zip("analysis.json", "{\"format\": \"cvescanner-analysis\", \"pad\": \"" + "x".repeat(4096) + "\"}");
        var e = assertThrows(IOException.class, () -> AnalysisFile.read(big, 1024));
        assertTrue(e.getMessage().contains("too large"), e.getMessage());
    }

    @Test
    void theNameProposedIsTheFolderAndTheDay() throws Exception {
        assertEquals("my-app", AnalysisFile.folderName("C:\\src\\my-app"));
        assertEquals("my-app", AnalysisFile.folderName("/home/me/src/my-app/"));
        assertEquals("projects-2026-11-23.cvescan",
                AnalysisFile.defaultName(samples(), Clock.fixed(EXPORTED, ZoneOffset.UTC)));
        assertTrue(AnalysisFile.named(Path.of("x/My-App.CVESCAN")));
        assertFalse(AnalysisFile.named(Path.of("x/my-app")));
    }

    private Path zip(String entry, String text) throws IOException {
        Path file = Files.createTempFile(dir, "test", AnalysisFile.EXTENSION);
        try (var zip = new ZipOutputStream(Files.newOutputStream(file))) {
            zip.putNextEntry(new ZipEntry(entry));
            zip.write(text.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return file;
    }
}
