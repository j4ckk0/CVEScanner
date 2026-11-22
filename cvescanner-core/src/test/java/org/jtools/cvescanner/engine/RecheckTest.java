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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import org.jtools.cvescanner.analysis.AnalysisFile;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An analysis re-checked here: its dependencies matched against these databases as a scan of the folder would match
 * them, its own warnings kept but its databases', its ignore entries applying unless others are named.
 */
class RecheckTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final ScanListener QUIET = new ScanListener() { public void status(String m) { } };
    private static final LocalDate TODAY = LocalDate.of(2026, 11, 23);
    private static final Path GHSA = SAMPLES.resolve("db/advisory-database-main.zip");
    private static final Path IGNORE = SAMPLES.resolve("ignore/cvescanner-ignore.csv");

    @TempDir
    Path dir;

    private static ScanOptions options(Path ignore, int maxAge, LocalDate today, boolean directOnly) {
        return new ScanOptions(ignore, ScanMode.SOURCES, maxAge, today, List.of(), null, null, null, directOnly);
    }

    /** The samples scanned, written to a file and read back: the analysis as another computer opens it. */
    private ScanResult exported(ScanOptions options) throws Exception {
        return exported(options, List.of(GHSA));
    }

    private ScanResult exported(ScanOptions options, List<Path> databases) throws Exception {
        var scan = Engine.scan(SAMPLES.resolve("projects"), databases, options, QUIET);
        Path file = dir.resolve("projects.cvescan");
        AnalysisFile.write(scan, file, org.jtools.cvescanner.cvss.Environment.NONE, true);
        return AnalysisFile.read(file);
    }

    @Test
    void againstTheSameDatabaseTheSameFindings() throws Exception {
        var options = options(IGNORE, 0, TODAY, false);
        var scan = Engine.scan(SAMPLES.resolve("projects"), List.of(GHSA), options, QUIET);
        var again = Engine.recheck(exported(options), List.of(GHSA), options(null, 0, TODAY, false), QUIET);
        assertEquals(scan.findings(), again.findings());
        assertEquals(scan.dependencies(), again.dependencies());
        assertEquals(scan.ignores().rules(), again.ignores().rules(), "the analysis's ignore entries apply");
        assertTrue(again.imported().rechecked());
        assertEquals(scan.root().toString(), again.imported().root());
    }

    @Test
    void againstAnotherDatabaseWhatThatOneFinds() throws Exception {
        Path examples = SAMPLES.resolve("db/examples.zip");
        var analysis = exported(options(null, 0, TODAY, false));
        var direct = Engine.scan(SAMPLES.resolve("projects"), List.of(examples), options(null, 0, TODAY, false), QUIET);
        var again = Engine.recheck(analysis, List.of(examples), options(null, 0, TODAY, false), QUIET);
        assertNotEquals(analysis.findings(), again.findings(), "the other database finds others");
        assertEquals(direct.findings(), again.findings());
        assertEquals(direct.snapshots().keySet(), again.snapshots().keySet());
    }

    @Test
    void directOnlyLeavesTheIndirectOnesOut() throws Exception {
        var analysis = exported(options(null, 0, TODAY, false));
        assertTrue(analysis.dependencies().stream().anyMatch(Dependency::transitive));
        var again = Engine.recheck(analysis, List.of(GHSA), options(null, 0, TODAY, true), QUIET);
        assertTrue(again.dependencies().stream().noneMatch(Dependency::transitive));
        assertTrue(again.directOnly());
        assertTrue(again.findings().stream().noneMatch(f -> Dependency.isTransitive(f.scope())));
    }

    @Test
    void anotherIgnoreFileReplacesTheAnalysissOwn() throws Exception {
        var analysis = exported(options(IGNORE, 0, TODAY, false));
        assertTrue(analysis.warnings().stream().anyMatch(w -> w.key().startsWith("ignore.")), "the sample's bad lines: " + analysis.warnings());
        var none = Engine.recheck(analysis, List.of(GHSA), options(Ignores.DISABLED, 0, TODAY, false), QUIET);
        assertTrue(none.ignores().rules().isEmpty());
        assertFalse(none.ignores().read());
        assertTrue(none.warnings().stream().noneMatch(w -> w.key().startsWith("ignore.")), "the analysis's ignore file not read: " + none.warnings());
        assertEquals(analysis.ignores().vex(), none.ignores().vex(), "its VEX statements still apply");
    }

    /** A database whose newest record is dated, as the samples' are not. */
    private Path dated() throws Exception {
        Path zip = dir.resolve("dated.zip");
        try (var out = new java.util.zip.ZipOutputStream(java.nio.file.Files.newOutputStream(zip))) {
            out.putNextEntry(new java.util.zip.ZipEntry("GHSA-aaaa.json"));
            out.write(("{\"id\":\"GHSA-aaaa\",\"modified\":\"2026-09-01T10:00:00Z\",\"affected\":[{\"package\":{\"ecosystem\":\"npm\","
                    + "\"name\":\"other\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]}]}").getBytes());
            out.closeEntry();
        }
        return zip;
    }

    @Test
    void theDatabasesWarningsAreThisComputers() throws Exception {
        var analysis = exported(options(null, 1, LocalDate.of(2030, 1, 1), false), List.of(GHSA, dated()));
        assertTrue(analysis.warnings().stream().anyMatch(w -> w.key().equals("warning.dbOld")));
        var again = Engine.recheck(analysis, List.of(GHSA), options(null, 0, TODAY, false), QUIET);
        assertTrue(again.warnings().stream().noneMatch(w -> w.key().equals("warning.dbOld")), again.warnings().toString());
    }
}
