package org.jtools.cvescanner.cli;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.report.Reports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * --export-analysis on one computer, --from-analysis on another: as scanned, the same reports; re-checked against the
 * same database, the same findings; the options that need the folder itself refused.
 */
class CliAnalysisTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final String GHSA = SAMPLES.resolve("db/advisory-database-main.zip").toString();

    @TempDir
    Path dir;

    private static int run(String... args) {
        var o = Options.parse(args);
        o.today = LocalDate.of(2026, 11, 23);
        o.homeCaches = false;
        return Cli.run(o);
    }

    /** The samples scanned with their ignore file, the analysis written beside the reports. */
    private Path exported() throws Exception {
        Path file = dir.resolve("projects.cvescan");
        assertEquals(0, run("--no-gui", "-d", SAMPLES.resolve("projects").toString(), "--db", GHSA, "--db-max-age", "0",
                "--ignore", SAMPLES.resolve("ignore/cvescanner-ignore.csv").toString(), "-o", dir.resolve("scanned").toString(),
                "--export-analysis", file.toString()));
        assertTrue(Files.isRegularFile(file));
        return file;
    }

    private String read(String out, String file) throws Exception {
        return Files.readString(dir.resolve(out).resolve(file));
    }

    /** report.md without its time and the analysis's line: what differs between a scan and the same opened elsewhere. */
    private static List<String> markdown(String report) {
        var lines = new ArrayList<String>();
        for (String line : report.lines().toList())
            if (!line.startsWith("- **Generated:**") && !line.startsWith("- **Analysis:**")) lines.add(line);
        return lines;
    }

    private static Map<String, Object> bom(String text) {
        Map<String, Object> root = new HashMap<>(Json.obj(Json.parse(text)));
        Map<String, Object> metadata = new HashMap<>(Json.obj(root.get("metadata")));
        metadata.remove("timestamp");
        root.put("metadata", metadata);
        return root;
    }

    @Test
    void asScannedTheSameReports() throws Exception {
        Path file = exported();
        assertEquals(0, run("--no-gui", "--from-analysis", file.toString(), "--as-scanned", "-o", dir.resolve("opened").toString()));
        assertEquals(read("scanned", "findings.csv"), read("opened", "findings.csv"));
        assertEquals(read("scanned", Reports.DEPENDENCIES), read("opened", Reports.DEPENDENCIES));
        assertEquals(bom(read("scanned", Reports.SBOM)), bom(read("opened", Reports.SBOM)));
        assertEquals(markdown(read("scanned", "report.md")), markdown(read("opened", "report.md")));
        assertTrue(read("opened", "report.md").contains("- **Analysis:** opened from `projects.cvescan`"), read("opened", "report.md"));
        Map<String, Object> json = Json.obj(Json.parse(read("opened", "findings.json")));
        assertEquals(false, Json.obj(json.get("imported_analysis")).get("rechecked"));
    }

    @Test
    void reCheckedAgainstTheSameDatabaseTheSameFindings() throws Exception {
        Path file = exported();
        // as a DIR argument, an analysis file is re-checked too
        assertEquals(0, run("--no-gui", file.toString(), "--db", GHSA, "--db-max-age", "0", "-o", dir.resolve("rechecked").toString()));
        assertEquals(read("scanned", "findings.csv"), read("rechecked", "findings.csv"));
        assertTrue(read("rechecked", "report.md").contains("its dependencies checked again here"));
    }

    @Test
    void theAnalysisIsPassedOn() throws Exception {
        Path file = exported(), again = dir.resolve("again.cvescan");
        assertEquals(0, run("--no-gui", "--from-analysis", file.toString(), "--db", GHSA, "-o", dir.resolve("b").toString(),
                "--export-analysis", again.toString()));
        assertEquals(0, run("--no-gui", "--from-analysis", again.toString(), "--as-scanned", "-o", dir.resolve("c").toString()));
        assertEquals(read("scanned", "findings.csv"), read("c", "findings.csv"));
    }

    @Test
    void aFileThatIsNotThereIsAnError() {
        assertEquals(1, run("--no-gui", "--from-analysis", dir.resolve("missing.cvescan").toString(), "--as-scanned",
                "-o", dir.resolve("x").toString()));
    }

    @Test
    void whatNeedsTheFolderIsRefused() {
        String file = dir.resolve("a.cvescan").toString();
        for (String[] args : List.of(new String[]{"--from-analysis", file, "--apply-fixes"},
                new String[]{"--from-analysis", file, "--installed"},
                new String[]{"--from-analysis", file, "-d", dir.toString()},
                new String[]{"--from-analysis", file, "--ignore-list"},
                new String[]{"--as-scanned"},
                new String[]{"--from-analysis", file, "--as-scanned", "--no-ignore"}))
            assertThrows(IllegalArgumentException.class, () -> Options.parse(args), String.join(" ", args));
    }
}
