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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.report.Reports;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The scan of the samples gives the reports kept in golden/: the prototype's for the first cases, this project's
 * for the components off-the-shelf and the ignore file. Each case holds the arguments it ran with (args.txt, the
 * databases — and a folder to scan other than samples/projects, -d — relative to samples/), its exit code and its
 * three reports. What differs from one run to the next is set aside: the time, the folder scanned, the databases'
 * file dates. The JSON is compared as values, the order of an object's keys aside.
 */
class GoldenTest {

    /** The day the golden reports were made: the databases' ages are counted from it. */
    private static final LocalDate TODAY = LocalDate.of(2026, 11, 21);

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();

    @TempDir
    Path out;

    static Stream<String> cases() throws IOException, URISyntaxException {
        Path golden = Path.of(GoldenTest.class.getResource("golden").toURI());
        try (Stream<Path> dirs = Files.list(golden)) {
            return dirs.map(dir -> dir.getFileName().toString()).sorted().toList().stream();
        }
    }

    @ParameterizedTest
    @MethodSource("cases")
    void theSamplesGiveWhatThePrototypeGave(String name) throws Exception {
        Path golden = Path.of(GoldenTest.class.getResource("golden/" + name).toURI());
        List<String> args = new ArrayList<>(List.of("--no-gui", "-d", SAMPLES.resolve("projects").toString(),
                "-o", out.toString()));
        String[] given = Files.readString(golden.resolve("args.txt")).trim().split("\\s+");
        for (int i = 0; i < given.length; i++) {
            args.add(given[i]);
            if (List.of("--db", "-d", "--ignore", "--vex", "--maven-repo", "--gradle-cache").contains(given[i]) && i + 1 < given.length) {
                args.add(SAMPLES.resolve(given[++i]).toString());
            }
        }

        var options = Options.parse(args.toArray(String[]::new));
        options.today = TODAY;
        options.homeCaches = false;   // the machine's own ~/.m2 and ~/.gradle never read: a case names the samples', or none
        int exit = Cli.run(options);

        assertEquals(Integer.parseInt(Files.readString(golden.resolve("exit.txt")).trim()), exit, "exit code");
        assertEquals(read(golden, "findings.csv"), read(out, "findings.csv"), "findings.csv");
        assertEquals(markdown(read(golden, "report.md")), markdown(read(out, "report.md")), "report.md");
        assertEquals(json(read(golden, "findings.json")), json(read(out, "findings.json")), "findings.json");
        if (Files.exists(golden.resolve(Reports.DEPENDENCIES)))
            assertEquals(read(golden, Reports.DEPENDENCIES), read(out, Reports.DEPENDENCIES), Reports.DEPENDENCIES);
        if (Files.exists(golden.resolve(Reports.SBOM)))
            assertEquals(bom(read(golden, Reports.SBOM)), bom(read(out, Reports.SBOM)), Reports.SBOM);
    }

    private static String read(Path dir, String file) {
        try {
            return Files.readString(dir.resolve(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Without what differs between runs: the databases' file dates, where the samples are (an ignore file's path). */
    private static String undated(String text) {
        return text.replaceAll("file dated [0-9-]+ [0-9:]+ UTC", "file dated <date>")
                .replace(SAMPLES.toString().replace('\\', '/'), "<samples>");
    }

    private static String markdown(String report) {
        return undated(report)
                .replaceAll("(\\*\\*Generated:\\*\\* ).*", "$1<time>")
                .replaceAll("(\\*\\*Scanned directory:\\*\\* ).*", "$1<dir>");
    }

    /** The SBOM without what differs between runs: its time, and the program's version (none when run from the classes). */
    private static Object bom(String text) {
        Map<String, Object> root = new HashMap<>(Json.obj(Json.parse(text)));
        Map<String, Object> metadata = new HashMap<>(Json.obj(root.get("metadata")));
        metadata.remove("timestamp");
        metadata.remove("tools");
        root.put("metadata", metadata);
        return root;
    }

    private static Object json(String text) {
        Map<String, Object> root = new HashMap<>(Json.obj(Json.parse(undated(text))));
        root.remove("generated");
        root.remove("scanned_directory");
        Map<String, Object> databases = new HashMap<>();
        Json.obj(root.get("databases")).forEach((file, desc) -> databases.put(file, undated((String) desc)));
        root.put("databases", databases);
        if (root.get("ignore_file") instanceof String file) root.put("ignore_file", undated(file));
        return root;
    }
}
