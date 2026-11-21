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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jtools.cvescanner.json.Json;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The scan of the samples gives what the prototype gave (the jar of the Claude-web session, SESSION_HANDOFF.md §8):
 * each case of golden/ holds the arguments it ran with (args.txt, the databases — and a folder to scan other than
 * samples/projects, -d — relative to samples/), its exit code
 * and its three reports. What differs from one run to the next is set aside: the time, the folder scanned, the
 * databases' file dates. The JSON is compared as values, the order of an object's keys aside.
 */
class GoldenTest {

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
            if ((given[i].equals("--db") || given[i].equals("-d")) && i + 1 < given.length) {
                args.add(SAMPLES.resolve(given[++i]).toString());
            }
        }

        int exit = Cli.run(Options.parse(args.toArray(String[]::new)));

        assertEquals(Integer.parseInt(Files.readString(golden.resolve("exit.txt")).trim()), exit, "exit code");
        assertEquals(read(golden, "findings.csv"), read(out, "findings.csv"), "findings.csv");
        assertEquals(markdown(read(golden, "report.md")), markdown(read(out, "report.md")), "report.md");
        assertEquals(json(read(golden, "findings.json")), json(read(out, "findings.json")), "findings.json");
    }

    private static String read(Path dir, String file) {
        try {
            return Files.readString(dir.resolve(file), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String undated(String text) {
        return text.replaceAll("file dated [0-9-]+ [0-9:]+ UTC", "file dated <date>");
    }

    private static String markdown(String report) {
        return undated(report)
                .replaceAll("(\\*\\*Generated:\\*\\* ).*", "$1<time>")
                .replaceAll("(\\*\\*Scanned directory:\\*\\* ).*", "$1<dir>");
    }

    private static Object json(String text) {
        Map<String, Object> root = new HashMap<>(Json.obj(Json.parse(text)));
        root.remove("generated");
        root.remove("scanned_directory");
        Map<String, Object> databases = new HashMap<>();
        Json.obj(root.get("databases")).forEach((file, desc) -> databases.put(file, undated((String) desc)));
        root.put("databases", databases);
        return root;
    }
}
