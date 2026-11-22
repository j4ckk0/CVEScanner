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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.fix.Machine;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.ScanListener;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The command line's filters and Apply fixes: the window's, by options. */
class CliOptionsTest {

    @TempDir
    Path dir;

    @Test
    void theFiltersAreParsedAsTheWindowSetsThem() {
        var o = Options.parse(new String[]{"--min-severity", "high", "--ecosystem", "npm,maven", "--ecosystem", "PyPI",
                "--hide-approximate", "--hide-name-matches", "--search", "lodash  CVE-2021", "--cve-only"});
        var f = o.filter();
        assertEquals(Severity.HIGH, f.minSeverity());
        assertEquals(Set.of(Ecosystem.NPM, Ecosystem.MAVEN, Ecosystem.PYPI), f.ecosystems());
        assertTrue(f.hideApproximate() && f.hideNameMatches() && f.cveOnly());
        assertEquals(List.of("lodash", "cve-2021"), f.searchWords());
        assertEquals(6, f.describe().size());
        assertFalse(Options.parse(new String[0]).filter().active());
    }

    @Test
    void wrongValuesAreSaid() {
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ecosystem", "nuget"}));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--min-severity", "unknown"}));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--yes"}), "--yes alone");
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--fix-packages", "lodash"}));
    }

    @Test
    void theMavenRepositoryIsTheHomeFoldersUnlessNamedOrTurnedOff() {
        assertEquals(Path.of("/repo"), Options.parse(new String[]{"--maven-repo", "/repo"}).scanOptions().mavenRepository());
        assertEquals(null, Options.parse(new String[]{"--no-transitive"}).scanOptions().mavenRepository());
        assertTrue(Options.parse(new String[0]).scanOptions().mavenRepository().endsWith(Path.of(".m2", "repository"))
                || Files.isRegularFile(Path.of(System.getProperty("user.home"), ".m2", "settings.xml")));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--maven-repo", "/repo", "--no-transitive"}));
    }

    @Test
    void applyFixesSaysEachPlanAndChangesNothingWithoutYes() throws Exception {
        Path samples = Path.of("..", "samples").toAbsolutePath().normalize();
        var r = Engine.scan(samples.resolve("projects"), List.of(samples.resolve("db/advisory-database-main.zip")),
                new ScanListener() { public void status(String m) { } });
        var o = Options.parse(new String[]{"--apply-fixes", "--fix-packages", "lodash,org.apache.logging.log4j:log4j-core"});
        var nothingInstalled = new Machine(List.of(Files.createDirectories(dir.resolve("bin"))), false, List.of(""), dir, null);
        var bytes = new ByteArrayOutputStream();
        var result = CliFixes.run(o, r.root(), r.findings(), new PrintStream(bytes, true, StandardCharsets.UTF_8), nothingInstalled);
        String out = bytes.toString(StandardCharsets.UTF_8);
        assertEquals(new CliFixes.Result(0, 0), result);
        assertTrue(out.contains("dry run"), out);
        assertTrue(out.contains("org.apache.logging.log4j:log4j-core  2.14.1 -> 2.15.0"), out);
        assertTrue(out.contains("lodash  4.17.15 -> 4.17.21") && out.contains("lodash  4.17.20 -> 4.17.21"), out);
        assertTrue(out.contains("mvn is not installed"), out);
        assertFalse(out.contains("minimist"), "only the packages named: " + out);
    }
}
