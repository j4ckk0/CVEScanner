package org.jtools.cvescanner.project;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** npm's declared ranges read without a lockfile, a yarn alias, and Gradle's variables. */
class NpmAndGradleTest {

    @Test
    void aRangeGivesItsLowestVersion() {
        var caret = NpmScanner.minVersion("^4.17.0");
        assertEquals("4.17.0", caret.version());
        assertFalse(caret.exact());
        var exact = NpmScanner.minVersion("1.2.3");
        assertEquals("1.2.3", exact.version());
        assertTrue(exact.exact());
        assertEquals("1.0.0", NpmScanner.minVersion(">=1.0.0 <2.0.0").version());
    }

    @Test
    void whatHasNoLowestVersionSaysWhy() {
        assertEquals("reason.unpinned", NpmScanner.minVersion("*").reason().key());
        assertEquals("reason.nonRegistry", NpmScanner.minVersion("git+https://github.com/a/b.git").reason().key());
        assertEquals("reason.noLowerBound", NpmScanner.minVersion("<2.0.0").reason().key());
        assertNull(NpmScanner.minVersion("*").version());
    }

    @Test
    void aYarnAliasIsADeclaredDependency(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("package.json"), "{\"dependencies\":{\"lodash-legacy\":\"npm:lodash@4.17.11\",\"async\":\"^2.6.3\"}}");
        Files.writeString(dir.resolve("yarn.lock"), """
                # yarn lockfile v1

                async@^2.6.3:
                  version "2.6.3"
                  dependencies:
                    lodash "^4.17.14"

                lodash@^4.17.14:
                  version "4.17.15"

                "lodash-legacy@npm:lodash@4.17.11":
                  version "4.17.11"
                """);
        var collector = new Collector(dir);
        NpmScanner.scan(List.of(dir.resolve("package.json")), dir, collector, warning -> { });
        Map<String, String> scopes = new TreeMap<>();
        collector.deps.forEach(d -> scopes.put(d.name() + "@" + d.version(), d.scope()));
        assertEquals(Map.of("async@2.6.3", "direct", "lodash@4.17.11", "direct", "lodash@4.17.15", "transitive"), scopes);
    }

    @Test
    void gradleVariablesOfExtAndGradleProperties() {
        var vars = GradleScanner.variables(GradleScanner.stripComments("""
                ext { springVersion = '5.3.1' }   // on the line of ext {
                def guavaVersion = "31.1-jre"
                /* jacksonVersion = '0.0' */
                """));
        assertEquals("5.3.1", GradleScanner.resolve("$springVersion", vars));
        assertEquals("31.1-jre", GradleScanner.resolve("${guavaVersion}", vars));
        assertFalse(vars.containsKey("jacksonVersion"), "a comment holds no variable");
    }
}
