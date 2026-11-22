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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.TreeSet;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** A direct-only scan keeps what the projects declare, each at the version its lockfile gives, and nothing they bring. */
class DirectOnlyTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final ScanListener QUIET = new ScanListener() { public void status(String m) { } };

    private static ScanResult scan(String project, String db, boolean directOnly) throws Exception {
        return Engine.scan(SAMPLES.resolve(project), List.of(SAMPLES.resolve(db)), new ScanOptions(null, ScanMode.SOURCES, 0,
                LocalDate.of(2026, 11, 21), List.of(), null, null, null, directOnly), QUIET);
    }

    private static TreeSet<String> rows(List<Dependency> deps) {
        var out = new TreeSet<String>();
        for (Dependency d : deps) out.add(d.file() + " " + d.name() + " " + d.version() + " " + d.scope());
        return out;
    }

    @ParameterizedTest
    @ValueSource(strings = {"projects", "projects-gradle-lock", "python-projects"})
    void theDeclaredOnesAtTheirLockedVersions(String project) throws Exception {
        String db = project.startsWith("python") ? "db/pypi.zip" : "db/advisory-database-main.zip";
        var full = scan(project, db, false);
        var direct = scan(project, db, true);
        assertTrue(full.dependencies().stream().anyMatch(Dependency::transitive), "the sample has indirect packages");
        assertEquals(rows(full.dependencies().stream().filter(d -> !d.transitive()).toList()), rows(direct.dependencies()));
        assertTrue(direct.directOnly());
        assertFalse(direct.gradleLocked(), "no lockfile note: the report says direct only");
        assertTrue(direct.findings().stream().noneMatch(f -> Dependency.isTransitive(f.scope())));
    }
}
