package org.jtools.cvescanner.ignore;

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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A VEX document's statements: their packages from purls or bom-refs; those saying it does not apply set findings aside. */
class VexFileTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();
    private static final LocalDate TODAY = LocalDate.of(2026, 11, 21);

    @TempDir
    Path dir;

    @Test
    void aPackageUrlIsThePackageAsCveScannerNamesIt() {
        assertArrayEquals(new String[]{"org.apache.logging.log4j:log4j-core", "2.14.1"},
                VexFile.fromPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"));
        assertArrayEquals(new String[]{"@babel/core", "7.0.0"}, VexFile.fromPurl("pkg:npm/%40babel/core@7.0.0"));
        assertArrayEquals(new String[]{"lodash", ""}, VexFile.fromPurl("pkg:npm/lodash"), "no version: any");
        assertArrayEquals(new String[]{"zope.interface", "5.0+local"}, VexFile.fromPurl("pkg:pypi/zope.interface@5.0%2Blocal"));
        assertArrayEquals(new String[]{"gdal", "3.4.1"}, VexFile.fromPurl("pkg:generic/gdal@3.4.1#src"));
        assertNull(VexFile.fromPurl("cpe:2.3:a:osgeo:gdal"));
        assertEquals("é😀%zz", VexFile.decode("%C3%A9😀%zz"), "UTF-8, a broken escape kept");
    }

    @Test
    void theSamplesStatementsByPurlAndByBomRefAndTheOneTiedToNothingSaid() throws IOException {
        var warnings = new ArrayList<Phrase>();
        var statements = VexFile.read(SAMPLES.resolve("vex/product.vex.json"), "product.vex.json", warnings::add);
        assertEquals(List.of("GHSA-35jh-r3h4-6jhm lodash 4.17.15 not_affected", "CVE-2022-42889 org.apache.commons:commons-text 1.9 false_positive",
                "CVE-2021-44228 org.apache.logging.log4j:log4j-core 2.14.1 in_triage", "CVE-2023-2976 com.google.guava:guava 31.1-jre resolved"),
                statements.stream().map(v -> v.id() + " " + v.pkg() + " " + v.version() + " " + v.state()).toList());
        assertEquals(List.of(true, true, false, false), statements.stream().map(VexStatement::setsAside).toList(),
                "resolved sets nothing aside: the scan still finds the version");
        assertEquals("not_affected (code_not_reachable): template() is never called", statements.getFirst().said());
        assertEquals(List.of("vex.warning.unknownRef"), warnings.stream().map(Phrase::key).toList());
    }

    @Test
    void aDocumentThatIsNotCycloneDxIsSaidAndReadAsNone() throws IOException {
        var warnings = new ArrayList<Phrase>();
        Files.writeString(dir.resolve("a.vex.json"), "{\"document\": {\"category\": \"csaf_vex\"}}");
        Files.writeString(dir.resolve("b.vex.json"), "not json");
        assertTrue(VexFile.read(dir.resolve("a.vex.json"), "a", warnings::add).isEmpty());
        assertTrue(VexFile.read(dir.resolve("b.vex.json"), "b", warnings::add).isEmpty());
        assertEquals(List.of("vex.warning.notCycloneDx", "vex.warning.notJson"), warnings.stream().map(Phrase::key).toList());
    }

    @Test
    void theFoldersOwnVexIsReadNeverAsAnSbomAndANamedOneMustBeThere() throws IOException {
        Path project = Files.createDirectories(dir.resolve("p"));
        Files.writeString(project.resolve("package.json"), "{\"dependencies\":{\"lodash\":\"4.17.15\"}}");
        Files.copy(SAMPLES.resolve("vex/product.vex.json"), project.resolve("product.vex.json"));
        var listener = new ScanListener() { public void status(String m) { } };
        var r = Engine.scan(project, List.of(SAMPLES.resolve("db/advisory-database-main.zip")),
                new ScanOptions(null, ScanMode.SOURCES, 0, TODAY), listener);
        assertTrue(r.dependencies().stream().allMatch(d -> d.ecosystem() == Ecosystem.NPM), "its components are no dependencies");
        assertEquals(List.of("product.vex.json"), r.ignores().vexSources());
        var split = r.ignores().split(r.findings(), TODAY);
        assertEquals(List.of("GHSA-35jh-r3h4-6jhm"), split.ignored().stream().map(i -> i.finding().id()).toList());
        assertTrue(split.ignored().getFirst().rule().fromVex());
        assertTrue(split.unused().isEmpty(), "a VEX document's statements on what the scan did not find are no warning");
        assertThrows(IOException.class, () -> Engine.scan(project, List.of(SAMPLES.resolve("db/advisory-database-main.zip")),
                new ScanOptions(null, ScanMode.SOURCES, 0, TODAY, List.of(dir.resolve("missing.vex.json"))), listener));
    }
}
