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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A pom.xml of a scanned repository is read and nothing else: no DTD, no external entity, whatever it names (README,
 * "No network"). The entities point to a file here, which is how a parser left as it is would show it reads
 * outside the POM; the network is never tried.
 */
class PomParserTest {

    @TempDir
    Path dir;

    private List<String> scan(String pom) throws Exception {
        Files.writeString(dir.resolve("secret.txt"), "4.2.0");
        Path file = dir.resolve("pom.xml");
        Files.writeString(file, pom.replace("SECRET", dir.resolve("secret.txt").toUri().toString()));
        List<String> warnings = new ArrayList<>();
        Collector collector = new Collector(dir);
        MavenScanner.scan(List.of(file), collector, warnings::add);
        assertTrue(collector.deps.stream().noneMatch(d -> d.version().contains("4.2.0")),
                "a version read from outside the POM: " + collector.deps);
        return warnings;
    }

    @Test
    void aDoctypeIsRefused() throws Exception {
        List<String> warnings = scan("""
                <?xml version="1.0"?>
                <!DOCTYPE project [ <!ENTITY v SYSTEM "SECRET"> ]>
                <project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
                  <dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>&v;</version></dependency></dependencies>
                </project>
                """);
        assertEquals(1, warnings.size(), warnings.toString());
        assertTrue(warnings.getFirst().contains("skipped pom.xml"), warnings.toString());
    }

    @Test
    void anExternalDtdIsRefused() throws Exception {
        List<String> warnings = scan("""
                <?xml version="1.0"?>
                <!DOCTYPE project SYSTEM "SECRET">
                <project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>
                """);
        assertEquals(1, warnings.size(), warnings.toString());
    }

    @Test
    void anXIncludeIsNotFollowed() throws Exception {
        List<String> warnings = scan("""
                <?xml version="1.0"?>
                <project xmlns:xi="http://www.w3.org/2001/XInclude"><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
                  <dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId>
                    <version><xi:include href="SECRET" parse="text"/></version></dependency></dependencies>
                </project>
                """);
        assertFalse(warnings.stream().anyMatch(w -> w.contains("4.2.0")), warnings.toString());
    }
}
