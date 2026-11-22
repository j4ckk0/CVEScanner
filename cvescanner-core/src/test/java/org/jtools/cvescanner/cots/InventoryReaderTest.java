package org.jtools.cvescanner.cots;

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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jtools.cvescanner.project.DependencyCollector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A cots.csv: a component a line, named by a CPE, a vendor and a name, or a name alone. */
class InventoryReaderTest {

    @TempDir
    Path dir;

    private Set<String> read(String text) throws Exception {
        Path file = Files.writeString(dir.resolve("cots.csv"), text);
        var col = new DependencyCollector(dir);
        InventoryReader.scan(List.of(file), col, w -> { throw new AssertionError(w.text()); });
        var found = new TreeSet<String>();
        col.deps.forEach(d -> found.add(d.name() + " " + d.version()));
        col.unresolved.forEach(u -> found.add(u.name() + (u.declared().isEmpty() ? "" : " " + u.declared()) + " unchecked: " + u.reason().key()));
        return found;
    }

    @Test
    void aCpeAVendorOrAKnownNameNamesTheComponent() throws Exception {
        assertEquals(Set.of("osgeo:gdal 3.4.1", "acme:libfoo 1.2", "x:y 2.0"),
                read("name,version,vendor,cpe\n# a comment\ngdal,3.4.1\nlibfoo,1.2,acme\n,,,cpe:2.3:a:x:y:2.0:*:*:*:*:*:*:*\n"));
        assertEquals(Set.of("osgeo:gdal unchecked: reason.noVersion"), read("gdal,\n"));
    }

    @Test
    void aCpeWithoutAVendorOrAProductIsSaidNotChecked() throws Exception {
        assertEquals(Set.of("cpe:2.3:a:acme::1.0 unchecked: reason.cpeNoProduct", "lib 1.0 unchecked: reason.cpeNoProduct",
                        "cpe:2.3:a:*:y unchecked: reason.cpeNoProduct"),
                read(",,,cpe:2.3:a:acme::1.0\nlib,1.0,,cpe:2.3:a:acme\n,,,cpe:2.3:a:*:y\n"));
    }
}
