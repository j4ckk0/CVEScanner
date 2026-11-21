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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jtools.cvescanner.project.Collector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** What an SBOM names: Maven and npm packages by their purl, components off-the-shelf by their CPE or their name. */
class SbomReaderTest {

    @TempDir
    Path dir;

    private Set<String> read(String fileName, String json, List<String> warnings) throws Exception {
        Path file = dir.resolve(fileName);
        Files.writeString(file, json);
        var col = new Collector(dir);
        SbomReader.scan(List.of(file), col, w -> warnings.add(w.text()));
        var found = new TreeSet<String>();
        col.deps.forEach(d -> found.add(d.ecosystem() + " " + d.name() + " " + d.version() + " " + d.scope()));
        col.unresolved.forEach(u -> found.add(u.ecosystem() + " " + u.name() + " unchecked"));
        return found;
    }

    @Test
    void purlsAreParsed() {
        assertEquals(new SbomReader.Purl("npm", "@angular", "core", "16.0.0"),
                SbomReader.Purl.parse("pkg:npm/%40angular/core@16.0.0?foo=bar#sub"));
        assertEquals(new SbomReader.Purl("maven", "org.yaml", "snakeyaml", "1.33"),
                SbomReader.Purl.parse("pkg:maven/org.yaml/snakeyaml@1.33"));
        assertEquals(new SbomReader.Purl("npm", "", "lodash", ""), SbomReader.Purl.parse("pkg:npm/lodash"));
        assertEquals("a%zz", SbomReader.Purl.parse("pkg:npm/a%zz@1").name(), "a malformed escape stays as written");
    }

    @Test
    void cycloneDxComponentsAndTheirs() throws Exception {
        var warnings = new ArrayList<String>();
        var found = read("bom.json", """
                {"bomFormat":"CycloneDX","metadata":{"component":{"name":"the-app","version":"1"}},
                 "components":[
                  {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
                  {"name":"core","purl":"pkg:npm/%40scope/core@1.0.0"},
                  {"name":"libpng","cpe":"cpe:2.3:a:libpng:libpng:1.6.37:*:*:*:*:*:*:*",
                   "components":[{"name":"zlib","version":"1.2.11"}]},
                  {"name":"<b>x</b>"}]}
                """, warnings);
        assertEquals(new TreeSet<>(Set.of(
                "Maven org.apache.logging.log4j:log4j-core 2.14.1 sbom", "npm @scope/core 1.0.0 sbom",
                "COTS libpng:libpng 1.6.37 sbom", "COTS zlib:zlib 1.2.11 sbom", "COTS <b>x</b> unchecked")), found);
        assertEquals(List.of(), warnings);
    }

    @Test
    void spdxPackagesAndTheirReferences() throws Exception {
        var found = read("app.spdx.json", """
                {"spdxVersion":"SPDX-2.3","packages":[
                  {"name":"FFmpeg","versionInfo":"4.4.2","externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:ffmpeg:ffmpeg:4.4.2:*:*:*:*:*:*:*"}]},
                  {"name":"lodash","versionInfo":"4.17.15","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.15"}]},
                  {"name":"something","versionInfo":"NOASSERTION"}]}
                """, new ArrayList<>());
        assertEquals(new TreeSet<>(Set.of("COTS ffmpeg:ffmpeg 4.4.2 sbom", "npm lodash 4.17.15 sbom", "COTS something unchecked")), found);
    }

    @Test
    void aBrokenSbomIsSkippedAndSaidSo() throws Exception {
        var warnings = new ArrayList<String>();
        assertEquals(Set.of(), read("bom.json", "{\"components\":[{\"name\":", warnings));
        assertEquals(1, warnings.size());
        assertTrue(warnings.getFirst().startsWith("skipped bom.json"), warnings.toString());
    }
}
