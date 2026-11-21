package org.jtools.cvescanner.report;

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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.Scoring;
import org.junit.jupiter.api.Test;

/** bom.cdx.json: the dependencies by their package URLs, the findings with both their ratings, the ignored analysed. */
class CycloneDxTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();

    @Test
    void eachEcosystemsPackageUrl() {
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", CycloneDx.purl(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1"));
        assertEquals("pkg:npm/%40babel/core@7.0.0", CycloneDx.purl(Ecosystem.NPM, "@babel/core", "7.0.0"));
        assertEquals("pkg:npm/lodash@4.17.20", CycloneDx.purl(Ecosystem.NPM, "lodash", "4.17.20"));
        assertEquals("pkg:pypi/zope-interface@5.0%2Blocal", CycloneDx.purl(Ecosystem.PYPI, "Zope.Interface", "5.0+local"));
        assertEquals("pkg:generic/gdal@3.4.1", CycloneDx.purl(Ecosystem.COTS, "osgeo:gdal", "3.4.1"));
        assertNull(CycloneDx.purl(Ecosystem.MAVEN, "log4j-core", "2.14.1"), "a jar known by its name alone: no group, no purl");
        assertEquals("maven:log4j-core@2.14.1", CycloneDx.ref(Ecosystem.MAVEN, "log4j-core", "2.14.1"));
    }

    @Test
    void theFindingsAndTheIgnoredOnesTheSameScanTheSameSerialNumber() throws Exception {
        var r = Engine.scan(SAMPLES.resolve("projects"), List.of(SAMPLES.resolve("db/advisory-database-main.zip")),
                SAMPLES.resolve("ignore/cvescanner-ignore.csv"), new ScanListener() { public void status(String m) { } });
        var env = Environment.preset("internet");
        var split = r.ignores().split(Scoring.applyAll(r.findings(), env, true), LocalDate.of(2026, 11, 21));
        String text = CycloneDx.bom(r, split, env);
        var bom = Json.obj(Json.parse(text));
        assertEquals("CycloneDX", bom.get("bomFormat"));
        assertEquals("1.6", bom.get("specVersion"));

        var refs = Json.arr(bom.get("components")).stream().map(c -> Json.str(Json.obj(c), "bom-ref")).toList();
        assertTrue(refs.contains("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"), refs.toString());
        assertEquals(refs.size(), refs.stream().distinct().count(), "a package version once");

        var vulnerabilities = Json.arr(bom.get("vulnerabilities")).stream().map(Json::obj).toList();
        assertEquals(split.active().size() + split.ignored().size(), vulnerabilities.size());
        for (var v : vulnerabilities) {
            String ref = Json.str(Json.obj(Json.arr(v.get("affects")).getFirst()), "ref");
            assertTrue(refs.contains(ref), "affects a component listed: " + ref);
        }
        Map<String, Object> log4shell = vulnerabilities.stream().filter(v -> "GHSA-jfh8-c2jp-5v3q".equals(v.get("id"))).findFirst().orElseThrow();
        var analysis = Json.obj(log4shell.get("analysis"));
        assertEquals("not_affected", analysis.get("state"), "set aside by the ignore file");
        assertEquals("Not exposed: JNDI lookups disabled, see SEC-12", analysis.get("detail"));
        var ratings = Json.arr(log4shell.get("ratings")).stream().map(Json::obj).toList();
        assertEquals(2, ratings.size(), "base and environmental");
        assertEquals("CVSSv4", ratings.getFirst().get("method"));
        assertTrue(Json.str(ratings.get(1), "justification").contains("Internet"), ratings.get(1).toString());
        assertEquals("CVE-2021-44228", Json.str(Json.obj(Json.arr(log4shell.get("references")).getFirst()), "id"));

        String again = CycloneDx.bom(r, split, env);
        assertEquals(bom.get("serialNumber"), Json.obj(Json.parse(again)).get("serialNumber"), "made from the content, not the time");
    }
}
