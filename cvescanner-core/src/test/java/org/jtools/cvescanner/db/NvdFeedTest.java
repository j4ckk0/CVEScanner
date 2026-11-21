package org.jtools.cvescanner.db;

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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;
import org.junit.jupiter.api.Test;

/** NVD's records as CPE rules: their products, versions and ranges, the rejected ones left out, their ratings. */
class NvdFeedTest {

    private static final String RECORD = """
            {"cve":{"id":"CVE-2022-0001","vulnStatus":"Analyzed","published":"2022-03-01T10:00:00.000",
             "descriptions":[{"lang":"es","value":"Uno."},{"lang":"en","value":"A heap overflow in GDAL. More words."}],
             "metrics":{"cvssMetricV31":[{"cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H","baseScore":8.8,"baseSeverity":"HIGH"}}]},
             "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
               {"vulnerable":true,"criteria":"cpe:2.3:a:osgeo:gdal:*:*:*:*:*:*:*:*","versionStartIncluding":"3.0.0","versionEndExcluding":"3.4.2"},
               {"vulnerable":true,"criteria":"cpe:2.3:a:osgeo:gdal:2.4.4:*:*:*:*:*:*:*"},
               {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]}}
            """;

    private static List<NvdFeed.Rule> rules(String record) {
        return NvdFeed.rules(Json.obj(Json.obj(Json.parse(record)).get("cve")));
    }

    private static Dependency component(String name, String version) {
        return new Dependency("COTS", name, version, "cots.csv", "inventory", false);
    }

    @Test
    void eachVulnerableCpeIsARule() {
        var rules = rules(RECORD);
        assertEquals(2, rules.size(), "the not vulnerable platform is no rule");
        var range = rules.getFirst();
        assertEquals("osgeo", range.vendor());
        assertEquals("gdal", range.product());
        assertTrue(NvdFeed.affected("3.4.1", range));
        assertTrue(NvdFeed.affected("3.0.0", range));
        assertFalse(NvdFeed.affected("3.4.2", range));
        assertFalse(NvdFeed.affected("2.4.4", range));
        var exact = rules.get(1);
        assertTrue(NvdFeed.affected("2.4.4", exact));
        assertFalse(NvdFeed.affected("2.4.5", exact));
        assertEquals("A heap overflow in GDAL.", range.info().summary());
    }

    @Test
    void theVendorDecidesTheMatch() {
        var rule = rules(RECORD).getFirst();
        assertEquals(MatchBasis.CPE, NvdFeed.basis(component("osgeo:gdal", "3.4.1"), rule));
        assertEquals(MatchBasis.CPE_PRODUCT, NvdFeed.basis(component("gdal", "3.4.1"), rule));
        assertNull(NvdFeed.basis(component("someone:gdal", "3.4.1"), rule), "another vendor's product of that name");
    }

    @Test
    void theFindingHasItsScoreItsFixAndItsNvdPage() {
        var f = NvdFeed.toFinding(component("osgeo:gdal", "3.4.1"), rules(RECORD).getFirst(), MatchBasis.CPE);
        assertEquals(Severity.HIGH, f.severity());
        assertEquals(8.8, f.cvss());
        assertEquals("3.4.2", f.fixedIn());
        assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2022-0001", f.url());
        assertEquals(List.of("CVE-2022-0001"), f.cves());
    }

    @Test
    void aRejectedCveHasNoRule() {
        assertEquals(List.of(), rules(RECORD.replace("\"Analyzed\"", "\"Rejected\"")));
    }

    @Test
    void aFeedIsReadForTheProductsAskedOnly() throws Exception {
        String feed = "{\"resultsPerPage\":2,\"format\":\"NVD_CVE\",\"vulnerabilities\":[" + RECORD + ","
                + RECORD.replace("osgeo:gdal", "ffmpeg:ffmpeg").replace("CVE-2022-0001", "CVE-2022-0002") + "]}";
        var found = new ArrayList<NvdFeed.Rule>();
        Set<String> used = new HashSet<>();
        int read = NvdFeed.read(new StringReader(feed), Set.of("ffmpeg"), found::add, used, () -> { });
        assertEquals(2, read);
        assertEquals(Set.of("CVE-2022-0002"), used);
        assertTrue(found.stream().allMatch(r -> r.product().equals("ffmpeg")), found.toString());
    }

    @Test
    void cpeEscapesAreUndone() {
        String[] parts = NvdFeed.splitCpe("cpe:2.3:a:nodejs:node\\.js\\:x:1.0:*");
        assertEquals("node.js:x", NvdFeed.unescape(parts[4]));
        assertEquals("1.0", parts[5]);
    }
}
