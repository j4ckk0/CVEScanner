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

import java.util.List;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.MatchBasis;
import org.junit.jupiter.api.Test;

/** A CVE JSON 5 record's rules: which dependency they name, and which versions they affect. */
class CveListTest {

    /** The rules of a record whose cna.affected is the JSON given, in the state given. */
    private static List<CveList.Rule> rules(String affected, String state) {
        return CveList.rules(Json.obj(Json.parse("""
                {"cveMetadata":{"cveId":"CVE-2026-0001","state":"%s"},
                 "containers":{"cna":{"descriptions":[{"lang":"en","value":"A flaw."}],"affected":%s}}}
                """.formatted(state, affected))));
    }

    private static CveList.Rule rule(String affectedEntry) {
        return rules("[" + affectedEntry + "]", "PUBLISHED").getFirst();
    }

    private static Dependency maven(String name, String version) {
        return new Dependency(Ecosystem.MAVEN, name, version, "pom.xml", "compile", false);
    }

    private static Dependency npm(String name, String version) {
        return new Dependency(Ecosystem.NPM, name, version, "package.json", "dependencies", false);
    }

    @Test
    void aRejectedRecordHasNoRule() {
        assertEquals(List.of(), rules("[{\"vendor\":\"x\",\"product\":\"y\"}]", "REJECTED"));
    }

    @Test
    void aPackageNameMatchesExactlyOrNotAtAll() {
        var r = rule("{\"packageName\":\"org.yaml:snakeyaml\",\"collectionURL\":\"https://repo.maven.apache.org/maven2\",\"product\":\"snakeyaml\"}");
        assertEquals(MatchBasis.CVE_PACKAGE, CveList.basis(maven("org.yaml:snakeyaml", "1.33"), r));
        assertNull(CveList.basis(maven("org.other:snakeyaml", "1.33"), r), "no fallback to the product name");
        var npmCollection = rule("{\"packageName\":\"org.yaml:snakeyaml\",\"collectionURL\":\"https://www.npmjs.com\"}");
        assertNull(CveList.basis(maven("org.yaml:snakeyaml", "1.33"), npmCollection), "another registry's package");
    }

    @Test
    void aMavenProductMatchesByNameWithItsVendorInTheGroup() {
        var r = rule("{\"vendor\":\"Apache Software Foundation\",\"product\":\"commons-text\"}");
        assertEquals(MatchBasis.CVE_NAME, CveList.basis(maven("org.apache.commons:commons-text", "1.9"), r));
        assertNull(CveList.basis(maven("com.example:commons-text", "1.9"), r), "the vendor is not in the group");
        var noise = rule("{\"vendor\":\"Software Foundation\",\"product\":\"commons-text\"}");
        assertNull(CveList.basis(maven("org.software.foundation:commons-text", "1.9"), noise), "noise words do not count");
        var placeholder = rule("{\"vendor\":\"n/a\",\"product\":\"jackson-databind\"}");
        assertNull(CveList.basis(maven("com.fasterxml.jackson.core:jackson-databind", "2.9.8"), placeholder));
    }

    @Test
    void anNpmProductMatchesByName() {
        assertEquals(MatchBasis.CVE_NAME, CveList.basis(npm("lodash", "4.17.15"), rule("{\"vendor\":\"lodash\",\"product\":\"lodash\"}")));
    }

    @Test
    void lessThanAndItsFix() {
        var r = rule("{\"product\":\"lodash\",\"versions\":[{\"version\":\"0\",\"lessThan\":\"4.17.21\",\"status\":\"affected\"}]}");
        assertTrue(CveList.affected(Ecosystem.NPM, "4.17.20", r));
        assertFalse(CveList.affected(Ecosystem.NPM, "4.17.21", r));
        assertEquals("4.17.21", CveList.fixedVersion(Ecosystem.NPM, "4.17.20", r));
    }

    @Test
    void constraintsInTheVersionField() {
        var r = rule("{\"product\":\"lodash\",\"versions\":[{\"version\":\">= 4.0.0, < 4.17.21\",\"status\":\"affected\"}]}");
        assertTrue(CveList.affected(Ecosystem.NPM, "4.17.15", r));
        assertFalse(CveList.affected(Ecosystem.NPM, "3.10.1", r));
        assertFalse(CveList.affected(Ecosystem.NPM, "4.17.21", r));
    }

    @Test
    void unaffectedWinsAndTheDefaultStatusCounts() {
        var r = rule("{\"product\":\"x\",\"defaultStatus\":\"affected\",\"versions\":["
                + "{\"version\":\"0\",\"lessThan\":\"3.0\",\"status\":\"affected\"},{\"version\":\"2.5.1\",\"status\":\"unaffected\"}]}");
        assertTrue(CveList.affected(Ecosystem.NPM, "2.5.0", r));
        assertFalse(CveList.affected(Ecosystem.NPM, "2.5.1", r), "an unaffected entry wins");
        assertTrue(CveList.affected(Ecosystem.NPM, "4.0.0", r), "nothing matched, an unaffected entry exists, defaultStatus affected");
    }

    @Test
    void aNonNumericUpperBoundCannotBeEvaluated() {
        // Log4Shell's record: lessThan "log4j-core*"
        var r = rule("{\"product\":\"Apache Log4j2\",\"versions\":[{\"version\":\"2.0-beta9\",\"lessThan\":\"log4j-core*\",\"status\":\"affected\"}]}");
        assertFalse(CveList.affected(Ecosystem.MAVEN, "2.14.1", r));
    }
}
