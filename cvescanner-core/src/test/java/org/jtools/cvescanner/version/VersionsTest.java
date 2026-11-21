package org.jtools.cvescanner.version;

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

import java.util.List;
import org.junit.jupiter.api.Test;

/** The order of versions, as Maven (ComparableVersion, approximated) and npm (SemVer 2.0) see it. */
class VersionsTest {

    private static void ascending(String ecosystem, String... versions) {
        for (int i = 0; i + 1 < versions.length; i++) {
            assertTrue(Versions.compare(ecosystem, versions[i], versions[i + 1]) < 0, versions[i] + " < " + versions[i + 1]);
            assertTrue(Versions.compare(ecosystem, versions[i + 1], versions[i]) > 0, versions[i + 1] + " > " + versions[i]);
        }
    }

    @Test
    void mavenTrailingZerosDoNotCount() {
        for (List<String> same : List.of(List.of("1", "1.0", "1.0.0"), List.of("32.0-jre", "32.0.0-jre"), List.of("1.0", "1.0-ga"),
                List.of("1.0-final", "1.0-release"), List.of("1.0-rc1", "1.0-cr1"))) {
            assertEquals(0, Versions.compareMaven(same.get(0), same.get(1)), same.toString());
        }
    }

    @Test
    void mavenQualifiersInTheirOrder() {
        ascending("Maven", "1.0-alpha1", "1.0-beta1", "1.0-milestone1", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1");
        ascending("Maven", "2.9.8", "2.9.10", "2.9.10.7", "2.10");
    }

    @Test
    void npmFollowsSemverPrecedence() {
        // the example of the SemVer 2.0 specification, section 11
        ascending("npm", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                "1.0.0-rc.1", "1.0.0");
        ascending("npm", "4.17.15", "4.17.20", "4.17.21");
        assertTrue(Versions.isSemver("1.2.3-rc.1+build.5"));
        // loose, as versions read from npm's ranges are: 1.2 is 1.2.0
        assertTrue(Versions.isSemver("1.2"));
        assertEquals(0, Versions.compare("npm", "1.2", "1.2.0"));
        assertFalse(Versions.isSemver("release-candidate"));
    }
}
