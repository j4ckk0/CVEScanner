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
import org.jtools.cvescanner.model.Ecosystem;

/** The order of versions, as Maven (ComparableVersion, approximated), npm (SemVer 2.0) and Python (PEP 440) see it. */
class VersionsTest {

    private static void ascending(Ecosystem ecosystem, String... versions) {
        for (int i = 0; i + 1 < versions.length; i++) {
            assertTrue(ecosystem.compare(versions[i], versions[i + 1]) < 0, versions[i] + " < " + versions[i + 1]);
            assertTrue(ecosystem.compare(versions[i + 1], versions[i]) > 0, versions[i + 1] + " > " + versions[i]);
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
        ascending(Ecosystem.MAVEN, "1.0-alpha1", "1.0-beta1", "1.0-milestone1", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1");
        ascending(Ecosystem.MAVEN, "2.9.8", "2.9.10", "2.9.10.7", "2.10");
    }

    @Test
    void theFixIsOfTheVersionsFlavour() {
        // Guava's advisories give a fix per flavour; Maven's order puts -android before -jre
        var fixes = List.of("32.0.0-android", "32.0.0-jre");
        assertEquals("32.0.0-jre", Ecosystem.MAVEN.nearestFix("31.1-jre", fixes));
        assertEquals("32.0.0-android", Ecosystem.MAVEN.nearestFix("31.1-android", fixes));
        assertEquals("32.0.0-android", Ecosystem.MAVEN.nearestFix("31.1", fixes), "no flavour: the lowest");
        assertEquals("32.0.0-jre", Ecosystem.MAVEN.nearestFix("31.1-jre", List.of("32.0.0-android")),
                "a fix given in another flavour only is said in the version's");
        assertEquals("2.0.0", Ecosystem.MAVEN.nearestFix("1.0-rc1", List.of("2.0.0")), "a pre-release is no flavour");
        assertEquals("4.1.71.Final", Ecosystem.MAVEN.nearestFix("4.1.68.Final", List.of("4.1.71.Final", "4.1.44.Final")));
        assertEquals("", Ecosystem.NPM.nearestFix("2.0.0", List.of("1.5.0")));
    }

    @Test
    void aPreReleaseWordIsNoFlavour() {
        // -beta, -rc, -snapshot are Maven qualifiers: a fix is never made up in them, nor from them
        assertEquals("2.0-rc", Ecosystem.MAVEN.nearestFix("2.0-beta", List.of("2.0-rc", "2.1")));
        assertEquals("32.0.0-rc", Ecosystem.MAVEN.nearestFix("31.1-jre", List.of("32.0.0-rc")));
        assertEquals("1.1", Ecosystem.MAVEN.nearestFix("1.0-snapshot", List.of("1.1", "1.2-snapshot")));
        assertEquals("1.1", Ecosystem.MAVEN.nearestFix("1.0-beta1", List.of("1.1", "2.0-beta1")), "a numbered one too");
        assertEquals("1.1", Ecosystem.MAVEN.nearestFix("1.0-rc.2", List.of("1.1", "2.0-rc.2")));
    }

    @Test
    void pythonFollowsPep440() {
        ascending(Ecosystem.PYPI, "1.0.dev1", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1.1", "2!0.5");
        assertEquals(0, Ecosystem.PYPI.compare("1.0", "1.0.0"));
        assertEquals(0, Ecosystem.PYPI.compare("1.0RC1", "1.0rc1"));
        assertEquals(0, Ecosystem.PYPI.compare("2.25.0+local.7", "2.25.0"), "a local label does not order");
        assertEquals("requests-oauthlib", Ecosystem.pep503("Requests_OAuthlib"));
    }

    @Test
    void npmFollowsSemverPrecedence() {
        // the example of the SemVer 2.0 specification, section 11
        ascending(Ecosystem.NPM, "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                "1.0.0-rc.1", "1.0.0");
        ascending(Ecosystem.NPM, "4.17.15", "4.17.20", "4.17.21");
        assertTrue(Versions.isSemver("1.2.3-rc.1+build.5"));
        // loose, as versions read from npm's ranges are: 1.2 is 1.2.0
        assertTrue(Versions.isSemver("1.2"));
        assertEquals(0, Ecosystem.NPM.compare("1.2", "1.2.0"));
        assertFalse(Versions.isSemver("release-candidate"));
    }
}
