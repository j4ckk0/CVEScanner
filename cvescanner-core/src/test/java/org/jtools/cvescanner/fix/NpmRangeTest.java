package org.jtools.cvescanner.fix;

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

import java.util.Optional;
import org.junit.jupiter.api.Test;

class NpmRangeTest {

    private static void within(String version, String range) {
        assertEquals(Optional.of(true), NpmRange.satisfies(version, range), version + " in " + range);
    }

    private static void outside(String version, String range) {
        assertEquals(Optional.of(false), NpmRange.satisfies(version, range), version + " not in " + range);
    }

    @Test
    void aCaretKeepsTheFirstNonZeroPart() {
        within("1.2.6", "^1.2.5");
        outside("2.0.0", "^1.2.5");
        outside("1.2.4", "^1.2.5");
        within("0.2.9", "^0.2.3");
        outside("0.3.0", "^0.2.3");
        outside("0.0.4", "^0.0.3");
        within("1.9.0", "^1.x");
    }

    @Test
    void aTildeKeepsTheMinor() {
        within("1.2.9", "~1.2.3");
        outside("1.3.0", "~1.2.3");
        within("1.9.0", "~1");
        outside("2.0.0", "~1");
    }

    @Test
    void xRangesComparatorsHyphensAndAlternatives() {
        within("1.5.0", "1.x");
        outside("2.0.0", "1.x");
        within("7.0.0", "*");
        within("1.9.9", ">=1.0.0 <2");
        outside("2.0.0", ">=1.0.0 <2");
        within("1.4.9", "1.2 - 1.4");
        outside("1.5.0", "1.2 - 1.4");
        within("1.4.0", "1.2.3 - 1.4.0");
        outside("1.4.1", "1.2.3 - 1.4.0");
        within("2.5.0", "^1.0.0 || ^2.0.0");
        outside("3.0.0", "^1.0.0 || ^2.0.0");
        outside("4.17.21", "4.17.20");
        within("4.17.21", "=4.17.21");
    }

    @Test
    void aPrereleaseIsWithinOnlyARangeNamingAPrereleaseOfTheSameVersion() {
        outside("1.2.4-beta", "^1.2.3");
        outside("1.2.3-beta", "1.2.3");
        outside("1.0.0-rc.1", "*");
        outside("2.0.0-rc.1", "^1.0.0");
        within("1.2.4-beta.2", "^1.2.4-beta.1");
        within("1.2.4-beta.10", ">1.2.4-beta.9");
        outside("1.2.4-alpha", "^1.2.4-beta");
        outside("1.2.5-beta", "^1.2.4-beta");
        within("1.2.5", "^1.2.4-beta");
        within("1.2.4-beta", "1.2.4-beta");
        within("2.0.0-rc.1", ">=2.0.0-rc.1 <2.0.0");
        within("1.0.0-rc.2", "1.0.0-rc.1 - 1.0.0");
        outside("1.0.0-rc.1", "^1.0.0-rc.2 || 1.x");
    }

    @Test
    void anAliasIsReadAfterItsNameAndAnythingElseSaysNothing() {
        within("1.2.6", "npm:minimist@^1.2.5");
        assertEquals(Optional.empty(), NpmRange.satisfies("1.2.6", "latest"));
        assertEquals(Optional.empty(), NpmRange.satisfies("1.2.6", "git+https://example.org/x.git"));
        assertEquals(Optional.empty(), NpmRange.satisfies("1.2.6", "file:../x"));
    }
}
