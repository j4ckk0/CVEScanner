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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.json.Json;
import org.junit.jupiter.api.Test;
import org.jtools.cvescanner.model.Ecosystem;

/** An OSV record's affected ranges (handoff §5.2): its events walked in version order, several intervals, fixes. */
class OsvTest {

    private static List<Object> events(String json) {
        return Json.arr(Json.parse(json));
    }

    private static Map<String, Object> affected(String json) {
        return Json.obj(Json.parse(json));
    }

    @Test
    void introducedThenFixed() {
        var e = events("[{\"introduced\":\"0\"},{\"fixed\":\"1.2.6\"}]");
        assertTrue(Osv.inRange(Ecosystem.NPM, "1.2.5", e));
        assertFalse(Osv.inRange(Ecosystem.NPM, "1.2.6", e));
        assertFalse(Osv.inRange(Ecosystem.NPM, "1.3.0", e));
    }

    @Test
    void severalIntervals() {
        var e = events("[{\"introduced\":\"1.0\"},{\"fixed\":\"1.5\"},{\"introduced\":\"2.0\"},{\"fixed\":\"2.3\"}]");
        assertTrue(Osv.inRange(Ecosystem.MAVEN, "1.2", e));
        assertFalse(Osv.inRange(Ecosystem.MAVEN, "1.7", e));
        assertTrue(Osv.inRange(Ecosystem.MAVEN, "2.1", e));
        assertFalse(Osv.inRange(Ecosystem.MAVEN, "0.9", e));
    }

    @Test
    void lastAffectedIsStillAffected() {
        var e = events("[{\"introduced\":\"0\"},{\"last_affected\":\"2.0\"}]");
        assertTrue(Osv.inRange(Ecosystem.MAVEN, "2.0", e));
        assertFalse(Osv.inRange(Ecosystem.MAVEN, "2.0.1", e));
    }

    @Test
    void eventsAreSortedBeforeTheWalk() {
        // an old advisory may list its fix before the introduction
        var e = events("[{\"fixed\":\"1.5\"},{\"introduced\":\"1.0\"}]");
        assertTrue(Osv.inRange(Ecosystem.MAVEN, "1.2", e));
        assertFalse(Osv.inRange(Ecosystem.MAVEN, "1.6", e));
    }

    @Test
    void listedVersionsAndGitRanges() {
        var a = affected("{\"versions\":[\"0.21.0\"],\"ranges\":[{\"type\":\"GIT\",\"events\":[{\"introduced\":\"0\"}]}]}");
        assertTrue(Osv.isAffected(Ecosystem.NPM, "0.21.0", a));
        assertFalse(Osv.isAffected(Ecosystem.NPM, "0.21.1", a), "a GIT range is ignored");
    }

    @Test
    void theNextFixIsTheSmallestAboveTheVersion() {
        var a = affected("{\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"1.0\"},{\"fixed\":\"1.5\"},"
                + "{\"introduced\":\"2.0\"},{\"fixed\":\"2.3\"}]}]}");
        assertEquals("1.5", Osv.nextFixed(Ecosystem.MAVEN, "1.2", a));
        assertEquals("2.3", Osv.nextFixed(Ecosystem.MAVEN, "2.1", a));
    }
}
