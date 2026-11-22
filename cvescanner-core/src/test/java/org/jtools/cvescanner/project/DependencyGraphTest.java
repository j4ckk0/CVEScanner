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

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DependencyGraphTest {

    @Test
    void eachPackageGetsItsShortestPathACycleEndsAnUnreachedOneIsAbsent() {
        var paths = DependencyGraph.paths(List.of("a", "b"), Map.of(
                "a", List.of("c"),
                "c", List.of("d", "a"),     // back to a: a cycle, walked once
                "b", List.of("d"),          // d through b is shorter than through a > c
                "x", List.of("d")));        // x: no root reaches it
        assertEquals(List.of(), paths.get("a"));
        assertEquals(List.of("a"), paths.get("c"));
        assertEquals(List.of("b"), paths.get("d"));
        assertFalse(paths.containsKey("x"));
    }
}
