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

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StepTest {

    private static Step step(Step.TextEdit edit, String... command) {
        return new Step(edit, List.of(command), Path.of("."), Map.of(), List.of());
    }

    @Test
    void inShortTheProgramIsNamedWithoutItsFolderNorItsWindowsExtension() {
        assertEquals("npm install lodash@4.17.21 --offline", step(null, "/opt/node/bin/npm", "install", "lodash@4.17.21", "--offline").brief());
        assertEquals("yarn up lodash@4.17.21", step(null, "C:\\Program Files\\nodejs\\yarn.CMD", "up", "lodash@4.17.21").brief()
                .replace("C:\\Program Files\\nodejs\\", ""));
        assertEquals("/opt/node/bin/npm install", step(null, "/opt/node/bin/npm", "install").shown());
    }

    @Test
    void anEditComesFirstInShortAsInFull() {
        var edit = new Step.TextEdit(Path.of("gradle", "build.gradle"), "'g:a:1'", "'g:a:2'");
        assertEquals("build.gradle: 'g:a:1' → 'g:a:2'; gradle --offline", step(edit, "/opt/gradle/bin/gradle", "--offline").brief());
    }
}
