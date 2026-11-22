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

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Gradle's dependency lockfiles: gradle.lockfile beside a build file, or the older gradle/dependency-locks/*.lockfile.
 * Each line, group:artifact:version=configuration,…, is what Gradle resolved for those configurations.
 */
final class GradleLockReader {

    private static final Pattern LINE = Pattern.compile("([^:#\\s=]+):([^:#\\s=]+):([^:#\\s=]+)\\s*=\\s*(.*)");

    /** A locked dependency: its coordinates, its version, the configurations it was resolved for. */
    record Locked(String group, String artifact, String version, List<String> configurations) {
        String ga() { return group + ":" + artifact; }

        /** Only test configurations lock it: testCompileClasspath, testRuntimeClasspath… */
        boolean testOnly() {
            return !configurations.isEmpty() && configurations.stream().allMatch(c -> c.startsWith("test"));
        }
    }

    private GradleLockReader() {}

    static List<Locked> read(Path lockfile) throws IOException {
        var out = new ArrayList<Locked>();
        for (String line : ProjectFiles.readText(lockfile).split("\\R")) {
            var m = LINE.matcher(line.strip());
            if (!m.matches()) continue;   // a comment, "empty=…"
            var configurations = new ArrayList<String>();
            for (String c : m.group(4).split(",")) if (!c.isBlank()) configurations.add(c.strip());
            out.add(new Locked(m.group(1), m.group(2), m.group(3), List.copyOf(configurations)));
        }
        return out;
    }
}
