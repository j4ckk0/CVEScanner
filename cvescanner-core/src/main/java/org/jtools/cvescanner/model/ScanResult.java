package org.jtools.cvescanner.model;

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


import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;

/**
 * What a scan found: every finding, those its ignore file sets aside among them (Ignores.split sets them apart, once they
 * are scored), the dependencies, those that could not be checked, the databases read, the files counted, the warnings.
 *
 * @param mavenRepository the local Maven repository read for the poms' transitive dependencies; null when none was
 */
public record ScanResult(Path root, List<Finding> findings, List<Dependency> dependencies, List<Unresolved> unresolved,
                  Map<String, Phrase> snapshots, Map<String, Integer> fileCounts, List<Phrase> warnings, Ignores ignores,
                  ScanMode mode, Path mavenRepository) {

    public ScanResult(Path root, List<Finding> findings, List<Dependency> dependencies, List<Unresolved> unresolved,
                      Map<String, Phrase> snapshots, Map<String, Integer> fileCounts, List<Phrase> warnings, Ignores ignores,
                      ScanMode mode) {
        this(root, findings, dependencies, unresolved, snapshots, fileCounts, warnings, ignores, mode, null);
    }

    /** A moment as the reports and the databases' descriptions write it, the same wherever the program runs. */
    public static final DateTimeFormatter TIMESTAMP_UTC = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);
}
