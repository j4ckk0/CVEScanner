package org.jtools.cvescanner;

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
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The databases' list: each zip once, however named; what stays unticked at start. */
class DatabaseChoiceTest {

    private static final Path FOLDER = Path.of("/opt/cvescanner/database");

    @Test
    void eachZipListedOnceHoweverNamed() {
        Path ghsa = Path.of("/data/cve/advisory-database-main.zip");
        var listed = DatabaseChoice.union(List.of(FOLDER.resolve("nvd.zip"), ghsa),
                List.of(Path.of("/data/cve/../cve/advisory-database-main.zip"), Path.of("/data/osv/all.zip")));
        assertEquals(List.of(FOLDER.resolve("nvd.zip"), ghsa, Path.of("/data/osv/all.zip")), listed);
    }

    @Test
    void aZipTheCommandLineNamesStartsTickedTheFoldersStayAsLeft() {
        Path inFolder = FOLDER.resolve("nvd.zip"), named = Path.of("/data/cve/advisory-database-main.zip"),
                added = Path.of("/data/osv/all.zip");
        var unticked = DatabaseChoice.untickedAtStart(List.of(inFolder, named, added), List.of(inFolder, named), FOLDER);
        assertEquals(Set.of(DatabaseChoice.key(inFolder), DatabaseChoice.key(added)), unticked);
    }
}
