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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** What a pnpm lockfile says of a package for its override: its versions locked, its dependents, whichever pnpm wrote it. */
class NpmDependentsTest {

    /** pnpm 5.x: a key and a need with their peers after an underscore, the version alone counting. */
    @Test
    void pnpm5PeersSuffixCut(@TempDir Path dir) throws Exception {
        Path lock = Files.writeString(dir.resolve("pnpm-lock.yaml"), """
                lockfileVersion: 5.4

                specifiers:
                  app-kit: 1.0.0

                dependencies:
                  app-kit: 1.0.0_react@18.2.0

                packages:

                  /app-kit/1.0.0_react@18.2.0:
                    resolution: {integrity: sha512-x}
                    peerDependencies:
                      react: ^18.2.0
                    dependencies:
                      ui-lib: 2.0.0_react@18.2.0
                    dev: false

                  /ui-lib/2.0.0_react@18.2.0:
                    resolution: {integrity: sha512-x}
                    dev: false

                  /ui-lib/3.0.0:
                    resolution: {integrity: sha512-x}
                    dev: false
                """);
        var unknown = NpmDependents.of(lock, "ui-lib", "2.0.0");
        assertEquals(Set.of("2.0.0", "3.0.0"), unknown.locked());
        assertFalse(unknown.rangesKnown(), "app-kit depends on it, its package.json not installed");

        Path installed = Files.createDirectories(dir.resolve("node_modules/.pnpm/app-kit@1.0.0_react@18.2.0/node_modules/app-kit"));
        Files.writeString(installed.resolve("package.json"),
                "{\"dependencies\":{\"ui-lib\":\"^2.0.0\"}}");
        var known = NpmDependents.of(lock, "ui-lib", "2.0.0");
        assertTrue(known.rangesKnown());
        assertEquals(List.of(new NpmDependents.Asked("app-kit@1.0.0", "^2.0.0")), known.asked(), "read in its folder, peers named");
    }

    @Test
    void theStoreFolderNamesThePeersAsPnpmDoes() {
        assertEquals("react-dom@18.2.0", NpmDependents.storeFolder("react-dom", "18.2.0", ""));
        assertEquals("react-dom@18.2.0_react@18.2.0", NpmDependents.storeFolder("react-dom", "18.2.0", "_react@18.2.0"));
        assertEquals("x@1.0.0_react@18.2.0_@types+react@18.0.0",
                NpmDependents.storeFolder("x", "1.0.0", "(react@18.2.0)(@types/react@18.0.0)"));
        assertEquals("@scope+x@1.0.0", NpmDependents.storeFolder("@scope/x", "1.0.0", ""));
    }
}
