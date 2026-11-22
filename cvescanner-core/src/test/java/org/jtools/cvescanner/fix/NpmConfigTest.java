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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NpmConfigTest {

    @TempDir
    Path dir;
    Path home;
    Path node;   // <dir>/node/bin/node, npm beside it in <dir>/node/lib/node_modules/npm

    @BeforeEach
    void setUp() throws IOException {
        home = Files.createDirectories(dir.resolve("home"));
        node = Files.createDirectories(dir.resolve("node").resolve("bin")).resolve("node");
        Files.writeString(node, "");
    }

    private Optional<Path> cache(Map<String, String> env) {
        return NpmConfig.cache(env, home, Optional.of(node), false);
    }

    private static void write(Path file, String text) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, text);
    }

    @Test
    void noneNamedLeavesNpmsDefault() {
        assertEquals(Optional.empty(), cache(Map.of()));
        assertEquals(Optional.empty(), NpmConfig.cache(Map.of(), home, Optional.empty(), true));
    }

    @Test
    void theVariableWinsWhateverItsCase() throws IOException {
        write(home.resolve(".npmrc"), "cache=/from/user\n");
        assertEquals(Optional.of(Path.of("/from/env")), cache(Map.of("NPM_CONFIG_CACHE", "/from/env")));
    }

    @Test
    void theUsersNpmrcComesBeforeTheGlobalOne() throws IOException {
        write(home.resolve(".npmrc"), "; a comment\nregistry=https://example.org/\ncache = \"/from/user\"\n");
        write(dir.resolve("node").resolve("etc").resolve("npmrc"), "cache=/from/global\n");
        assertEquals(Optional.of(Path.of("/from/user")), cache(Map.of()));
    }

    @Test
    void theGlobalNpmrcIsUnderThePrefixTheVariableNames() throws IOException {
        // as on GitHub's Windows runner: npm_config_prefix set, the cache in <prefix>/etc/npmrc
        Path prefix = dir.resolve("npm").resolve("prefix");
        write(prefix.resolve("etc").resolve("npmrc"), "cache=" + dir.resolve("npm").resolve("cache") + "\n");
        assertEquals(Optional.of(dir.resolve("npm").resolve("cache")), cache(Map.of("npm_config_prefix", prefix.toString())));
    }

    @Test
    void withoutAPrefixTheGlobalNpmrcIsBesideNode() throws IOException {
        write(dir.resolve("node").resolve("etc").resolve("npmrc"), "cache=/from/global\n");
        assertEquals(Optional.of(Path.of("/from/global")), cache(Map.of()));
    }

    @Test
    void npmsOwnNpmrcComesLastAndMayMoveThePrefix() throws IOException {
        Path npmDir = dir.resolve("node").resolve("lib").resolve("node_modules").resolve("npm");
        write(npmDir.resolve("npmrc"), "cache=/from/builtin\n");
        assertEquals(Optional.of(Path.of("/from/builtin")), cache(Map.of()));
        write(npmDir.resolve("npmrc"), "prefix=${APPDATA}/npm\n");
        write(dir.resolve("roaming").resolve("npm").resolve("etc").resolve("npmrc"), "cache=/from/roaming\n");
        assertEquals(Optional.of(Path.of("/from/roaming")), cache(Map.of("APPDATA", dir.resolve("roaming").toString())));
    }

    @Test
    void aTildeIsTheHomeFolder() throws IOException {
        write(home.resolve(".npmrc"), "cache=~/.cache/npm\n");
        assertEquals(Optional.of(home.resolve(".cache/npm")), cache(Map.of()));
    }
}
