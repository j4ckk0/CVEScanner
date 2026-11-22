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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** npm's declared ranges read without a lockfile, a yarn alias, and Gradle's variables. */
class NpmAndGradleTest {

    @Test
    void aRangeGivesItsLowestVersion() {
        var caret = NpmReader.minVersion("^4.17.0");
        assertEquals("4.17.0", caret.version());
        assertFalse(caret.exact());
        var exact = NpmReader.minVersion("1.2.3");
        assertEquals("1.2.3", exact.version());
        assertTrue(exact.exact());
        assertEquals("1.0.0", NpmReader.minVersion(">=1.0.0 <2.0.0").version());
    }

    @Test
    void whatHasNoLowestVersionSaysWhy() {
        assertEquals("reason.unpinned", NpmReader.minVersion("*").reason().key());
        assertEquals("reason.nonRegistry", NpmReader.minVersion("git+https://github.com/a/b.git").reason().key());
        assertEquals("reason.noLowerBound", NpmReader.minVersion("<2.0.0").reason().key());
        assertNull(NpmReader.minVersion("*").version());
    }

    @Test
    void aYarnAliasIsADeclaredDependency(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("package.json"), "{\"dependencies\":{\"lodash-legacy\":\"npm:lodash@4.17.11\",\"async\":\"^2.6.3\"}}");
        Files.writeString(dir.resolve("yarn.lock"), """
                # yarn lockfile v1

                async@^2.6.3:
                  version "2.6.3"
                  dependencies:
                    lodash "^4.17.14"

                lodash@^4.17.14:
                  version "4.17.15"

                "lodash-legacy@npm:lodash@4.17.11":
                  version "4.17.11"
                """);
        var collector = new DependencyCollector(dir);
        NpmReader.scan(List.of(dir.resolve("package.json")), dir, collector, warning -> { });
        Map<String, String> scopes = new TreeMap<>();
        collector.deps.forEach(d -> scopes.put(d.name() + "@" + d.version(), d.scope()));
        assertEquals(Map.of("async@2.6.3", "direct", "lodash@4.17.11", "direct", "lodash@4.17.15", "transitive"), scopes);
    }

    /** Each package's parents, "name@version > …", by "name@version"; "?" when the lockfile does not say. */
    private static Map<String, String> parents(Path dir, String packageJson, String lockName, String lock) throws Exception {
        Files.writeString(dir.resolve("package.json"), packageJson);
        Files.writeString(dir.resolve(lockName), lock);
        var collector = new DependencyCollector(dir);
        NpmReader.scan(List.of(dir.resolve("package.json")), dir, collector, warning -> { });
        Map<String, String> out = new TreeMap<>();
        collector.deps.forEach(d -> out.put(d.name() + "@" + d.version(),
                d.scope() + " " + (d.parents() == null ? "?" : String.join(" > ", d.parents()))));
        return out;
    }

    @Test
    void aPackageLocksParentsAsNodeFindsThemTheNearestCopyKept(@TempDir Path dir) throws Exception {
        var found = parents(dir, "{\"dependencies\":{\"express\":\"4.17.1\",\"debug\":\"4.3.1\"}}", "package-lock.json", """
                {"lockfileVersion": 3, "packages": {
                  "": {"dependencies": {"express": "4.17.1", "debug": "4.3.1"}},
                  "node_modules/express": {"version": "4.17.1", "dependencies": {"body-parser": "1", "debug": "2.6.9"}},
                  "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"debug": "2.6.9"}},
                  "node_modules/body-parser/node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
                  "node_modules/body-parser/node_modules/ms": {"version": "2.0.0"},
                  "node_modules/express/node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
                  "node_modules/express/node_modules/ms": {"version": "2.0.0"},
                  "node_modules/debug": {"version": "4.3.1", "dependencies": {"ms": "2.1.2"}},
                  "node_modules/ms": {"version": "2.1.2"}
                }}""");
        assertEquals(Map.of(
                "express@4.17.1", "direct ", "debug@4.3.1", "direct ",
                "body-parser@1.19.0", "transitive express@4.17.1",
                "debug@2.6.9", "transitive express@4.17.1",
                "ms@2.0.0", "transitive express@4.17.1 > debug@2.6.9",
                "ms@2.1.2", "transitive debug@4.3.1"), found);
    }

    @Test
    void yarnLocksParentsV1AndBerryAnotherVersionOfADeclaredNameIsNotDirect(@TempDir Path dir) throws Exception {
        String pkg = "{\"dependencies\":{\"express\":\"^4.17.1\",\"debug\":\"^4.3.1\"}}";
        var v1 = parents(dir, pkg, "yarn.lock", """
                # yarn lockfile v1

                debug@2.6.9:
                  version "2.6.9"
                  dependencies:
                    ms "2.0.0"

                debug@^4.3.1:
                  version "4.3.1"

                express@^4.17.1:
                  version "4.17.1"
                  dependencies:
                    debug "2.6.9"

                ms@2.0.0:
                  version "2.0.0"
                """);
        var expected = Map.of("express@4.17.1", "direct ", "debug@4.3.1", "direct ",
                "debug@2.6.9", "transitive express@4.17.1", "ms@2.0.0", "transitive express@4.17.1 > debug@2.6.9");
        assertEquals(expected, v1);
        var berry = parents(dir, pkg, "yarn.lock", """
                __metadata:
                  version: 8

                "app@workspace:.":
                  version: 0.0.0-use.local
                  dependencies:
                    debug: "npm:^4.3.1"
                    express: "npm:^4.17.1"

                "debug@npm:2.6.9":
                  version: 2.6.9
                  dependencies:
                    ms: "npm:2.0.0"

                "debug@npm:^4.3.1":
                  version: 4.3.1

                "express@npm:^4.17.1":
                  version: 4.17.1
                  dependencies:
                    debug: "npm:2.6.9"

                "ms@npm:2.0.0":
                  version: 2.0.0
                """);
        assertEquals(expected, berry, "the project's own entry is no package");
    }

    @Test
    void pnpmLocksParentsV9AndV6ThePeersSuffixCut(@TempDir Path dir) throws Exception {
        String pkg = "{\"dependencies\":{\"react-dom\":\"18.2.0\",\"react\":\"18.2.0\"}}";
        var expected = Map.of("react-dom@18.2.0", "direct ", "react@18.2.0", "direct ",
                "scheduler@0.23.0", "transitive react-dom@18.2.0", "loose-envify@1.4.0", "transitive react@18.2.0");
        assertEquals(expected, parents(dir, pkg, "pnpm-lock.yaml", """
                lockfileVersion: '9.0'

                importers:

                  .:
                    dependencies:
                      react:
                        specifier: 18.2.0
                        version: 18.2.0
                      react-dom:
                        specifier: 18.2.0
                        version: 18.2.0(react@18.2.0)

                packages:

                  loose-envify@1.4.0:
                    resolution: {integrity: sha512-x}
                  react-dom@18.2.0:
                    resolution: {integrity: sha512-x}
                  react@18.2.0:
                    resolution: {integrity: sha512-x}
                  scheduler@0.23.0:
                    resolution: {integrity: sha512-x}

                snapshots:

                  loose-envify@1.4.0: {}
                  react-dom@18.2.0(react@18.2.0):
                    dependencies:
                      loose-envify: 1.4.0
                      react: 18.2.0
                      scheduler: 0.23.0
                  react@18.2.0:
                    dependencies:
                      loose-envify: 1.4.0
                  scheduler@0.23.0:
                    dependencies:
                      loose-envify: 1.4.0
                """));
        assertEquals(expected, parents(dir, pkg, "pnpm-lock.yaml", """
                lockfileVersion: '6.0'

                dependencies:
                  react:
                    specifier: 18.2.0
                    version: 18.2.0
                  react-dom:
                    specifier: 18.2.0
                    version: 18.2.0(react@18.2.0)

                packages:

                  /loose-envify@1.4.0:
                    resolution: {integrity: sha512-x}
                  /react-dom@18.2.0(react@18.2.0):
                    dependencies:
                      loose-envify: 1.4.0
                      react: 18.2.0
                      scheduler: 0.23.0
                  /react@18.2.0:
                    dependencies:
                      loose-envify: 1.4.0
                  /scheduler@0.23.0:
                    dependencies:
                      loose-envify: 1.4.0
                """));
    }

    /** A workspace: the root's package.json and a member's, one lockfile; each package's scope and parents. */
    private static Map<String, String> workspace(Path parent, String lockName, String lock) throws Exception {
        Path dir = Files.createDirectories(parent.resolve(lockName + ".d"));   // a folder each: one lockfile in it
        Files.writeString(dir.resolve("package.json"), "{\"workspaces\":[\"packages/*\"],\"devDependencies\":{\"minimist\":\"1.2.5\"}}");
        Files.createDirectories(dir.resolve("packages/a"));
        Files.writeString(dir.resolve("packages/a/package.json"), "{\"name\":\"a\",\"dependencies\":{\"express\":\"4.17.1\"}}");
        Files.writeString(dir.resolve(lockName), lock);
        var collector = new DependencyCollector(dir);
        NpmReader.scan(List.of(dir.resolve("package.json"), dir.resolve("packages/a/package.json")), dir, collector, warning -> { });
        Map<String, String> out = new TreeMap<>();
        collector.deps.forEach(d -> out.put(d.name() + "@" + d.version(),
                d.scope() + " " + (d.parents() == null ? "?" : String.join(" > ", d.parents()))));
        return out;
    }

    @Test
    void whatAWorkspaceDeclaresIsDirectItsOwnDependenciesUnderIt(@TempDir Path dir) throws Exception {
        var expected = Map.of("minimist@1.2.5", "direct ", "express@4.17.1", "direct ", "debug@2.6.9", "transitive express@4.17.1");
        assertEquals(Map.of("minimist@1.2.5", "direct (dev) ", "express@4.17.1", "direct ", "debug@2.6.9", "transitive express@4.17.1"),
                workspace(dir, "package-lock.json", """
                {"lockfileVersion": 3, "packages": {
                  "": {"workspaces": ["packages/*"], "devDependencies": {"minimist": "1.2.5"}},
                  "node_modules/a": {"resolved": "packages/a", "link": true},
                  "packages/a": {"version": "1.0.0", "dependencies": {"express": "4.17.1"}},
                  "node_modules/express": {"version": "4.17.1", "dependencies": {"debug": "2.6.9"}},
                  "node_modules/debug": {"version": "2.6.9"},
                  "node_modules/minimist": {"version": "1.2.5", "dev": true}
                }}"""));
        assertEquals(expected, workspace(dir, "pnpm-lock.yaml", """
                lockfileVersion: '9.0'

                importers:

                  .:
                    devDependencies:
                      minimist:
                        specifier: 1.2.5
                        version: 1.2.5

                  packages/a:
                    dependencies:
                      express:
                        specifier: 4.17.1
                        version: 4.17.1

                packages:

                  debug@2.6.9:
                    resolution: {integrity: sha512-x}
                  express@4.17.1:
                    resolution: {integrity: sha512-x}
                  minimist@1.2.5:
                    resolution: {integrity: sha512-x}

                snapshots:

                  debug@2.6.9: {}
                  express@4.17.1:
                    dependencies:
                      debug: 2.6.9
                  minimist@1.2.5: {}
                """), "pnpm's lock read without its dev marks");
    }

    @Test
    void aDeclarationResolvingToNoEntryIsDirectByItsName(@TempDir Path dir) throws Exception {
        // yarn's resolutions: the entry is keyed by the resolution's spec, not by what package.json says
        var found = parents(dir, "{\"dependencies\":{\"lodash\":\"^4.17.0\"},\"resolutions\":{\"lodash\":\"4.17.21\"}}", "yarn.lock", """
                # yarn lockfile v1

                lodash@4.17.21:
                  version "4.17.21"
                """);
        assertEquals(Map.of("lodash@4.17.21", "direct "), found);
    }

    @Test
    void aV1PackageLockDoesNotSayTheParents(@TempDir Path dir) throws Exception {
        var found = parents(dir, "{\"dependencies\":{\"a\":\"1.0.0\"}}", "package-lock.json", """
                {"lockfileVersion": 1, "dependencies": {
                  "a": {"version": "1.0.0", "requires": {"b": "1.0.0"}},
                  "b": {"version": "1.0.0"}}}""");
        assertEquals(Map.of("a@1.0.0", "direct ", "b@1.0.0", "transitive ?"), found);
    }

    @Test
    void gradleVariablesOfExtAndGradleProperties() {
        var vars = GradleReader.variables(GradleReader.stripComments("""
                ext { springVersion = '5.3.1' }   // on the line of ext {
                def guavaVersion = "31.1-jre"
                /* jacksonVersion = '0.0' */
                """));
        assertEquals("5.3.1", GradleReader.resolve("$springVersion", vars));
        assertEquals("31.1-jre", GradleReader.resolve("${guavaVersion}", vars));
        assertFalse(vars.containsKey("jacksonVersion"), "a comment holds no variable");
    }
}
