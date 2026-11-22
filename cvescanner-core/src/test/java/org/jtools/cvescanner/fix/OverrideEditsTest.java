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
import org.jtools.cvescanner.json.Json;
import org.junit.jupiter.api.Test;

class OverrideEditsTest {

    private static final Path PACKAGE_JSON = Path.of("package.json");

    private static String put(String text, List<String> path, String key, String value) {
        return new PackageJsonMembers(PACKAGE_JSON, path, Map.of(key, value)).apply(text);
    }

    @Test
    void anOverridesObjectIsMadeLastAsTheFileIsIndented() {
        String text = "{\n  \"name\": \"t\",\n  \"dependencies\": {\n    \"mkdirp\": \"0.5.5\"\n  }\n}\n";
        assertEquals("{\n  \"name\": \"t\",\n  \"dependencies\": {\n    \"mkdirp\": \"0.5.5\"\n  },\n"
                + "  \"overrides\": { \"minimist@1.2.5\": \"1.2.6\" }\n}\n", put(text, List.of("overrides"), "minimist@1.2.5", "1.2.6"));
    }

    @Test
    void anExistingObjectGetsTheMemberOnALineOfItsOwn() {
        String text = "{\n\t\"name\": \"t\",\n\t\"overrides\": {\n\t\t\"a\": \"1\"\n\t}\n}";
        assertEquals("{\n\t\"name\": \"t\",\n\t\"overrides\": {\n\t\t\"a\": \"1\",\n\t\t\"minimist@1.2.5\": \"1.2.6\"\n\t}\n}",
                put(text, List.of("overrides"), "minimist@1.2.5", "1.2.6"));
    }

    @Test
    void anInlineFileStaysInline() {
        String text = "{ \"name\": \"t\", \"dependencies\": { \"lodash\": \"4.17.20\" } }\n";
        assertEquals("{ \"name\": \"t\", \"dependencies\": { \"lodash\": \"4.17.20\" }, \"resolutions\": { \"minimist\": \"1.2.6\" } }\n",
                put(text, List.of("resolutions"), "minimist", "1.2.6"));
    }

    @Test
    void aMemberThereTakesTheNewValueAndANestedPathIsMade() {
        String text = "{\n  \"overrides\": {\n    \"minimist@1.2.5\": \"1.2.5\"\n  }\n}\n";
        assertEquals("{\n  \"overrides\": {\n    \"minimist@1.2.5\": \"1.2.6\"\n  }\n}\n", put(text, List.of("overrides"), "minimist@1.2.5", "1.2.6"));
        String pnpm = put("{\n  \"pnpm\": {\n    \"onlyBuiltDependencies\": []\n  }\n}\n", List.of("pnpm", "overrides"), "m@1", "2");
        assertEquals(Map.of("onlyBuiltDependencies", List.of(), "overrides", Map.of("m@1", "2")), Json.obj(Json.parse(pnpm)).get("pnpm"));
        String none = put("{ \"name\": \"t\" }", List.of("pnpm", "overrides"), "m@1", "2");
        assertEquals(Map.of("overrides", Map.of("m@1", "2")), Json.obj(Json.parse(none)).get("pnpm"));
    }

    @Test
    void windowsLineEndsAreKeptAndQuotesEscaped() {
        String text = "{\r\n  \"name\": \"t\"\r\n}\r\n";
        assertEquals("{\r\n  \"name\": \"t\",\r\n  \"resolutions\": { \"a\\\"b\": \"1\" }\r\n}\r\n", put(text, List.of("resolutions"), "a\"b", "1"));
        assertEquals(null, put("[]", List.of("overrides"), "a", "1"), "not an object: not edited");
    }

    @Test
    void pnpmsWorkspaceFileGetsItsOverride() {
        var edit = new PnpmWorkspaceOverride(Path.of("pnpm-workspace.yaml"), "minimist@1.2.5", "1.2.6", null);
        assertEquals("overrides:\n  'minimist@1.2.5': 1.2.6\n", edit.apply(""));
        assertEquals("packages:\n  - 'a'\noverrides:\n  'minimist@1.2.5': 1.2.6\n", edit.apply("packages:\n  - 'a'\n"));
        assertEquals("overrides:\n    'minimist@1.2.5': 1.2.6\n    lodash: 4.17.21\nx: 1\n", edit.apply("overrides:\n    lodash: 4.17.21\nx: 1\n"));
        assertEquals("overrides:\n  'minimist@1.2.5': 1.2.6\nx: 1\n", edit.apply("overrides: {}\nx: 1\n"));
        assertEquals("pnpm-workspace.yaml: overrides 'minimist@1.2.5': 1.2.6", edit.shown());
    }
    private static final PomManagedEntry PIN = new PomManagedEntry(Path.of("pom.xml"), "org.yaml", "snakeyaml", "2.0");

    @Test
    void aPinIsAddedToThePomsOwnDependencyManagement() {
        String pom = """
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>g</groupId>
                        <artifactId>a</artifactId>
                        <version>1</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;
        assertEquals("""
                <project>
                  <modelVersion>4.0.0</modelVersion>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>g</groupId>
                        <artifactId>a</artifactId>
                        <version>1</version>
                      </dependency>
                      <dependency>
                        <groupId>org.yaml</groupId>
                        <artifactId>snakeyaml</artifactId>
                        <version>2.0</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """, PIN.apply(pom));
        assertEquals(PIN.apply(pom), PIN.apply(PIN.apply(pom)), "managed already: left alone");
    }

    @Test
    void theManagementIsMadeBeforeTheDependenciesAProfilesAndACommentsNotCounting() {
        String pom = """
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <!-- <dependencyManagement><dependencies></dependencies></dependencyManagement> -->
                    <profiles><profile><dependencyManagement><dependencies></dependencies></dependencyManagement></profile></profiles>
                    <dependencies>
                        <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>
                    </dependencies>
                </project>
                """;
        assertEquals("""
                <project>
                    <modelVersion>4.0.0</modelVersion>
                    <!-- <dependencyManagement><dependencies></dependencies></dependencyManagement> -->
                    <profiles><profile><dependencyManagement><dependencies></dependencies></dependencyManagement></profile></profiles>
                    <dependencyManagement>
                        <dependencies>
                            <dependency>
                                <groupId>org.yaml</groupId>
                                <artifactId>snakeyaml</artifactId>
                                <version>2.0</version>
                            </dependency>
                        </dependencies>
                    </dependencyManagement>
                    <dependencies>
                        <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>
                    </dependencies>
                </project>
                """, PIN.apply(pom));
    }

    @Test
    void aBarePomGetsItLastAndItsLineEndsKept() {
        String pom = "<project>\r\n\t<modelVersion>4.0.0</modelVersion>\r\n</project>\r\n";
        assertEquals("<project>\r\n\t<modelVersion>4.0.0</modelVersion>\r\n\t<dependencyManagement>\r\n\t\t<dependencies>\r\n"
                + "\t\t\t<dependency>\r\n\t\t\t\t<groupId>org.yaml</groupId>\r\n\t\t\t\t<artifactId>snakeyaml</artifactId>\r\n"
                + "\t\t\t\t<version>2.0</version>\r\n\t\t\t</dependency>\r\n\t\t</dependencies>\r\n\t</dependencyManagement>\r\n"
                + "</project>\r\n", PIN.apply(pom));
        assertEquals(null, PIN.apply("not a pom"));
        assertEquals("pom.xml: dependencyManagement org.yaml:snakeyaml 2.0", PIN.shown());
    }
}
