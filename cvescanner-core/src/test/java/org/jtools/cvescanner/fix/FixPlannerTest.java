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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** How a fix would be applied, or why not: the tool, the command, the edit, the Java and Node checks. Nothing is run. */
class FixPlannerTest {

    @TempDir
    Path dir;
    Path root;
    FakeMachine fake;

    @BeforeEach
    void setUp() throws IOException {
        root = Files.createDirectories(dir.resolve("project"));
        fake = new FakeMachine(dir);
    }

    private Path write(String path, String text) throws IOException {
        Path p = root.resolve(path);
        Files.createDirectories(p.getParent());
        Files.writeString(p, text);
        return p;
    }

    private FixPlan plan(Ecosystem eco, String pkg, String from, String to, Object... fileAndScope) {
        var declarations = new java.util.ArrayList<FixRequest.Declaration>();
        for (int i = 0; i < fileAndScope.length; i += 2)
            declarations.add(new FixRequest.Declaration(root.resolve((String) fileAndScope[i]), (String) fileAndScope[i + 1]));
        return new FixPlanner(root, fake.machine()).plan(new FixRequest(eco, pkg, from, to, declarations));
    }

    private static String reason(FixPlan p) {
        return p.notApplicable() == null ? null : p.notApplicable().key();
    }

    private void mavenParentAndChild(String javaRelease) throws IOException {
        write("pom.xml", """
                <project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
                  <properties><log4j.version>2.14.1</log4j.version>%s</properties>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency>
                  </dependencies></dependencyManagement>
                </project>""".formatted(javaRelease == null ? "" : "<maven.compiler.release>" + javaRelease + "</maven.compiler.release>"));
        write("child/pom.xml", """
                <project><modelVersion>4.0.0</modelVersion><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>
                  <artifactId>child</artifactId>
                  <dependencies>
                    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
                    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
                  </dependencies>
                </project>""");
    }

    @Test
    void aMavenVersionManagedInTheParentIsChangedThereOnceForTheChildToo() throws IOException {
        mavenParentAndChild(null);
        fake.program("mvn", "exit 0");
        fake.versionsPlugin();
        var p = plan(Ecosystem.MAVEN, "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "2.9.10.7",
                "pom.xml", "dependencyManagement", "child/pom.xml", "compile");
        assertTrue(p.applicable(), String.valueOf(p.notApplicable()));
        assertEquals(1, p.steps().size(), "one step for the parent, the child's use included");
        var cmd = p.steps().getFirst().command();
        assertEquals(List.of("-o", "-B", "-q", "-N", "-f", root.resolve("pom.xml").toString(), "versions:use-dep-version",
                "-Dincludes=com.fasterxml.jackson.core:jackson-databind", "-DdepVersion=2.9.10.7", "-DforceVersion=true",
                "-DprocessDependencyManagement=true", "-DgenerateBackupPoms=false"), cmd.subList(1, cmd.size()));
        assertEquals(List.of(root.resolve("pom.xml")), p.steps().getFirst().touched());
        assertEquals("fix.requirement.noJavaTarget", p.requirement().key());
        assertFalse(p.majorJump());
    }

    @Test
    void aMavenVersionFromAPropertyIsChangedWhereThePropertyIs() throws IOException {
        mavenParentAndChild(null);
        Path wrapper = write("mvnw", "#!/bin/sh\n");
        wrapper.toFile().setExecutable(true);
        fake.versionsPlugin();
        var p = plan(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "child/pom.xml", "compile");
        var cmd = p.steps().getFirst().command();
        assertEquals(wrapper.toString(), cmd.getFirst(), "the project's own wrapper first");
        assertTrue(cmd.containsAll(List.of("-f", root.resolve("pom.xml").toString(), "versions:set-property",
                "-Dproperty=log4j.version", "-DnewVersion=2.17.1")), cmd.toString());
    }

    @Test
    void noToolNoPluginNoFix() throws IOException {
        mavenParentAndChild(null);
        assertEquals("fix.reason.notInstalled", reason(plan(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1",
                "child/pom.xml", "compile")));
        fake.program("mvn", "exit 0");
        assertEquals("fix.reason.versionsPlugin", reason(plan(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1",
                "child/pom.xml", "compile")));
    }

    @Test
    void aFixNeedingANewerJavaThanTheProjectsIsNotApplied() throws IOException {
        mavenParentAndChild("8");
        fake.program("mvn", "exit 0");
        fake.versionsPlugin();
        String log4j = "org.apache.logging.log4j:log4j-core";
        assertEquals(Phrase.of("fix.reason.javaUnknown", "2.17.1"), plan(Ecosystem.MAVEN, log4j, "2.14.1", "2.17.1", "child/pom.xml", "compile").notApplicable(),
                "its jar not cached: not checked, so not applied");
        fake.jar("org.apache.logging.log4j", "log4j-core", "2.17.1", 11);
        assertEquals(Phrase.of("fix.reason.javaTooNew", "2.17.1", 11, 8), plan(Ecosystem.MAVEN, log4j, "2.14.1", "2.17.1", "child/pom.xml", "compile").notApplicable());
        fake.jar("org.apache.logging.log4j", "log4j-core", "2.12.4", 8);
        var p = plan(Ecosystem.MAVEN, log4j, "2.14.1", "2.12.4", "child/pom.xml", "compile");
        assertTrue(p.applicable());
        assertEquals(Phrase.of("fix.requirement.java", 8, 8), p.requirement());
    }

    @Test
    void gradleVersionsAreEditedWhereTheyAreWritten() throws IOException {
        write("settings.gradle", "");
        write("build.gradle", """
                ext { snakeVersion = '1.33' }
                java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }
                dependencies {
                    implementation "org.yaml:snakeyaml:${snakeVersion}"
                    implementation group: 'commons-io', name: 'commons-io', version: '2.6'
                    implementation 'com.google.guava:guava:31.1-jre'
                }""");
        write("gradle/libs.versions.toml", """
                [versions]
                text = "1.9"
                [libraries]
                commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }""");
        assertEquals("fix.reason.notInstalled", reason(plan(Ecosystem.MAVEN, "com.google.guava:guava", "31.1-jre", "32.0.0-jre", "build.gradle", "implementation")));
        fake.program("gradle", "exit 0");
        fake.jar("com.google.guava", "guava", "32.0.0-jre", 8);
        fake.jar("org.yaml", "snakeyaml", "2.0", 8);
        fake.jar("commons-io", "commons-io", "2.7", 8);
        fake.jar("org.apache.commons", "commons-text", "1.10.0", 8);
        var guava = plan(Ecosystem.MAVEN, "com.google.guava:guava", "31.1-jre", "32.0.0-jre", "build.gradle", "implementation");
        assertEquals(new Step.TextEdit(root.resolve("build.gradle"), "'com.google.guava:guava:31.1-jre'", "'com.google.guava:guava:32.0.0-jre'"),
                guava.steps().getFirst().edit());
        assertEquals(List.of("--offline", "-q", "-p", root.toString(), "dependencies"), guava.steps().getFirst().command().subList(1, 6));
        assertEquals(Phrase.of("fix.requirement.java", 8, 17), guava.requirement());
        assertEquals("snakeVersion = '2.0'", plan(Ecosystem.MAVEN, "org.yaml:snakeyaml", "1.33", "2.0", "build.gradle", "implementation")
                .steps().getFirst().edit().after());
        assertEquals("group: 'commons-io', name: 'commons-io', version: '2.7'", plan(Ecosystem.MAVEN, "commons-io:commons-io", "2.6", "2.7",
                "build.gradle", "implementation").steps().getFirst().edit().after());
        var text = plan(Ecosystem.MAVEN, "org.apache.commons:commons-text", "1.9", "1.10.0", "gradle/libs.versions.toml", "catalog:commons-text");
        assertEquals(new Step.TextEdit(root.resolve("gradle/libs.versions.toml"), "text = \"1.9\"", "text = \"1.10.0\""), text.steps().getFirst().edit());
        assertEquals(root, text.steps().getFirst().directory(), "the catalog's project, where settings.gradle is");
        assertEquals("fix.reason.versionNotFound", reason(plan(Ecosystem.MAVEN, "com.google.guava:guava", "30.0-jre", "32.0.0-jre", "build.gradle", "implementation")));
    }

    @Test
    void npmYarnAndPnpmEachByItsLockfileTheirScriptsNotRun() throws Exception {
        write("a/package.json", "{\"devDependencies\":{\"lodash\":\"^4.17.0\"}}");
        write("a/package-lock.json", "{}");
        write("b/package.json", "{\"dependencies\":{\"lodash\":\"^4.17.0\"}}");
        write("b/yarn.lock", "# yarn lockfile v1\n");
        write("c/package.json", "{\"dependencies\":{\"lodash\":\"^4.17.0\"}}");
        write("c/yarn.lock", "__metadata:\n  version: 6\n");
        write("d/package.json", "{\"devDependencies\":{\"lodash\":\"^4.17.0\"}}");
        write("d/pnpm-lock.yaml", "lockfileVersion: '6.0'\n");
        for (String tool : List.of("npm", "yarn", "pnpm")) fake.program(tool, "exit 0");
        var npm = plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "a/package-lock.json", "direct (dev)").steps().getFirst();
        assertEquals(List.of("install", "lodash@4.17.21", "--offline", "--ignore-scripts", "--save-dev"), npm.command().subList(1, 6));
        assertEquals(Map.of("npm_config_offline", "true"), npm.environment());
        assertEquals(List.of("add", "lodash@4.17.21", "--offline", "--ignore-scripts"),
                plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "b/yarn.lock", "direct").steps().getFirst().command().subList(1, 5));
        var berry = plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "c/yarn.lock", "direct").steps().getFirst();
        assertEquals(List.of("up", "lodash@4.17.21"), berry.command().subList(1, 3));
        assertEquals("0", berry.environment().get("YARN_ENABLE_SCRIPTS"));
        assertEquals(List.of("add", "lodash@4.17.21", "--offline", "--ignore-scripts", "-D"),
                plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "d/pnpm-lock.yaml", "direct").steps().getFirst().command().subList(1, 6));
        assertEquals("fix.reason.transitive", reason(plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "a/package-lock.json", "transitive (dev)")));
    }

    @Test
    void aFixNeedingANewerNodeThanTheProjectsIsNotApplied() throws Exception {
        write("package.json", "{\"engines\":{\"node\":\">=14\"},\"dependencies\":{\"axios\":\"0.21.0\"}}");
        fake.program("npm", "exit 0");
        assertEquals("fix.reason.nodeUnknown", reason(plan(Ecosystem.NPM, "axios", "0.21.0", "1.6.0", "package.json", "dependencies")));
        fake.npmPackage("axios", "{\"versions\":{\"1.6.0\":{\"engines\":{\"node\":\">=18\"}},\"0.21.2\":{\"engines\":{\"node\":\">=12\"}},\"0.21.4\":{}}}");
        assertEquals(Phrase.of("fix.reason.nodeTooNew", "1.6.0", ">=18", ">=14"),
                plan(Ecosystem.NPM, "axios", "0.21.0", "1.6.0", "package.json", "dependencies").notApplicable());
        assertEquals(Phrase.of("fix.requirement.node", ">=12", ">=14"), plan(Ecosystem.NPM, "axios", "0.21.0", "0.21.2", "package.json", "dependencies").requirement());
        assertEquals("fix.requirement.nodeAny", plan(Ecosystem.NPM, "axios", "0.21.0", "0.21.4", "package.json", "dependencies").requirement().key());
    }

    @Test
    void componentsOffTheShelfAndPackagesWithoutAFixAreNotApplied() {
        assertEquals("fix.reason.cots", reason(plan(Ecosystem.COTS, "osgeo:gdal", "3.4.1", "3.5.0", "cots.csv", "inventory")));
        assertEquals("fix.reason.noFix", reason(plan(Ecosystem.NPM, "x", "1.0.0", "", "package.json", "dependencies")));
    }

    @Test
    void aMajorVersionJumpIsSaid() {
        assertTrue(FixPlanner.majorJump(new FixRequest(Ecosystem.MAVEN, "g:a", "2.9.8", "3.0.0", List.of())));
        assertFalse(FixPlanner.majorJump(new FixRequest(Ecosystem.MAVEN, "g:a", "2.9.8", "2.12.7.1", List.of())));
        assertNull(plan(Ecosystem.COTS, "a:b", "1", "2", "x", "y").requirement());
    }
}
