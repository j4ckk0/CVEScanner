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
        fake.jar("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.7", 8);
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
    void aTransitiveMavenDependencyFollowsTheDeclaredPomOfItsChainElseIsPinned() throws IOException {
        mavenParentAndChild(null);
        fake.program("mvn", "exit 0");
        fake.versionsPlugin();
        fake.jar("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.7", 8);
        // managed in the parent, transitive in the child: the parent's entry governs it, upgraded, said so
        var governed = plan(Ecosystem.MAVEN, "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "2.9.10.7",
                "pom.xml", "dependencyManagement", "child/pom.xml", "transitive via g:x");
        assertTrue(governed.applicable(), String.valueOf(governed.notApplicable()));
        assertEquals(1, governed.steps().size());
        assertFalse(governed.majorJump());
        assertEquals(List.of("fix.note.transitiveFollow"), governed.notes().stream().map(Phrase::key).toList());

        // transitive only: pinned in the topmost pom's dependencyManagement, Maven reading the pom offline; asked first
        assertEquals("fix.reason.notCachedMaven", reason(plan(Ecosystem.MAVEN, "org.yaml:snakeyaml", "1.33", "2.0",
                "child/pom.xml", "transitive via g:x")));
        fake.jar("org.yaml", "snakeyaml", "2.0", 8);
        var pinned = plan(Ecosystem.MAVEN, "org.yaml:snakeyaml", "1.33", "2.0", "child/pom.xml", "transitive via g:x");
        assertTrue(pinned.applicable(), String.valueOf(pinned.notApplicable()));
        var step = pinned.steps().getFirst();
        assertEquals(new PomManagedEntry(root.resolve("pom.xml"), "org.yaml", "snakeyaml", "2.0"), step.edit());
        assertEquals(List.of("-o", "-B", "-q", "-N", "validate", "-f", root.resolve("pom.xml").toString()), step.command().subList(1, 8));
        assertTrue(pinned.majorJump(), "a pin asks first");
        assertEquals(List.of(Phrase.of("fix.note.pinnedMaven", "pom.xml", "1.33")), pinned.notes());

        // a Gradle build declares it, a Maven module has it transitively: both fixed, the Gradle edit and the Maven pin
        write("build.gradle", "dependencies {\n    implementation 'org.yaml:snakeyaml:1.33'\n}\n");
        fake.program("gradle", "exit 0");
        var both = plan(Ecosystem.MAVEN, "org.yaml:snakeyaml", "1.33", "2.0", "build.gradle", "implementation", "child/pom.xml", "transitive via g:x");
        assertEquals(2, both.steps().size(), String.valueOf(both.notApplicable()));
        assertTrue(both.steps().get(0).edit() instanceof Step.TextEdit);
        assertTrue(both.steps().get(1).edit() instanceof PomManagedEntry);

        // transitive in Gradle builds only: nothing written by hand to edit
        assertEquals("fix.reason.transitiveGradle", reason(plan(Ecosystem.MAVEN, "org.yaml:snakeyaml", "1.33", "2.0",
                "build.gradle", "transitive via g:x")));
    }

    @Test
    void aMavenVersionFromAPropertyIsChangedWhereThePropertyIs() throws IOException {
        mavenParentAndChild(null);
        write("mvnw", "#!/bin/sh\n").toFile().setExecutable(true);
        fake.versionsPlugin();
        fake.jar("org.apache.logging.log4j", "log4j-core", "2.17.1", 8);
        assertEquals("fix.reason.notInstalled", reason(plan(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1",
                "child/pom.xml", "compile")), "a wrapper is not used: it would download its Maven");
        Path mvn = fake.program("mvn", "exit 0");
        var p = plan(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core", "2.14.1", "2.17.1", "child/pom.xml", "compile");
        var cmd = p.steps().getFirst().command();
        assertEquals(mvn.toString(), cmd.getFirst());
        assertTrue(cmd.containsAll(List.of("-f", root.resolve("pom.xml").toString(), "versions:set-property",
                "-Dproperty=log4j.version", "-DnewVersion=2.17.1")), cmd.toString());
    }

    @Test
    void packagesSharingAPropertyAreAllRaisedToTheHighestFix() throws IOException {
        write("pom.xml", """
                <project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version>
                  <properties><spring.version>5.3.17</spring.version></properties>
                  <dependencies>
                    <dependency><groupId>org.springframework</groupId><artifactId>spring-webmvc</artifactId><version>${spring.version}</version></dependency>
                    <dependency><groupId>org.springframework</groupId><artifactId>spring-beans</artifactId><version>${spring.version}</version></dependency>
                  </dependencies>
                </project>""");
        fake.program("mvn", "exit 0");
        fake.versionsPlugin();
        fake.jar("org.springframework", "spring-webmvc", "5.3.42", 8);
        fake.jar("org.springframework", "spring-beans", "5.3.42", 8);
        var declared = List.of(new FixRequest.Declaration(root.resolve("pom.xml"), "compile"));
        var plans = new FixPlanner(root, fake.machine()).plan(List.of(
                new FixRequest(Ecosystem.MAVEN, "org.springframework:spring-webmvc", "5.3.17", "5.3.42", declared),
                new FixRequest(Ecosystem.MAVEN, "org.springframework:spring-beans", "5.3.17", "5.3.20", declared)));
        for (var p : plans) {
            assertEquals("5.3.42", p.request().to(), p.request().pkg());
            assertTrue(p.steps().getFirst().command().contains("-DnewVersion=5.3.42"));
            assertEquals(Phrase.of("fix.note.shared", "org.springframework:spring-webmvc, org.springframework:spring-beans", "5.3.42"), p.notes().getFirst());
        }
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
        assertEquals(Phrase.of("fix.reason.notCachedMaven", "2.17.1"), plan(Ecosystem.MAVEN, log4j, "2.14.1", "2.17.1", "child/pom.xml", "compile").notApplicable(),
                "not cached: an offline build could not use it, nor can its Java be checked");
        Path gradleOnly = Files.createDirectories(fake.home.resolve(".gradle/caches/modules-2/files-2.1/org.apache.logging.log4j/log4j-core/2.17.1/abc"));
        assertEquals(Phrase.of("fix.reason.notCachedMaven", "2.17.1"), plan(Ecosystem.MAVEN, log4j, "2.14.1", "2.17.1", "child/pom.xml", "compile").notApplicable(),
                "in Gradle's cache only: no help to a pom " + gradleOnly);
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
                .steps().getFirst().edit() instanceof Step.TextEdit t ? t.after() : null);
        assertEquals("group: 'commons-io', name: 'commons-io', version: '2.7'", plan(Ecosystem.MAVEN, "commons-io:commons-io", "2.6", "2.7",
                "build.gradle", "implementation").steps().getFirst().edit() instanceof Step.TextEdit t ? t.after() : null);
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
        assertEquals("fix.reason.notCachedNpm", reason(plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "a/package-lock.json", "direct (dev)")));
        fake.npmTarball("lodash", "4.17.21");
        var npm = plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "a/package-lock.json", "direct (dev)").steps().getFirst();
        assertEquals(List.of("install", "lodash@4.17.21", "--offline", "--ignore-scripts", "--save-dev"), npm.command().subList(1, 6));
        assertEquals(Map.of("npm_config_offline", "true", "npm_config_save_prefix", "^"), npm.environment(), "written ^4.17.21, as it was");
        assertEquals(List.of("add", "lodash@^4.17.21", "--offline", "--ignore-scripts"),
                plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "b/yarn.lock", "direct").steps().getFirst().command().stream().skip(1).toList());
        var berryPlan = plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "c/yarn.lock", "direct");
        var berry = berryPlan.steps().getFirst();
        assertEquals(List.of("up", "lodash@4.17.21"), berry.command().subList(1, 3));
        assertEquals("0", berry.environment().get("YARN_ENABLE_SCRIPTS"));
        assertEquals("false", berry.environment().get("YARN_ENABLE_IMMUTABLE_INSTALLS"), "a CI machine's yarn would refuse the new lockfile");
        assertEquals(List.of("fix.note.pinned"), berryPlan.notes().stream().map(Phrase::key).toList(), "no range resolved offline");
        var pnpm = plan(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", "d/pnpm-lock.yaml", "direct");
        assertEquals(List.of("add", "lodash@4.17.21", "--offline", "--ignore-scripts", "-D"), pnpm.steps().getFirst().command().subList(1, 6));
        assertEquals(List.of("fix.note.pinned"), pnpm.notes().stream().map(Phrase::key).toList());
    }

    /** mkdirp 0.5.5 asking minimist ^1.2.5, locked at 1.2.5: as the real tools' fixtures (samples/fix-tools). */
    private static final String PACKAGE_LOCK = """
            {"name": "t", "lockfileVersion": 3, "packages": {
              "": {"dependencies": {"mkdirp": "0.5.5"}},
              "node_modules/mkdirp": {"version": "0.5.5", "dependencies": {"minimist": "%s"}},
              "node_modules/minimist": {"version": "1.2.5"}}}""";

    @Test
    void aTransitiveNpmPackageIsOverriddenItsVulnerableVersionOnly() throws Exception {
        write("a/package.json", "{\n  \"dependencies\": {\n    \"mkdirp\": \"0.5.5\"\n  }\n}\n");
        write("a/package-lock.json", PACKAGE_LOCK.formatted("^1.2.5"));
        fake.program("npm", "exit 0");
        assertEquals("fix.reason.notCachedNpm", reason(plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "a/package-lock.json", "transitive")));
        fake.npmTarball("minimist", "1.2.6");
        var p = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "a/package-lock.json", "transitive");
        assertTrue(p.applicable(), String.valueOf(p.notApplicable()));
        assertFalse(p.majorJump(), "1.2.6 within ^1.2.5: nothing to ask");
        var step = p.steps().getFirst();
        // under the dependent using the vulnerable copy: npm 10 ignores a key naming minimist's own version
        assertEquals(new PackageJsonMembers(root.resolve("a/package.json"), List.of("overrides", "mkdirp@0.5.5"), Map.of("minimist", "1.2.6"),
                root.resolve("a/package-lock.json")), step.edit());
        assertEquals(List.of("install", "--offline", "--ignore-scripts"), step.command().subList(1, 4));
        assertEquals("package.json: overrides.mkdirp@0.5.5 \"minimist\": \"1.2.6\"", step.edit().shown());
        // two dependents using it: an override under each, in one edit
        write("a/package-lock.json", """
                {"name": "t", "lockfileVersion": 3, "packages": {
                  "": {"dependencies": {"mkdirp": "0.5.5", "optimist": "0.6.1"}},
                  "node_modules/mkdirp": {"version": "0.5.5", "dependencies": {"minimist": "^1.2.5"}},
                  "node_modules/optimist": {"version": "0.6.1", "dependencies": {"minimist": "~1.2.0"}},
                  "node_modules/minimist": {"version": "1.2.5"}}}""");
        var two = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "a/package-lock.json", "transitive").steps().getFirst().edit();
        assertEquals("package.json: overrides.mkdirp@0.5.5 \"minimist\": \"1.2.6\", overrides.optimist@0.6.1 \"minimist\": \"1.2.6\"",
                two.shown());
        assertEquals(root.resolve("a/package-lock.json"), two.proof());
        String written = two.apply(Files.readString(root.resolve("a/package.json")));
        assertEquals(Map.of("mkdirp@0.5.5", Map.of("minimist", "1.2.6"), "optimist@0.6.1", Map.of("minimist", "1.2.6")),
                org.jtools.cvescanner.json.Json.obj(org.jtools.cvescanner.json.Json.parse(written)).get("overrides"));
        write("a/package-lock.json", PACKAGE_LOCK.formatted("^1.2.5"));
        // a fix outside what the dependent asks: applied only when ticked, said so
        write("a/package-lock.json", PACKAGE_LOCK.formatted("~1.2.5"));
        fake.npmTarball("minimist", "1.3.0");
        var outside = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.3.0", "a/package-lock.json", "transitive");
        assertTrue(outside.majorJump());
        assertEquals(List.of(Phrase.of("fix.note.outsideRangeOf", "1.3.0", "mkdirp@0.5.5", "~1.2.5")), outside.notes());
    }

    @Test
    void yarnOverridesBySpecAndYarn1OnlyWhenEveryCopyIsTheVulnerableOne() throws Exception {
        fake.program("yarn", "exit 0");
        write("b/package.json", "{\"dependencies\":{\"mkdirp\":\"0.5.5\"}}");
        write("b/yarn.lock", "# yarn lockfile v1\n\nminimist@^1.2.5:\n  version \"1.2.5\"\n\nmkdirp@0.5.5:\n  version \"0.5.5\"\n"
                + "  dependencies:\n    minimist \"^1.2.5\"\n");
        var yarn1 = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "b/yarn.lock", "transitive");
        assertEquals(Map.of("minimist", "1.2.6"), ((PackageJsonMembers) yarn1.steps().getFirst().edit()).members());
        assertEquals(List.of("install", "--offline", "--ignore-scripts"), yarn1.steps().getFirst().command().subList(1, 4));
        assertFalse(yarn1.majorJump());
        Files.writeString(root.resolve("b/yarn.lock"), Files.readString(root.resolve("b/yarn.lock")) + "\nminimist@^0.2.0:\n  version \"0.2.4\"\n");
        assertEquals(Phrase.of("fix.reason.yarn1Override", "minimist", "0.2.4"),
                plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "b/yarn.lock", "transitive").notApplicable());

        write("c/package.json", "{\"dependencies\":{\"mkdirp\":\"0.5.5\"}}");
        write("c/yarn.lock", "__metadata:\n  version: 8\n\n\"minimist@npm:^1.2.5\":\n  version: 1.2.5\n  resolution: \"minimist@npm:1.2.5\"\n");
        var berry = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "c/yarn.lock", "transitive").steps().getFirst();
        assertEquals(Map.of("minimist@npm:^1.2.5", "npm:1.2.6"), ((PackageJsonMembers) berry.edit()).members());
        assertEquals(List.of("install"), berry.command().subList(1, 2));
        assertEquals("0", berry.environment().get("YARN_ENABLE_NETWORK"));
    }

    @Test
    void pnpmOverridesInItsWorkspaceFileTheRangesReadOnceInstalled() throws Exception {
        fake.program("pnpm", "exit 0");
        write("d/package.json", "{\"dependencies\":{\"mkdirp\":\"0.5.5\"}}");
        write("d/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  minimist@1.2.5:\n    resolution: {integrity: x}\n\n"
                + "snapshots:\n\n  minimist@1.2.5: {}\n\n  mkdirp@0.5.5:\n    dependencies:\n      minimist: 1.2.5\n");
        var unknown = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "d/pnpm-lock.yaml", "transitive");
        assertTrue(unknown.majorJump(), "not installed: mkdirp's range unknown, asked first");
        assertEquals(List.of(Phrase.of("fix.note.rangesUnknown")), unknown.notes());
        var step = unknown.steps().getFirst();
        assertEquals(new PnpmWorkspaceOverride(root.resolve("d/pnpm-workspace.yaml"), "minimist@1.2.5", "1.2.6",
                root.resolve("d/pnpm-lock.yaml")), step.edit());
        assertEquals(List.of("install", "--offline", "--ignore-scripts", "--no-frozen-lockfile"), step.command().subList(1, 5));
        write("d/node_modules/.pnpm/mkdirp@0.5.5/node_modules/mkdirp/package.json", "{\"dependencies\":{\"minimist\":\"^1.2.5\"}}");
        var installed = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "d/pnpm-lock.yaml", "transitive");
        assertFalse(installed.majorJump());
        assertEquals(List.of(), installed.notes());
    }

    @Test
    void whereTheProjectDeclaresThePackageItIsUpgradedThereAndOverriddenElsewhere() throws Exception {
        fake.program("npm", "exit 0");
        fake.npmTarball("minimist", "1.2.6");
        write("a/package.json", "{\"dependencies\":{\"minimist\":\"1.2.5\",\"mkdirp\":\"0.5.5\"}}");
        write("a/package-lock.json", PACKAGE_LOCK.formatted("^1.2.5"));
        write("e/package.json", "{\"dependencies\":{\"mkdirp\":\"0.5.5\"}}");
        write("e/package-lock.json", PACKAGE_LOCK.formatted("^1.2.5"));
        var p = plan(Ecosystem.NPM, "minimist", "1.2.5", "1.2.6", "a/package-lock.json", "direct", "a/package-lock.json", "transitive",
                "e/package-lock.json", "transitive");
        assertEquals(2, p.steps().size());
        assertEquals(List.of("install", "minimist@1.2.6"), p.steps().get(0).command().subList(1, 3));
        assertTrue(p.steps().get(1).edit() instanceof PackageJsonMembers);
        assertEquals(root.resolve("e"), p.steps().get(1).directory());
    }

    @Test
    void anExactVersionStaysExactAndATildeATilde() throws Exception {
        write("a/package.json", "{\"dependencies\":{\"lodash\":\"4.17.20\"}}");
        write("a/package-lock.json", "{}");
        write("b/package.json", "{\"dependencies\":{\"lodash\":\"~4.17.20\"}}");
        write("b/package-lock.json", "{}");
        write("c/package.json", "{\"dependencies\":{\"lodash\":\"4.17.20\"}}");
        write("c/yarn.lock", "# yarn lockfile v1\n");
        write("d/package.json", "{\"devDependencies\":{\"lodash\":\"~4.17.20\"}}");
        write("d/yarn.lock", "# yarn lockfile v1\n");
        write("e/package.json", "{\"dependencies\":{\"lodash\":\"4.17.20\"}}");
        write("e/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        for (String tool : List.of("npm", "yarn", "pnpm")) fake.program(tool, "exit 0");
        fake.npmTarball("lodash", "4.17.21");
        var exact = plan(Ecosystem.NPM, "lodash", "4.17.20", "4.17.21", "a/package-lock.json", "direct").steps().getFirst();
        assertEquals("--save-exact", exact.command().getLast(), "npm would write ^4.17.21 otherwise");
        assertEquals(Map.of("npm_config_offline", "true"), exact.environment());
        var tilde = plan(Ecosystem.NPM, "lodash", "4.17.20", "4.17.21", "b/package-lock.json", "direct").steps().getFirst();
        assertEquals("~", tilde.environment().get("npm_config_save_prefix"));
        assertEquals(List.of("add", "lodash@4.17.21", "--offline", "--ignore-scripts", "--exact"),
                plan(Ecosystem.NPM, "lodash", "4.17.20", "4.17.21", "c/yarn.lock", "direct").steps().getFirst().command().stream().skip(1).toList());
        assertEquals(List.of("add", "lodash@4.17.21", "--offline", "--ignore-scripts", "--tilde", "--dev"),
                plan(Ecosystem.NPM, "lodash", "4.17.20", "4.17.21", "d/yarn.lock", "direct (dev)").steps().getFirst().command().stream().skip(1).toList());
        assertTrue(plan(Ecosystem.NPM, "lodash", "4.17.20", "4.17.21", "e/pnpm-lock.yaml", "direct").notes().isEmpty(), "exact already");
    }

    @Test
    void onWindowsNoCaretGoesThroughCmdYarn1PinsTheVersionAndSaysSo() throws Exception {
        write("b/package.json", "{\"dependencies\":{\"lodash\":\"^4.17.0\"}}");
        write("b/yarn.lock", "# yarn lockfile v1\n");
        Path yarn = fake.program("yarn.cmd", "exit 0");
        var windows = new Machine(List.of(fake.bin), true, List.of(".cmd"), fake.home, null);
        var plan = new FixPlanner(root, windows).plan(List.of(new FixRequest(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21",
                List.of(new FixRequest.Declaration(root.resolve("b/yarn.lock"), "direct"))))).getFirst();
        assertEquals(List.of(yarn.toString(), "add", "lodash@4.17.21", "--offline", "--ignore-scripts", "--exact"), plan.steps().getFirst().command());
        assertEquals(List.of("fix.note.pinnedWindows"), plan.notes().stream().map(Phrase::key).toList());
        assertEquals(List.of("cmd.exe", "/c", "C:\\Program Files\\nodejs\\yarn.cmd", "add", "lodash@4.17.21"),
                ToolRunner.command(List.of("C:\\Program Files\\nodejs\\yarn.cmd", "add", "lodash@4.17.21")));
    }

    @Test
    void theCachesAreWhereTheToolsEnvironmentPutsThem() {
        Path home = Path.of("/h"), gradle = Path.of("/g"), npm = Path.of("/n");
        var machine = new Machine(List.of(), false, List.of(""), home, null, gradle, npm);
        assertEquals(gradle.resolve("caches/modules-2/files-2.1"), machine.gradleCache());
        assertEquals(npm.resolve("_cacache"), machine.npmCache());
        var defaults = new Machine(List.of(), false, List.of(""), home, null);
        assertEquals(home.resolve(".gradle/caches/modules-2/files-2.1"), defaults.gradleCache());
        assertEquals(home.resolve(".npm/_cacache"), defaults.npmCache());
    }

    @Test
    void aFixNeedingANewerNodeThanTheProjectsIsNotApplied() throws Exception {
        write("package.json", "{\"engines\":{\"node\":\">=14\"},\"dependencies\":{\"axios\":\"0.21.0\"}}");
        fake.program("npm", "exit 0");
        for (String v : List.of("1.6.0", "0.21.2", "0.21.4")) fake.npmTarball("axios", v);
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
    void aNameOrVersionThatCouldBeAnOptionIsNotApplied() {
        assertEquals("fix.reason.unsafe", reason(plan(Ecosystem.NPM, "--registry=http://x", "1.0.0", "1.0.1", "package.json", "dependencies")));
        assertEquals("fix.reason.unsafe", reason(plan(Ecosystem.MAVEN, "g:a", "1.0", "1.1 & calc", "pom.xml", "compile")));
        assertEquals("fix.reason.unsafe", reason(plan(Ecosystem.NPM, "lodash", "4.17.15", "-1", "package.json", "dependencies")));
    }

    @Test
    void aMajorVersionJumpIsSaid() {
        assertTrue(FixPlanner.majorJump(new FixRequest(Ecosystem.MAVEN, "g:a", "2.9.8", "3.0.0", List.of())));
        assertFalse(FixPlanner.majorJump(new FixRequest(Ecosystem.MAVEN, "g:a", "2.9.8", "2.12.7.1", List.of())));
        assertNull(plan(Ecosystem.COTS, "a:b", "1", "2", "x", "y").requirement());
    }
}
