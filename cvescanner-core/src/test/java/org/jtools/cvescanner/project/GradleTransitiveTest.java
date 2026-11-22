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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Unresolved;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GradleTransitiveTest {

    @TempDir
    Path dir;
    private final List<Phrase> warnings = new ArrayList<>();
    private DependencyCollector col;

    private Path cache() {
        return dir.resolve("files-2.1");
    }

    /** A pom in Gradle's cache: group/artifact/version/sha1/artifact-version.pom. */
    private void pom(String g, String a, String v, String body) throws IOException {
        Path file = cache().resolve(g).resolve(a).resolve(v).resolve("0123abcd").resolve(a + "-" + v + ".pom");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>" + g
                + "</groupId><artifactId>" + a + "</artifactId><version>" + v + "</version>" + body + "</project>");
    }

    private static String deps(String... gavs) {
        var sb = new StringBuilder("<dependencies>");
        for (String gav : gavs) {
            String[] p = gav.split(":");
            sb.append("<dependency><groupId>").append(p[0]).append("</groupId><artifactId>").append(p[1]).append("</artifactId>");
            if (p.length > 2) sb.append("<version>").append(p[2]).append("</version>");
            if (p.length > 3) sb.append("<scope>").append(p[3]).append("</scope>");
            sb.append("</dependency>");
        }
        return sb.append("</dependencies>").toString();
    }

    /** The build scanned, with Gradle's cache unless none: each dependency's version and scope, by name and file. */
    private Map<String, String> scan(String build, boolean withCache, String... extra) throws IOException {
        Path project = Files.createDirectories(dir.resolve("project"));
        Path file = Files.writeString(project.resolve("build.gradle.kts"), build);
        var catalogs = new ArrayList<Path>();
        var locks = new ArrayList<Path>();
        for (int i = 0; i < extra.length; i += 2) {
            Path p = project.resolve(extra[i]);
            Files.createDirectories(p.getParent());
            Files.writeString(p, extra[i + 1]);
            (extra[i].endsWith(".toml") ? catalogs : locks).add(p);
        }
        col = new DependencyCollector(project);
        GradleReader.scan(List.of(file), List.of(), catalogs, locks, col, warnings::add, withCache ? new GradleCache(cache()) : null);
        var out = new TreeMap<String, String>();
        for (Dependency d : col.deps) out.put(d.name() + " @" + d.file(), d.version() + " " + d.scope());
        return out;
    }

    @Test
    void theHighestVersionAskedWinsADeclaredOneRaised() throws IOException {
        pom("g", "b", "1", deps("g:a:2"));
        pom("g", "a", "1", deps("g:old:1"));
        pom("g", "a", "2", "");
        pom("g", "old", "1", "");
        var found = scan("""
                dependencies {
                    implementation("g:a:1")
                    implementation("g:b:1")
                }""", true);
        assertEquals(Map.of("g:a @build.gradle.kts", "2 implementation", "g:b @build.gradle.kts", "1 implementation"), found,
                "a raised to 2 by b; old, which only a 1 brought, gone");
        assertTrue(warnings.isEmpty(), warnings.toString());
    }

    @Test
    void aPlatformGivesVersionsAndTakesPartAnEnforcedOneForces() throws IOException {
        pom("g", "bom", "1", "<packaging>pom</packaging><dependencyManagement>" + deps("g:x:3", "g:y:5") + "</dependencyManagement>");
        pom("g", "lib", "1", deps("g:y:4"));
        pom("g", "x", "3", "");
        pom("g", "y", "5", "");
        var found = scan("""
                dependencies {
                    implementation(platform("g:bom:1"))
                    implementation("g:x")
                    implementation("g:lib:1")
                }""", true);
        assertEquals("3 implementation", found.get("g:x @build.gradle.kts"));
        assertEquals("5 transitive via g:lib", found.get("g:y @build.gradle.kts"), "the platform's 5 above lib's 4");
        pom("g", "y", "4", "");
        pom("g", "strict", "1", "<packaging>pom</packaging><dependencyManagement>" + deps("g:y:4") + "</dependencyManagement>");
        pom("g", "up", "1", deps("g:y:9"));
        var forced = scan("""
                dependencies {
                    implementation(enforcedPlatform("g:strict:1"))
                    implementation("g:up:1")
                }""", true);
        assertEquals("4 transitive via g:up", forced.get("g:y @build.gradle.kts"), "an enforced platform's version forced");
    }

    @Test
    void anExcludeBlockAndTheConfigurationsScopes() throws IOException {
        pom("g", "a", "1", deps("g:logging:1", "g:core:1"));
        pom("g", "core", "1", "");
        pom("g", "t", "1", deps("g:assert:1"));
        pom("g", "assert", "1", "");
        pom("g", "api", "1", deps("g:inner:1"));
        pom("g", "inner", "1", "");
        var found = scan("""
                dependencies {
                    implementation("g:a:1") {
                        exclude(group = "g", module = "logging")
                    }
                    testImplementation("g:t:1")
                    compileOnly("g:api:1")
                    classpath("g:plugin:1")
                }""", true);
        assertEquals(null, found.get("g:logging @build.gradle.kts"), found.toString());
        assertEquals("1 transitive via g:a", found.get("g:core @build.gradle.kts"));
        assertEquals("1 transitive (test) via g:t", found.get("g:assert @build.gradle.kts"));
        assertEquals("1 transitive (provided) via g:api", found.get("g:inner @build.gradle.kts"));
        assertTrue(warnings.isEmpty(), "the excluded and the classpath not looked for: " + warnings);
    }

    @Test
    void aCatalogEntryIsFollowedFromTheLineThatUsesIt() throws IOException {
        pom("g", "netty", "4", deps("g:buffer:4"));
        pom("g", "buffer", "4", "");
        var found = scan("""
                dependencies {
                    testImplementation(libs.netty.codec)
                }""", true, "gradle/libs.versions.toml", "[libraries]\nnetty-codec = { module = \"g:netty\", version = \"4\" }\n");
        assertEquals("4 catalog:netty-codec", found.get("g:netty @gradle/libs.versions.toml"));
        assertEquals("4 transitive (test) via g:netty", found.get("g:buffer @build.gradle.kts"));
    }

    @Test
    void aCatalogEntryAPlatformGivesAVersionToOrTheGraphRaisesSaysThatVersion() throws IOException {
        pom("g", "bom", "1", "<packaging>pom</packaging><dependencyManagement>" + deps("g:x:3") + "</dependencyManagement>");
        pom("g", "x", "3", "");
        pom("g", "lib", "1", deps("g:codec:2"));
        pom("g", "codec", "1", "");
        pom("g", "codec", "2", "");
        var found = scan("""
                dependencies {
                    implementation(platform("g:bom:1"))
                    implementation(libs.x)
                    implementation(libs.codec)
                    implementation("g:lib:1")
                }""", true, "gradle/libs.versions.toml", "[libraries]\nx = { module = \"g:x\" }\ncodec = \"g:codec:1\"\n");
        assertEquals("3 catalog:x", found.get("g:x @gradle/libs.versions.toml"), "the platform's version, not 'no version in catalog'");
        assertEquals("2 catalog:codec", found.get("g:codec @gradle/libs.versions.toml"), "raised to 2 by lib");
        assertTrue(col.unresolved.isEmpty(), col.unresolved.toString());
    }

    @Test
    void aLockfilesVersionsWinTheDeclaredOnesDirect() throws IOException {
        var found = scan("""
                dependencies {
                    implementation("g:a:1")
                    implementation(libs.b)
                    classpath("g:tool:7")
                }""", false,
                "gradle/libs.versions.toml", "[libraries]\nb = \"g:b:1\"\n",
                "gradle.lockfile", """
                        # comment
                        g:a:1.5=compileClasspath,runtimeClasspath
                        g:b:2=runtimeClasspath
                        g:c:3=runtimeClasspath
                        g:t:4=testCompileClasspath,testRuntimeClasspath
                        empty=annotationProcessor
                        """);
        assertEquals(Map.of("g:a @gradle.lockfile", "1.5 direct", "g:b @gradle.lockfile", "2 direct", "g:c @gradle.lockfile", "3 transitive",
                "g:t @gradle.lockfile", "4 transitive (test)", "g:tool @build.gradle.kts", "7 classpath"), found,
                "the lockfile's versions, the catalog's b not listed again at 1");
    }

    @Test
    void withoutACacheAVersionlessDeclarationIsUnchecked() throws IOException {
        var found = scan("""
                dependencies {
                    implementation(platform("g:bom:1"))
                    implementation("g:x")
                }""", false);
        assertEquals(Map.of("g:bom @build.gradle.kts", "1 implementation"), found);
        assertEquals(List.of("g:x reason.platformVersion"), col.unresolved.stream().map(u -> u.name() + " " + u.reason().key()).toList());
    }

    @Test
    void aMissingPomIsSaidOnce() throws IOException {
        pom("g", "a", "1", deps("g:gone:1", "g:gone2:2"));
        scan("dependencies {\n    implementation(\"g:a:1\")\n}", true);
        assertEquals(1, warnings.size());
        assertEquals("warning.gradlePomsMissing", warnings.getFirst().key());
        assertEquals(2, warnings.getFirst().arguments().getFirst());
        assertTrue(Unresolved.class.isRecord());
    }
}
