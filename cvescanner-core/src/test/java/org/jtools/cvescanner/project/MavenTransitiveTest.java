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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MavenTransitiveTest {

    @TempDir
    Path dir;
    private final List<Phrase> warnings = new ArrayList<>();
    private DependencyCollector col;

    private Path repo() {
        return dir.resolve("repo");
    }

    /** A pom in the repository: its coordinates, then what goes inside project. */
    private void pom(String g, String a, String v, String body) throws IOException {
        Path file = repo().resolve(g.replace('.', '/')).resolve(a).resolve(v).resolve(a + "-" + v + ".pom");
        Files.createDirectories(file.getParent());
        Files.writeString(file, project(g, a, v, body));
    }

    private static String project(String g, String a, String v, String body) {
        return "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion>"
                + (g == null ? "" : "<groupId>" + g + "</groupId>") + "<artifactId>" + a + "</artifactId>"
                + (v == null ? "" : "<version>" + v + "</version>") + body + "</project>";
    }

    private static String deps(String... deps) {
        return "<dependencies>" + String.join("", deps) + "</dependencies>";
    }

    private static String dep(String gav, String... extra) {
        String[] p = gav.split(":");
        return "<dependency><groupId>" + p[0] + "</groupId><artifactId>" + p[1] + "</artifactId>"
                + (p.length > 2 ? "<version>" + p[2] + "</version>" : "") + String.join("", extra) + "</dependency>";
    }

    /** The project's poms scanned with the repository: each dependency's name, version and scope, by name. */
    private Map<String, String> scan(String... projectPoms) throws IOException {
        var paths = new ArrayList<Path>();
        for (int i = 0; i < projectPoms.length; i += 2) {
            Path p = dir.resolve("project").resolve(projectPoms[i]).resolve("pom.xml");
            Files.createDirectories(p.getParent());
            Files.writeString(p, projectPoms[i + 1]);
            paths.add(p);
        }
        col = new DependencyCollector(dir.resolve("project"));
        MavenReader.scan(paths, col, warnings::add, new MavenRepository(repo()));
        var out = new TreeMap<String, String>();
        for (Dependency d : col.deps) out.put(d.name() + " @" + d.file(), d.version() + " " + d.scope());
        return out;
    }

    private static String app(String body) {
        return project("com.example", "app", "1.0", body);
    }

    @Test
    void theNearestVersionWinsAndADeclaredOneAlways() throws IOException {
        pom("g", "a", "1", deps(dep("g:c:1"), dep("g:b:2")));
        pom("g", "b", "1", deps(dep("g:d:1")));
        pom("g", "d", "1", deps(dep("g:c:2")));
        pom("g", "c", "1", "");
        var found = scan(".", app(deps(dep("g:a:1"), dep("g:b:1"))));
        assertEquals(Map.of(
                "g:a @pom.xml", "1 compile", "g:b @pom.xml", "1 compile",
                "g:c @pom.xml", "1 transitive via g:a", "g:d @pom.xml", "1 transitive via g:b"), found);
        assertTrue(warnings.isEmpty(), warnings.toString());
    }

    @Test
    void eachTransitiveDependencyKnowsThePackagesThatBringItTheNearestPath() throws IOException {
        pom("g", "a", "1", deps(dep("g:b:1")));
        pom("g", "b", "1", deps(dep("g:c:1")));
        pom("g", "x", "1", deps(dep("g:c:1")));
        pom("g", "c", "1", "");
        scan(".", app(deps(dep("g:a:1"), dep("g:x:1"))));
        var parents = new TreeMap<String, List<String>>();
        for (Dependency d : col.deps) parents.put(d.name(), d.parents());
        assertEquals(Map.of("g:a", List.of(), "g:x", List.of(), "g:b", List.of("g:a@1"), "g:c", List.of("g:x@1")), parents,
                "c: through x (two levels) rather than a > b (three)");
    }

    @Test
    void theProjectsDependencyManagementOverridesATransitiveVersion() throws IOException {
        pom("g", "a", "1", deps(dep("g:c:1")));
        pom("g", "c", "3", "");
        var found = scan(".", app("<dependencyManagement>" + deps(dep("g:c:3")) + "</dependencyManagement>" + deps(dep("g:a:1"))));
        assertEquals("3 transitive via g:a", found.get("g:c @pom.xml"));
    }

    @Test
    void exclusionsOptionalTestAndProvidedAreNotFollowed() throws IOException {
        pom("g", "a", "1", deps(dep("g:c:1"), dep("g:o:1", "<optional>true</optional>"), dep("g:t:1", "<scope>test</scope>"),
                dep("g:p:1", "<scope>provided</scope>"), dep("g:r:1", "<scope>runtime</scope>")));
        pom("g", "b", "1", deps(dep("g:x:1")));
        pom("g", "c", "1", "");
        pom("g", "r", "1", "");
        var found = scan(".", app(deps(
                dep("g:a:1", "<exclusions><exclusion><groupId>g</groupId><artifactId>c</artifactId></exclusion></exclusions>"),
                dep("g:b:1", "<exclusions><exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion></exclusions>"))));
        assertEquals(Map.of("g:a @pom.xml", "1 compile", "g:b @pom.xml", "1 compile", "g:r @pom.xml", "1 transitive (runtime) via g:a"), found);
    }

    @Test
    void aScopeNotWrittenIsTheManagements() throws IOException {
        // as log4j-core: its test libraries written without a scope, their parent's management making them test
        pom("g", "parent", "1", "<packaging>pom</packaging><dependencyManagement>"
                + deps(dep("g:junit:5", "<scope>test</scope>")) + "</dependencyManagement>");
        pom("g", "a", "1", "<parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                + deps(dep("g:junit"), dep("g:c:1")));
        pom("g", "c", "1", "");
        var found = scan(".", app(deps(dep("g:a:1"))));
        assertEquals(null, found.get("g:junit @pom.xml"), found.toString());
        assertEquals("1 transitive via g:a", found.get("g:c @pom.xml"));
    }

    @Test
    void aDependencyReachedForTestsAndForCompilingIsCompiledWith() throws IOException {
        // as spring-core, nearer through the test starter than through the web one: the version the nearest, the scope compile
        pom("g", "test-starter", "1", deps(dep("g:core:2")));
        pom("g", "web", "1", deps(dep("g:mid:1")));
        pom("g", "mid", "1", deps(dep("g:core:3")));
        pom("g", "core", "2", deps(dep("g:jcl:2")));
        pom("g", "jcl", "2", "");
        var found = scan(".", app(deps(dep("g:test-starter:1", "<scope>test</scope>"), dep("g:web:1"))));
        assertEquals("2 transitive via g:web", found.get("g:core @pom.xml"));
        assertEquals("2 transitive via g:web", found.get("g:jcl @pom.xml"), "what it brings widened too");
    }

    @Test
    void aTestDependencysOwnAreTestToo() throws IOException {
        pom("g", "t", "1", deps(dep("g:x:1")));
        pom("g", "x", "1", "");
        assertEquals("1 transitive (test) via g:t", scan(".", app(deps(dep("g:t:1", "<scope>test</scope>")))).get("g:x @pom.xml"));
    }

    @Test
    void aParentsPropertiesAndAnImportedBomGiveTheVersions() throws IOException {
        pom("g", "bom", "1", "<packaging>pom</packaging><dependencyManagement>" + deps(dep("g:y:7")) + "</dependencyManagement>");
        pom("g", "parent", "1", "<packaging>pom</packaging><properties><x.version>5</x.version></properties>"
                + "<dependencyManagement>" + deps(dep("g:bom:1", "<type>pom</type><scope>import</scope>")) + "</dependencyManagement>");
        pom("g", "a", "1", "<parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                + deps(dep("g:x:${x.version}"), dep("g:y")));
        pom("g", "x", "5", "");
        pom("g", "y", "7", "");
        var found = scan(".", app(deps(dep("g:a:1"))));
        assertEquals("5 transitive via g:a", found.get("g:x @pom.xml"));
        assertEquals("7 transitive via g:a", found.get("g:y @pom.xml"));
        assertTrue(warnings.isEmpty(), warnings.toString());
    }

    @Test
    void missingPomsAndUnresolvedVersionsAreSaidOnce() throws IOException {
        pom("g", "a", "1", deps(dep("g:m:1"), dep("g:n:2"), dep("g:r:[1,2)")));
        var found = scan(".", app(deps(dep("g:a:1"))));
        assertEquals("1 transitive via g:a", found.get("g:m @pom.xml"));   // listed: its own poms is what is missing
        assertEquals(2, warnings.size(), warnings.toString());
        assertEquals("warning.mavenPomsMissing", warnings.get(0).key());
        assertEquals(2, warnings.get(0).arguments().get(0));
        assertEquals("warning.mavenUnresolved", warnings.get(1).key());
        assertEquals(1, warnings.get(1).arguments().get(0));
    }

    @Test
    void aSiblingModuleIsFollowedThroughItsOwnPom() throws IOException {
        pom("g", "c", "1", "");
        String parent = project("com.example", "parent", "1.0", "<packaging>pom</packaging>");
        String a = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><parent><groupId>com.example</groupId>"
                + "<artifactId>parent</artifactId><version>1.0</version></parent><artifactId>a</artifactId>"
                + deps(dep("com.example:b:1.0")) + "</project>";
        String b = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><parent><groupId>com.example</groupId>"
                + "<artifactId>parent</artifactId><version>1.0</version></parent><artifactId>b</artifactId>"
                + deps(dep("g:c:1")) + "</project>";
        var found = scan(".", parent, "a", a, "b", b);
        assertEquals("1 transitive via com.example:b", found.get("g:c @a/pom.xml"));
        assertTrue(warnings.isEmpty(), warnings.toString());
    }

    @Test
    void aVersionAnExternalParentManagesIsResolved() throws IOException {
        pom("org.corp", "corp-parent", "3", "<packaging>pom</packaging><dependencyManagement>" + deps(dep("g:d:4"))
                + "</dependencyManagement>");
        pom("g", "d", "4", "");
        String child = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><parent><groupId>org.corp</groupId>"
                + "<artifactId>corp-parent</artifactId><version>3</version></parent><artifactId>app</artifactId>"
                + deps(dep("g:d")) + "</project>";
        assertEquals("4 compile", scan(".", child).get("g:d @pom.xml"));
        assertTrue(warnings.isEmpty(), warnings.toString());
    }

    @Test
    void aHostilePomImportingItselfOrACycleOfBomsIsReadOnce() throws IOException {
        pom("g", "bom-a", "1", "<packaging>pom</packaging><dependencyManagement>" + deps(dep("g:bom-b:1", "<type>pom</type><scope>import</scope>"),
                dep("g:x:2")) + "</dependencyManagement>");
        pom("g", "bom-b", "1", "<packaging>pom</packaging><dependencyManagement>" + deps(dep("g:bom-a:1", "<type>pom</type><scope>import</scope>"))
                + "</dependencyManagement>");
        pom("g", "x", "2", "");
        pom("g", "a", "1", "<dependencyManagement>" + deps(dep("g:bom-a:1", "<type>pom</type><scope>import</scope>"))
                + "</dependencyManagement>" + deps(dep("g:x")));
        String self = app("<dependencyManagement>" + deps(dep("com.example:app:1.0", "<type>pom</type><scope>import</scope>"))
                + "</dependencyManagement>" + deps(dep("g:a:1")));
        assertEquals("2 transitive via g:a", scan(".", self).get("g:x @pom.xml"));
    }

    @Test
    void aCoordinateThatWouldLeaveTheRepositoryIsNotRead() throws IOException {
        var found = scan(".", app(deps(dep(".etc:passwd:1"), dep("g..x:y:1"), dep("g:a:..%2F1"))));
        assertEquals(3, found.size(), found.toString());   // the three declared, nothing read for them
        assertTrue(warnings.stream().allMatch(w -> w.key().equals("warning.mavenPomsMissing")), warnings.toString());
    }

    @Test
    void withoutARepositoryOnlyTheDeclaredOnes() throws IOException {
        pom("g", "a", "1", deps(dep("g:c:1")));
        Path p = dir.resolve("project").resolve("pom.xml");
        Files.createDirectories(p.getParent());
        Files.writeString(p, app(deps(dep("g:a:1"))));
        var col = new DependencyCollector(dir.resolve("project"));
        MavenReader.scan(List.of(p), col, warnings::add);
        assertEquals(List.of("g:a"), col.deps.stream().map(Dependency::name).toList());
    }
}
