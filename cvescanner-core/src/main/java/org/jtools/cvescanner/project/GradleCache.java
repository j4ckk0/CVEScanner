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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilder;

/**
 * Gradle's cache of downloaded modules, read for the poms of a build's dependencies:
 * files-2.1/group/artifact/version/sha1/artifact-version.pom. Only read, never written; a pom not there is not fetched
 * (README, "No network"). Each pom is read once.
 */
public final class GradleCache implements PomSource {

    private final Path root;
    private final DocumentBuilder parser = MavenReader.pomParser();
    private final Map<String, Optional<MavenReader.Pom>> read = new HashMap<>();

    /** @param root the files-2.1 folder */
    public GradleCache(Path root) {
        this.root = root;
    }

    /**
     * The files-2.1 folder of this home's Gradle cache: under GRADLE_USER_HOME when it is given, else ~/.gradle.
     *
     * @param gradleUserHome the GRADLE_USER_HOME variable; null or blank when not set
     */
    public static Path locate(Path home, String gradleUserHome) {
        Path base = gradleUserHome != null && !gradleUserHome.isBlank() ? Path.of(gradleUserHome.strip()) : home.resolve(".gradle");
        return base.resolve("caches").resolve("modules-2").resolve("files-2.1");
    }

    public Path root() {
        return root;
    }

    @Override
    public String shown() {
        return root.toString().replace('\\', '/');
    }

    @Override
    public Optional<MavenReader.Pom> pom(String group, String artifact, String version) {
        if (group == null || artifact == null || version == null || !MavenRepository.safe(group) || !MavenRepository.safe(artifact)
                || !MavenRepository.safe(version))
            return Optional.empty();
        return read.computeIfAbsent(group + ":" + artifact + ":" + version, _ -> {
            Path dir = root.resolve(group).resolve(artifact).resolve(version);   // the group as written, its dots kept
            if (!dir.normalize().startsWith(root.normalize()) || !Files.isDirectory(dir)) return Optional.empty();
            String name = artifact + "-" + version + ".pom";
            try (Stream<Path> hashes = Files.list(dir)) {
                for (Path hash : hashes.sorted().toList()) {
                    Path file = hash.resolve(name);
                    if (Files.isRegularFile(file)) return Optional.of(MavenReader.parse(file, parser.parse(file.toFile()).getDocumentElement()));
                }
            } catch (IOException | org.xml.sax.SAXException | RuntimeException _) {
                // unreadable: as if not there
            }
            return Optional.empty();
        });
    }
}
