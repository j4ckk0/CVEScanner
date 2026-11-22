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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;

/**
 * The local Maven repository, read for the poms of a project's dependencies: what each one depends on, its parents,
 * the dependency management it imports. Only read, never written; a pom not there is not fetched (README, "No
 * network"). Each pom is read once.
 */
public final class MavenRepository implements PomSource {

    private static final Pattern LOCAL_REPOSITORY = Pattern.compile("<localRepository>\\s*([^<]+?)\\s*</localRepository>");

    private final Path root;
    private final DocumentBuilder parser = MavenReader.pomParser();
    private final Map<Path, Optional<MavenReader.Pom>> read = new HashMap<>();

    public MavenRepository(Path root) {
        this.root = root;
    }

    /** The local repository of this home folder: the one ~/.m2/settings.xml names, else ~/.m2/repository. */
    public static Path locate(Path home) {
        Path settings = home.resolve(".m2").resolve("settings.xml");
        try {
            if (Files.isRegularFile(settings)) {
                var m = LOCAL_REPOSITORY.matcher(ProjectFiles.readText(settings));
                if (m.find()) return Path.of(m.group(1).replace("${user.home}", home.toString()));
            }
        } catch (Exception _) {
            // the default, then
        }
        return home.resolve(".m2").resolve("repository");
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
        if (group == null || artifact == null || version == null || !safe(group) || !safe(artifact) || !safe(version))
            return Optional.empty();
        Path file = root.resolve(group.replace('.', '/')).resolve(artifact).resolve(version).resolve(artifact + "-" + version + ".pom");
        if (!file.normalize().startsWith(root.normalize())) return Optional.empty();   // never a file outside the repository
        return read.computeIfAbsent(file, f -> {
            if (!Files.isRegularFile(f)) return Optional.empty();
            try {
                return Optional.of(MavenReader.parse(f, parser.parse(f.toFile()).getDocumentElement()));
            } catch (Exception _) {
                return Optional.empty();
            }
        });
    }

    /** A coordinate that stays inside the repository (or Gradle's cache): no separator, no dot at an end nor two together, nothing unresolved. */
    static boolean safe(String part) {
        return !part.isBlank() && !part.contains("/") && !part.contains("\\") && !part.contains("..") && !part.startsWith(".")
                && !part.endsWith(".") && !part.contains("${") && !part.contains(":");
    }
}
