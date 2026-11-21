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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class ProjectFiles {
    static final Set<String> SKIP_DIRS = Set.of("node_modules", "target", "build", "dist", "out", "bower_components", "vendor");
    public final List<Path> poms = new ArrayList<>(), gradle = new ArrayList<>(), catalogs = new ArrayList<>(),
            gradleProps = new ArrayList<>(), packageJsons = new ArrayList<>();

    public static ProjectFiles find(Path root) throws IOException {
        var f = new ProjectFiles();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.equals(root)) return FileVisitResult.CONTINUE;
                String n = dir.getFileName().toString();
                return SKIP_DIRS.contains(n) || n.startsWith(".") ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String n = file.getFileName().toString();
                switch (n) {
                    case "pom.xml" -> f.poms.add(file);
                    case "build.gradle", "build.gradle.kts" -> f.gradle.add(file);
                    case "gradle.properties" -> f.gradleProps.add(file);
                    case "package.json" -> f.packageJsons.add(file);
                    default -> { if (n.endsWith(".versions.toml")) f.catalogs.add(file); }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException e) { return FileVisitResult.CONTINUE; }
        });
        for (var list : List.of(f.poms, f.gradle, f.catalogs, f.gradleProps, f.packageJsons)) Collections.sort(list);
        return f;
    }

    static String readText(Path p) throws IOException { return new String(Files.readAllBytes(p), UTF_8); }
}
