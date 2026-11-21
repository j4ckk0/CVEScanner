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
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.jtools.cvescanner.model.ScanMode;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class ProjectFiles {
    static final Set<String> SKIP_DIRS = Set.of("node_modules", "target", "build", "dist", "out", "bower_components", "vendor");
    public final List<Path> poms = new ArrayList<>(), gradle = new ArrayList<>(), catalogs = new ArrayList<>(),
            gradleProps = new ArrayList<>(), packageJsons = new ArrayList<>();
    /** What names components off-the-shelf: inventories, SBOMs, binaries, pkg-config files, vcpkg and Conan manifests. */
    public final List<Path> cotsInventories = new ArrayList<>(), sboms = new ArrayList<>(), binaries = new ArrayList<>(),
            pkgConfigs = new ArrayList<>(), vcpkgManifests = new ArrayList<>(), conanFiles = new ArrayList<>();
    /** What an installed product ships: jars (WAR, EAR), the package.json of installed npm packages, Python's metadata. */
    public final List<Path> jars = new ArrayList<>(), installedPackageJsons = new ArrayList<>(), pythonMetadata = new ArrayList<>();

    private static final Pattern BINARY = Pattern.compile(".*\\.(dll|exe|dylib|so(\\.\\d+)*)", Pattern.CASE_INSENSITIVE);

    public static ProjectFiles find(Path root) throws IOException {
        return find(root, ScanMode.SOURCES);
    }

    /**
     * The files of a scan: the projects' manifests (SOURCES), or what an installed product ships (INSTALLED), where no
     * folder but a hidden one is passed over: node_modules, build, dist hold what is installed.
     */
    public static ProjectFiles find(Path root, ScanMode mode) throws IOException {
        var f = new ProjectFiles();
        boolean installed = mode == ScanMode.INSTALLED;
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (dir.equals(root)) return FileVisitResult.CONTINUE;
                String n = dir.getFileName().toString();
                return (!installed && SKIP_DIRS.contains(n)) || n.startsWith(".") ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String n = file.getFileName().toString();
                if (installed) {
                    installedFile(f, file, n);
                    return FileVisitResult.CONTINUE;
                }
                switch (n) {
                    case "pom.xml" -> f.poms.add(file);
                    case "build.gradle", "build.gradle.kts" -> f.gradle.add(file);
                    case "gradle.properties" -> f.gradleProps.add(file);
                    case "package.json" -> f.packageJsons.add(file);
                    case "cots.csv" -> f.cotsInventories.add(file);
                    case "bom.json" -> f.sboms.add(file);
                    case "vcpkg.json" -> f.vcpkgManifests.add(file);
                    case "conanfile.txt", "conanfile.py", "conan.lock" -> f.conanFiles.add(file);
                    default -> {
                        String lower = n.toLowerCase(Locale.ROOT);
                        if (n.endsWith(".versions.toml")) f.catalogs.add(file);
                        else if (lower.endsWith(".cots.csv")) f.cotsInventories.add(file);
                        else if (lower.endsWith(".cdx.json") || lower.endsWith(".spdx.json")) f.sboms.add(file);
                        else if (lower.endsWith(".pc")) f.pkgConfigs.add(file);
                        else if (BINARY.matcher(n).matches()) f.binaries.add(file);
                    }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException e) { return FileVisitResult.CONTINUE; }
        });
        for (var list : List.of(f.poms, f.gradle, f.catalogs, f.gradleProps, f.packageJsons, f.cotsInventories, f.sboms,
                f.binaries, f.pkgConfigs, f.vcpkgManifests, f.conanFiles, f.jars, f.installedPackageJsons, f.pythonMetadata))
            Collections.sort(list);
        return f;
    }

    /** A file of an installed product: what it ships, and what describes components off-the-shelf in both modes. */
    private static void installedFile(ProjectFiles f, Path file, String n) {
        String lower = n.toLowerCase(Locale.ROOT);
        String parent = file.getParent() == null || file.getParent().getFileName() == null ? "" : file.getParent().getFileName().toString();
        if (lower.endsWith(".jar") || lower.endsWith(".war") || lower.endsWith(".ear")) f.jars.add(file);
        else if (n.equals("package.json") && inNodeModules(file)) f.installedPackageJsons.add(file);
        else if ((n.equals("METADATA") && parent.endsWith(".dist-info")) || (n.equals("PKG-INFO") && parent.endsWith(".egg-info"))) f.pythonMetadata.add(file);
        else if (n.equals("cots.csv") || lower.endsWith(".cots.csv")) f.cotsInventories.add(file);
        else if (n.equals("bom.json") || lower.endsWith(".cdx.json") || lower.endsWith(".spdx.json")) f.sboms.add(file);
        else if (lower.endsWith(".pc")) f.pkgConfigs.add(file);
        else if (BINARY.matcher(n).matches()) f.binaries.add(file);
    }

    /** The package.json of an installed package: node_modules/name/ or node_modules/@scope/name/. */
    private static boolean inNodeModules(Path packageJson) {
        Path dir = packageJson.getParent();
        if (dir == null || dir.getParent() == null) return false;
        Path up = dir.getParent();
        if (up.getFileName() != null && up.getFileName().toString().startsWith("@")) up = up.getParent();
        return up != null && up.getFileName() != null && up.getFileName().toString().equals("node_modules");
    }

    public static String readText(Path p) throws IOException { return new String(Files.readAllBytes(p), UTF_8); }
}
