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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The machine the fixes would run on, as far as they need it: where its programs are (PATH) and its caches (the
 * local Maven repository, Gradle's and npm's caches). A value, so that a test gives its own.
 */
public record Machine(List<Path> path, boolean windows, List<String> pathExt, Path home, Path localAppData) {

    public Machine {
        path = List.copyOf(path);
        pathExt = List.copyOf(pathExt);
    }

    /** This machine, as its environment says. */
    public static Machine current() {
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
        var dirs = new ArrayList<Path>();
        for (String d : System.getenv().getOrDefault("PATH", "").split(Pattern.quote(File.pathSeparator)))
            if (!d.isBlank()) dirs.add(Path.of(d.strip()));
        List<String> ext = windows ? List.of(System.getenv().getOrDefault("PATHEXT", ".COM;.EXE;.BAT;.CMD").toLowerCase(Locale.ROOT).split(";"))
                : List.of("");
        String local = System.getenv("LOCALAPPDATA");
        return new Machine(dirs, windows, ext, Path.of(System.getProperty("user.home")), local == null ? null : Path.of(local));
    }

    /**
     * A program, found without starting anything: the project's own wrapper first (mvnw, gradlew, from the folder up
     * to the one scanned), else on PATH. Empty when it is nowhere: the fix is then not applied, nothing installed.
     */
    public Optional<Path> program(String name, String wrapper, Path from, Path root) {
        if (wrapper != null)
            for (Path dir = from; dir != null && dir.startsWith(root); dir = dir.getParent()) {
                Optional<Path> w = executable(dir, wrapper);
                if (w.isPresent()) return w;
            }
        for (Path dir : path) {
            Optional<Path> p = executable(dir, name);
            if (p.isPresent()) return p;
        }
        return Optional.empty();
    }

    private Optional<Path> executable(Path dir, String name) {
        for (String ext : windows ? pathExt : List.of("")) {
            Path p = dir.resolve(name + ext);
            if (Files.isRegularFile(p) && (windows || Files.isExecutable(p))) return Optional.of(p);
        }
        return Optional.empty();
    }

    /** The local Maven repository: the one ~/.m2/settings.xml names, else ~/.m2/repository. */
    public Path mavenRepository() {
        Path settings = home.resolve(".m2").resolve("settings.xml");
        try {
            if (Files.isRegularFile(settings)) {
                var m = Pattern.compile("<localRepository>\\s*([^<]+?)\\s*</localRepository>").matcher(ProjectFiles.readText(settings));
                if (m.find()) return Path.of(m.group(1).replace("${user.home}", home.toString()));
            }
        } catch (Exception _) {
            // the default, then
        }
        return home.resolve(".m2").resolve("repository");
    }

    public Path gradleCache() {
        return home.resolve(".gradle").resolve("caches").resolve("modules-2").resolve("files-2.1");
    }

    /** npm's content cache: ~/.npm/_cacache, or %LOCALAPPDATA%\npm-cache\_cacache on Windows. */
    public Path npmCache() {
        return windows && localAppData != null ? localAppData.resolve("npm-cache").resolve("_cacache")
                : home.resolve(".npm").resolve("_cacache");
    }
}
