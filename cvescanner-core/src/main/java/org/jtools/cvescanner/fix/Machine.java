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
import org.jtools.cvescanner.project.MavenRepository;

/**
 * The machine the fixes would run on, as far as they need it: where its programs are (PATH) and its caches (the
 * local Maven repository, Gradle's and npm's caches). A value, so that a test gives its own.
 */
public record Machine(List<Path> path, boolean windows, List<String> pathExt, Path home, Path localAppData,
                      Path gradleUserHome, Path npmCacheDir) {

    public Machine {
        path = List.copyOf(path);
        pathExt = List.copyOf(pathExt);
    }

    /** A machine whose caches are where their tools put them by default. */
    public Machine(List<Path> path, boolean windows, List<String> pathExt, Path home, Path localAppData) {
        this(path, windows, pathExt, home, localAppData, null, null);
    }

    /** This machine, as its environment says. */
    public static Machine current() {
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
        var dirs = new ArrayList<Path>();
        for (String d : System.getenv().getOrDefault("PATH", "").split(Pattern.quote(File.pathSeparator)))
            if (!d.isBlank()) dirs.add(Path.of(d.strip()));
        List<String> ext = windows ? List.of(System.getenv().getOrDefault("PATHEXT", ".COM;.EXE;.BAT;.CMD").toLowerCase(Locale.ROOT).split(";"))
                : List.of("");
        Path home = Path.of(System.getProperty("user.home"));
        var found = new Machine(dirs, windows, ext, home, env("LOCALAPPDATA"), env("GRADLE_USER_HOME"), null);
        Path npmCache = NpmConfig.cache(System.getenv(), home, found.program("node"), windows).orElse(null);
        return new Machine(dirs, windows, ext, home, found.localAppData(), found.gradleUserHome(), npmCache);
    }

    private static Path env(String name) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? null : Path.of(value.strip());
    }

    /**
     * A program on PATH, found without starting anything. Empty when it is not there: the fix is then not applied, and
     * nothing is installed. A project's wrapper (mvnw, gradlew) is not used: it downloads its tool when not unpacked.
     */
    public Optional<Path> program(String name) {
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
        return MavenRepository.locate(home);
    }

    /** Gradle's downloads: under GRADLE_USER_HOME when it is set, else ~/.gradle. */
    public Path gradleCache() {
        return (gradleUserHome != null ? gradleUserHome : home.resolve(".gradle")).resolve("caches").resolve("modules-2").resolve("files-2.1");
    }

    /**
     * npm's content cache: under the folder npm's configuration names (npm_config_cache, an npmrc) when it names one,
     * else ~/.npm/_cacache, %LOCALAPPDATA%\npm-cache\_cacache on Windows.
     */
    public Path npmCache() {
        if (npmCacheDir != null) return npmCacheDir.resolve("_cacache");
        return windows && localAppData != null ? localAppData.resolve("npm-cache").resolve("_cacache")
                : home.resolve(".npm").resolve("_cacache");
    }
}
