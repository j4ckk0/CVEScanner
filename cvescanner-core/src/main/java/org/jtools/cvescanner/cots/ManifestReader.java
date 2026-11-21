package org.jtools.cvescanner.cots;

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
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The components a C or C++ build declares: pkg-config files (*.pc: Name:, Version:), vcpkg manifests (vcpkg.json:
 * its dependencies, their version from "overrides" or "version>="), and Conan's (conanfile.txt, conanfile.py,
 * conan.lock: name/version references). A version set elsewhere — vcpkg's baseline, a Conan range — cannot be read
 * here: the component is unchecked, and said why.
 */
public final class ManifestReader {

    /** A Conan reference: name/version, then @user/channel or #revision, which are left out. */
    private static final Pattern CONAN_REF = Pattern.compile("([A-Za-z0-9_][A-Za-z0-9_.+-]*)/(\\[[^\\]]*\\]|[^\\s\"'@#,\\[\\]]+)");
    private static final Pattern PY_REQUIRES = Pattern.compile("requires\\s*(?:\\(|=|\\+=)\\s*[\\[(]?\\s*((?:[\"'][^\"']+[\"']\\s*,?\\s*)+)");

    private ManifestReader() {
    }

    public static void scan(List<Path> pkgConfigs, List<Path> vcpkgManifests, List<Path> conanFiles, DependencyCollector col,
                            Consumer<Phrase> warn) {
        for (Path file : pkgConfigs) read(file, col, warn, ManifestReader::pkgConfig);
        for (Path file : vcpkgManifests) read(file, col, warn, ManifestReader::vcpkg);
        for (Path file : conanFiles) read(file, col, warn, ManifestReader::conan);
    }

    private interface Reader {
        void read(String text, Path file, DependencyCollector col);
    }

    private static void read(Path file, DependencyCollector col, Consumer<Phrase> warn, Reader reader) {
        try {
            reader.read(ProjectFiles.readText(file), file, col);
        } catch (IOException | RuntimeException e) {
            warn.accept(Phrase.of("warning.skipped", col.rel(file), e.getMessage()));
        }
    }

    /** A pkg-config file: its Name when a known one (else the file's), its Version. */
    private static void pkgConfig(String text, Path file, DependencyCollector col) {
        String name = null, version = null;
        for (String line : text.lines().toList()) {
            if (line.startsWith("Name:")) name = line.substring(5).strip();
            else if (line.startsWith("Version:")) version = line.substring(8).strip();
        }
        String stem = file.getFileName().toString().replaceFirst("(?i)\\.pc$", "");
        String id = name != null && KnownProducts.isKnown(name) ? KnownProducts.identify(name) : KnownProducts.identify(stem);
        add(col, file, id, version, "pkg-config", false, Phrase.of("reason.noVersion"));
    }

    /** A vcpkg manifest: each dependency, its version from an override, else its minimum ("version>="), else none. */
    private static void vcpkg(String text, Path file, DependencyCollector col) {
        var root = Json.obj(Json.parse(text));
        Map<String, String> overrides = new LinkedHashMap<>();
        for (Object o : Json.arr(root.get("overrides"))) {
            var override = Json.obj(o);
            String name = Json.str(override, "name"), version = firstOf(override, "version", "version-semver", "version-string");
            if (name != null && version != null) overrides.put(name, version);
        }
        for (Object d : Json.arr(root.get("dependencies"))) {
            String name = d instanceof String s ? s : Json.str(Json.obj(d), "name");
            if (name == null) continue;
            String minimum = d instanceof String ? null : Json.str(Json.obj(d), "version>=");
            String version = overrides.containsKey(name) ? overrides.get(name) : minimum;
            add(col, file, KnownProducts.identify(name), version == null ? null : version.replaceFirst("#.*", ""), "vcpkg",
                    !overrides.containsKey(name) && minimum != null, Phrase.of("reason.vcpkgBaseline"));
        }
    }

    /** Conan: a lockfile's references, or a conanfile's requirements. */
    private static void conan(String text, Path file, DependencyCollector col) {
        String name = file.getFileName().toString();
        if (name.equals("conan.lock")) {
            var root = Json.obj(Json.parse(text));
            for (String key : List.of("requires", "build_requires", "python_requires"))
                for (Object ref : Json.arr(root.get(key))) if (ref instanceof String s) conanRef(s, file, col);
            for (Object node : Json.obj(Json.obj(root.get("graph_lock")).get("nodes")).values())
                if (Json.obj(node).get("ref") instanceof String s) conanRef(s, file, col);
        } else if (name.endsWith(".py")) {
            Matcher m = PY_REQUIRES.matcher(text);
            while (m.find()) {
                Matcher q = Pattern.compile("[\"']([^\"']+)[\"']").matcher(m.group(1));
                while (q.find()) conanRef(q.group(1), file, col);
            }
        } else {
            String section = "";
            for (String line : text.lines().map(String::strip).toList()) {
                if (line.startsWith("[")) section = line;
                else if (!line.isEmpty() && !line.startsWith("#")
                        && (section.equals("[requires]") || section.equals("[tool_requires]") || section.equals("[build_requires]")))
                    conanRef(line, file, col);
            }
        }
    }

    private static void conanRef(String ref, Path file, DependencyCollector col) {
        Matcher m = CONAN_REF.matcher(ref);
        if (!m.lookingAt()) return;
        String version = m.group(2);
        String id = KnownProducts.identify(m.group(1));
        if (version.startsWith("[")) col.miss("COTS", id, version, file, Phrase.of("reason.versionRange"));
        else col.add("COTS", id, version, file, "conan", false);
    }

    private static void add(DependencyCollector col, Path file, String id, String version, String scope, boolean approximate, Phrase whyNone) {
        if (version == null || version.isBlank()) col.miss("COTS", id, "", file, whyNone);
        else col.add("COTS", id, version.strip(), file, scope, approximate);
    }

    private static String firstOf(Map<String, Object> o, String... keys) {
        for (String key : keys) if (Json.str(o, key) != null) return Json.str(o, key);
        return null;
    }
}
