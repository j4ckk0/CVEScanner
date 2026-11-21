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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.version.Versions;

public final class NpmReader {
    private static final List<String> LOCKFILES = List.of("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml");
    private static final Pattern NON_REGISTRY = Pattern.compile("^(file:|link:|portal:|workspace:|catalog:|git|github:|https?:)");
    private static final Pattern GITHUB_SHORTHAND = Pattern.compile("^[\\w.\\-]+/[\\w.\\-]+(#.*)?$");
    private static final Pattern RANGE_VERSION = Pattern.compile("(\\d+)(?:\\.(\\d+|[xX*]))?(?:\\.(\\d+|[xX*]))?(-[0-9A-Za-z.\\-]+)?");
    private static final Pattern EXACT = Pattern.compile("=?v?\\d+\\.\\d+\\.\\d+(-[0-9A-Za-z.\\-]+)?");
    private static final Pattern YARN_VERSION = Pattern.compile("\\s+version:?\\s+\"?([^\"\\s]+)\"?");
    private static final Pattern PNPM_KEY = Pattern.compile("^ {2}['\"]?/?((?:@[^/@\\s'\"]+/)?[^/@\\s'\"]+)[@/](\\d[^:()\\s'\"]*)");

    record LockEntry(String name, String version, boolean dev, boolean direct) {}

    /** The lowest version a range of package.json allows, exact when the range names one version; or why there is none. */
    public record MinVersion(String version, boolean exact, Phrase reason) {}

    private NpmReader() {}

    public static MinVersion minVersion(String spec) {
        String s = spec.strip();
        if (s.isEmpty() || Set.of("*", "x", "X", "latest", "next").contains(s)) return new MinVersion(null, false, Phrase.of("reason.unpinned", spec));
        if (NON_REGISTRY.matcher(s).lookingAt() || GITHUB_SHORTHAND.matcher(s).matches()) return new MinVersion(null, false, Phrase.of("reason.nonRegistry"));
        String first = s.split("\\|\\|")[0].strip();
        if (first.startsWith("<")) return new MinVersion(null, false, Phrase.of("reason.noLowerBound"));
        var m = RANGE_VERSION.matcher(first);
        if (!m.find()) return new MinVersion(null, false, Phrase.of("reason.unparseableRange"));
        var nums = new ArrayList<String>();
        for (int g = 1; g <= 3; g++) {
            String p = m.group(g);
            nums.add(p != null && p.chars().allMatch(Character::isDigit) ? p : "0");
        }
        String v = String.join(".", nums) + Objects.toString(m.group(4), "");
        return new MinVersion(v, EXACT.matcher(first).matches(), null);
    }

    public static void scan(List<Path> packageJsons, Path root, DependencyCollector col, Consumer<Phrase> warn) {
        var doneLocks = new HashSet<Path>();
        for (Path pkgPath : packageJsons) {
            Map<String, Object> pkg;
            try {
                pkg = Json.obj(Json.parse(ProjectFiles.readText(pkgPath)));
            } catch (IOException | IllegalArgumentException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(pkgPath), e.getMessage()));
                continue;
            }
            var declared = new LinkedHashMap<String, String[]>();   // name -> {spec, section}
            for (String sec : List.of("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
                Json.obj(pkg.get(sec)).forEach((n, spec) -> {
                    if (spec instanceof String s) declared.putIfAbsent(n, new String[]{s, sec});
                });

            Path lock = findLock(pkgPath.getParent(), root);
            if (lock != null) {
                if (!doneLocks.add(lock)) continue;   // workspace member, already covered by the root lockfile
                try {
                    String base = lock.getFileName().toString();
                    var entries = switch (base) {
                        case "yarn.lock" -> yarnLock(lock, declared.keySet());
                        case "pnpm-lock.yaml" -> pnpmLock(lock, declared.keySet());
                        default -> packageLock(lock, declared.keySet());
                    };
                    for (var e : entries) {
                        if (!Versions.isSemver(e.version())) {
                            col.miss(Ecosystem.NPM, e.name(), e.version(), lock, Phrase.of("reason.nonRegistryLock"));
                            continue;
                        }
                        col.add(Ecosystem.NPM, e.name(), e.version(), lock, (e.direct() ? "direct" : "transitive") + (e.dev() ? " (dev)" : ""), false);
                    }
                    continue;
                } catch (IOException | IllegalArgumentException e) {
                    warn.accept(Phrase.of("warning.lockUnreadable", col.rel(lock), e.getMessage()));
                }
            }
            declared.forEach((declaredName, specAndSection) -> {
                String name = declaredName, spec = specAndSection[0];
                if (spec.startsWith("npm:")) {                     // "alias": "npm:real-name@^1.0.0"
                    String target = spec.substring(4);
                    int at = target.lastIndexOf('@');
                    name = at > 0 ? target.substring(0, at) : target;
                    spec = at > 0 ? target.substring(at + 1) : "";
                }
                var mv = minVersion(spec);
                if (mv.version() != null) col.add(Ecosystem.NPM, name, mv.version(), pkgPath, specAndSection[1], !mv.exact());
                else col.miss(Ecosystem.NPM, name, specAndSection[0], pkgPath, mv.reason());
            });
        }
    }

    private static Path findLock(Path dir, Path root) {
        for (Path d = dir.toAbsolutePath().normalize(); d != null; d = d.getParent()) {
            for (String name : LOCKFILES) {
                Path p = d.resolve(name);
                if (Files.isRegularFile(p)) return p;
            }
            if (d.equals(root)) break;
        }
        return null;
    }

    private static List<LockEntry> packageLock(Path path, Set<String> declared) throws IOException {
        var data = Json.obj(Json.parse(ProjectFiles.readText(path)));
        var out = new ArrayList<LockEntry>();
        if (data.get("packages") instanceof Map<?, ?>) {
            Json.obj(data.get("packages")).forEach((key, value) -> {
                var info = Json.obj(value);
                if (key.isEmpty() || !key.contains("node_modules/") || Boolean.TRUE.equals(info.get("link"))) return;
                String keyName = key.substring(key.lastIndexOf("node_modules/") + "node_modules/".length());
                String name = Objects.requireNonNullElse(Json.str(info, "name"), keyName);
                String version = Json.str(info, "version");
                if (version != null)
                    out.add(new LockEntry(name, version, Boolean.TRUE.equals(info.get("dev")),
                            key.equals("node_modules/" + keyName) && declared.contains(keyName)));
            });
        } else {
            walkV1(Json.obj(data.get("dependencies")), 0, declared, out);
        }
        return out;
    }

    private static void walkV1(Map<String, Object> deps, int depth, Set<String> declared, List<LockEntry> out) {
        deps.forEach((name, value) -> {
            var info = Json.obj(value);
            String version = Objects.requireNonNullElse(Json.str(info, "version"), "");
            String real = name;
            if (version.startsWith("npm:")) {
                String target = version.substring(4);
                int at = target.lastIndexOf('@');
                real = target.substring(0, Math.max(at, 0));
                version = target.substring(at + 1);
            }
            out.add(new LockEntry(real, version, Boolean.TRUE.equals(info.get("dev")), depth == 0 && declared.contains(name)));
            walkV1(Json.obj(info.get("dependencies")), depth + 1, declared, out);
        });
    }

    private static List<LockEntry> yarnLock(Path path, Set<String> declared) throws IOException {
        var out = new ArrayList<LockEntry>();
        // the packages an entry resolves, each with whether it is declared — under its own name or an npm: alias's
        var names = new LinkedHashMap<String, Boolean>();
        for (String line : ProjectFiles.readText(path).lines().toList()) {
            if (line.isBlank() || line.strip().startsWith("#")) continue;
            if (!Character.isWhitespace(line.charAt(0))) {
                names.clear();
                String header = line.strip();
                if (header.endsWith(":")) header = header.substring(0, header.length() - 1);
                for (String spec : header.split(",")) {
                    spec = spec.strip().replace("\"", "");
                    if (spec.isEmpty() || spec.startsWith("__metadata")) continue;
                    if (spec.contains("@npm:")) {
                        String alias = spec.substring(0, spec.indexOf("@npm:")), target = spec.substring(spec.indexOf("@npm:") + 5);
                        int at = target.lastIndexOf('@');
                        names.merge(at > 0 ? target.substring(0, at) : alias, declared.contains(alias), Boolean::logicalOr);
                    } else {
                        int at = spec.lastIndexOf('@');
                        if (at > 0) names.merge(spec.substring(0, at), declared.contains(spec.substring(0, at)), Boolean::logicalOr);
                    }
                }
            } else {
                var m = YARN_VERSION.matcher(line);
                if (m.lookingAt() && !names.isEmpty()) {
                    names.forEach((n, direct) -> out.add(new LockEntry(n, m.group(1), false, direct)));
                    names.clear();
                }
            }
        }
        return out;
    }

    private static List<LockEntry> pnpmLock(Path path, Set<String> declared) throws IOException {
        var out = new ArrayList<LockEntry>();
        String section = null;
        for (String line : ProjectFiles.readText(path).lines().toList()) {
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0))) {
                section = line.split(":")[0].strip();
                continue;
            }
            if ("packages".equals(section) || "snapshots".equals(section)) {
                var m = PNPM_KEY.matcher(line);
                if (m.find()) out.add(new LockEntry(m.group(1), m.group(2), false, declared.contains(m.group(1))));
            }
        }
        return out;
    }
}
