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
    /** A need of a yarn.lock entry: v1's `name "range"`, berry's `name: "npm:range"`; the name quoted when scoped. */
    private static final Pattern YARN_NEED = Pattern.compile("\\s+\"?((?:@[^/\"\\s]+/)?[^\"\\s:]+)\"?:?\\s+\"?([^\"]*?)\"?\\s*");
    private static final Pattern PNPM_KEY = Pattern.compile("^ {2}['\"]?/?((?:@[^/@\\s'\"]+/)?[^/@\\s'\"]+)[@/](\\d[^:()\\s'\"]*)");

    /** @param parents the packages that bring it, "name@version", the declared one first; null when the lock does not say */
    record LockEntry(String name, String version, boolean dev, boolean direct, List<String> parents) {}

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
                        case "yarn.lock" -> yarnLock(lock, declared);
                        case "pnpm-lock.yaml" -> pnpmLock(lock, declared.keySet());
                        default -> packageLock(lock, declared.keySet());
                    };
                    for (var e : entries) {
                        if (!Versions.isSemver(e.version())) {
                            col.miss(Ecosystem.NPM, e.name(), e.version(), lock, Phrase.of("reason.nonRegistryLock"));
                            continue;
                        }
                        col.add(Ecosystem.NPM, e.name(), e.version(), lock, (e.direct() ? "direct" : "transitive") + (e.dev() ? " (dev)" : ""),
                                e.direct() ? List.of() : e.parents());
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
            var packages = Json.obj(data.get("packages"));
            var paths = packageLockPaths(packages);
            packages.forEach((key, value) -> {
                var info = Json.obj(value);
                if (key.isEmpty() || !key.contains("node_modules/") || Boolean.TRUE.equals(info.get("link"))) return;
                String keyName = key.substring(key.lastIndexOf("node_modules/") + "node_modules/".length());
                String name = Objects.requireNonNullElse(Json.str(info, "name"), keyName);
                String version = Json.str(info, "version");
                if (version != null)
                    out.add(new LockEntry(name, version, Boolean.TRUE.equals(info.get("dev")),
                            key.equals("node_modules/" + keyName) && declared.contains(keyName), shownPath(paths.get(key), packages)));
            });
            return nearest(out);
        }
        walkV1(Json.obj(data.get("dependencies")), 0, declared, out);
        return out;
    }

    /** One entry per package version, the copy installed nearest the project: npm installs one copy per place needed. */
    private static List<LockEntry> nearest(List<LockEntry> entries) {
        var kept = new LinkedHashMap<String, LockEntry>();
        for (var e : entries)
            kept.merge(e.name() + "@" + e.version(), e, (a, b) -> depth(b) < depth(a) ? b : a);
        return List.copyOf(kept.values());
    }

    private static int depth(LockEntry e) {
        return e.direct() ? -1 : e.parents() == null ? Integer.MAX_VALUE : e.parents().size();
    }

    /**
     * package-lock.json (v2, v3): what each installed package depends on, found as Node finds it (its own
     * node_modules, then its parents' up to the root); each package's parents, by its key, from the root's dependencies.
     */
    private static Map<String, List<String>> packageLockPaths(Map<String, Object> packages) {
        var children = new HashMap<String, List<String>>();
        packages.forEach((key, value) -> {
            var info = Json.obj(value);
            String from = Boolean.TRUE.equals(info.get("link")) && Json.str(info, "resolved") != null ? Json.str(info, "resolved") : key;
            var kids = new ArrayList<String>();
            for (String section : List.of("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")) {
                if (section.equals("devDependencies") && !key.isEmpty()) continue;   // a package's own are not installed
                for (String n : Json.obj(Json.obj(packages.get(from)).get(section)).keySet()) {
                    String found = installed(packages, from, n);
                    if (found != null && !kids.contains(found)) kids.add(found);
                }
            }
            children.put(key, kids);
        });
        // a link (a workspace's package) brings what its folder depends on
        packages.forEach((key, value) -> {
            var info = Json.obj(value);
            if (Boolean.TRUE.equals(info.get("link")) && Json.str(info, "resolved") != null) {
                String target = Json.str(info, "resolved");
                children.computeIfAbsent(target, _ -> new ArrayList<>()).addAll(children.getOrDefault(key, List.of()));
                children.put(key, List.of(target));
            }
        });
        // the root is not a package: the walk starts at what it depends on
        return DependencyGraph.paths(children.getOrDefault("", List.of()), children);
    }

    /** Where Node finds package n required from the package at this key: the nearest node_modules up to the root. */
    private static String installed(Map<String, Object> packages, String from, String n) {
        String base = from;
        while (true) {
            String candidate = (base.isEmpty() ? "" : base + "/") + "node_modules/" + n;
            if (packages.containsKey(candidate)) return candidate;
            if (base.isEmpty()) return null;
            int at = base.lastIndexOf("node_modules/");
            base = at <= 0 ? "" : base.substring(0, at - 1);
        }
    }

    /** The keys of a path as the packages they are, "name@version"; null stays null. */
    private static List<String> shownPath(List<String> keys, Map<String, Object> packages) {
        if (keys == null) return null;
        var out = new ArrayList<String>();
        for (String k : keys) {
            var info = Json.obj(packages.get(k));
            String keyName = k.contains("node_modules/") ? k.substring(k.lastIndexOf("node_modules/") + "node_modules/".length()) : k;
            String name = Objects.requireNonNullElse(Json.str(info, "name"), keyName);
            String version = Json.str(info, "version");
            out.add(version == null ? name : name + "@" + version);
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
            // a v1 lock nests packages where they are installed, not under what requires them: no parents said
            boolean direct = depth == 0 && declared.contains(name);
            out.add(new LockEntry(real, version, Boolean.TRUE.equals(info.get("dev")), direct, direct ? List.of() : null));
            walkV1(Json.obj(info.get("dependencies")), depth + 1, declared, out);
        });
    }

    /** A yarn.lock entry: the specs it resolves ("name@range"), its packages each with whether declared, what it needs. */
    private static final class YarnEntry {
        final List<String> specs = new ArrayList<>();
        final Map<String, Boolean> names = new LinkedHashMap<>();
        final List<String> needs = new ArrayList<>();   // "name@range", as the entry it resolves to is keyed
        String version;

        String id() {
            return names.keySet().iterator().next() + "@" + version;
        }
    }

    /** yarn.lock, v1 and berry: each entry's packages at its version, their parents from the declared ones' entries. */
    private static List<LockEntry> yarnLock(Path path, Map<String, String[]> declared) throws IOException {
        var entries = new ArrayList<YarnEntry>();
        YarnEntry entry = null;
        boolean inNeeds = false;
        for (String line : ProjectFiles.readText(path).lines().toList()) {
            if (line.isBlank() || line.strip().startsWith("#")) continue;
            if (!Character.isWhitespace(line.charAt(0))) {
                entry = new YarnEntry();
                inNeeds = false;
                String header = line.strip();
                if (header.endsWith(":")) header = header.substring(0, header.length() - 1);
                for (String spec : header.split(",")) {
                    spec = spec.strip().replace("\"", "");
                    // berry's entry of the project itself, or of a workspace: no package of the registry
                    if (spec.isEmpty() || spec.startsWith("__metadata") || spec.contains("@workspace:")) continue;
                    entry.specs.add(spec);
                    // the packages an entry resolves, each with whether it is declared — under its own name or an npm: alias's
                    if (spec.contains("@npm:")) {
                        String alias = spec.substring(0, spec.indexOf("@npm:")), target = spec.substring(spec.indexOf("@npm:") + 5);
                        int at = target.lastIndexOf('@');
                        entry.names.merge(at > 0 ? target.substring(0, at) : alias, declared.containsKey(alias), Boolean::logicalOr);
                    } else {
                        int at = spec.lastIndexOf('@');
                        if (at > 0) entry.names.merge(spec.substring(0, at), declared.containsKey(spec.substring(0, at)), Boolean::logicalOr);
                    }
                }
                if (!entry.names.isEmpty()) entries.add(entry);
                continue;
            }
            if (entry == null) continue;
            int indent = line.length() - line.stripLeading().length();
            if (indent <= 2) {
                inNeeds = line.strip().matches("(dependencies|optionalDependencies):?");
                var m = YARN_VERSION.matcher(line);
                if (entry.version == null && m.lookingAt()) entry.version = m.group(1);
            } else if (inNeeds) {
                var m = YARN_NEED.matcher(line);
                if (m.matches()) entry.needs.add(m.group(1) + "@" + m.group(2));
            }
        }
        var bySpec = new HashMap<String, String>();
        var children = new HashMap<String, List<String>>();
        for (var e : entries) {
            if (e.version == null) continue;
            for (String spec : e.specs) bySpec.putIfAbsent(spec, e.id());
        }
        for (var e : entries) {
            if (e.version == null) continue;
            var kids = children.computeIfAbsent(e.id(), _ -> new ArrayList<>());
            for (String need : e.needs) {
                String id = yarnResolve(bySpec, need);
                if (id != null) kids.add(id);
            }
        }
        var roots = new ArrayList<String>();
        declared.forEach((name, specAndSection) -> {
            String id = yarnResolve(bySpec, name + "@" + specAndSection[0]);
            if (id != null) roots.add(id);
        });
        var paths = DependencyGraph.paths(roots, children);
        var out = new ArrayList<LockEntry>();
        for (var e : entries) {
            if (e.version == null) continue;
            // direct: the version a declaration resolves to, not another version of a declared name
            boolean declaredOne = roots.contains(e.id());
            e.names.forEach((n, named) -> out.add(new LockEntry(n, e.version, false, named && declaredOne, paths.get(e.id()))));
        }
        return out;
    }

    /** The entry a "name@range" resolves to: keyed so in v1, "name@npm:range" in berry. */
    private static String yarnResolve(Map<String, String> bySpec, String need) {
        String id = bySpec.get(need);
        if (id != null) return id;
        int at = need.lastIndexOf('@');
        return at > 0 ? bySpec.get(need.substring(0, at) + "@npm:" + need.substring(at + 1)) : null;
    }

    /**
     * pnpm-lock.yaml (v5 to v9): its packages at their versions, their parents from what each needs, from the root
     * project's dependencies (importer "." or, before importers, the top-level ones).
     */
    private static List<LockEntry> pnpmLock(Path path, Set<String> declared) throws IOException {
        var found = new LinkedHashMap<String, String[]>();   // id "name@version" -> {name, version}
        var children = new HashMap<String, List<String>>();
        var roots = new ArrayList<String>();
        String section = null, current = null, importer = null, rootDep = null;
        boolean inNeeds = false, inImporterDeps = false;
        for (String line : ProjectFiles.readText(path).lines().toList()) {
            if (line.isBlank() || line.strip().startsWith("#")) continue;
            int indent = line.length() - line.stripLeading().length();
            String content = line.strip();
            if (indent == 0) {
                section = content.split(":")[0].strip();
                current = importer = rootDep = null;
                inNeeds = inImporterDeps = false;
                continue;
            }
            if ("packages".equals(section) || "snapshots".equals(section)) {
                if (indent == 2) {
                    var m = PNPM_KEY.matcher(line);
                    current = m.find() ? m.group(1) + "@" + m.group(2) : null;
                    if (current != null) found.putIfAbsent(current, new String[]{m.group(1), m.group(2)});
                    inNeeds = false;
                } else if (indent == 4) {
                    inNeeds = content.equals("dependencies:") || content.equals("optionalDependencies:");
                } else if (indent == 6 && inNeeds && current != null) {
                    String id = pnpmNeed(content);
                    if (id != null) children.computeIfAbsent(current, _ -> new ArrayList<>()).add(id);
                }
            } else if ("importers".equals(section)) {
                if (indent == 2) {
                    importer = unquote(content.substring(0, Math.max(content.indexOf(':'), 0)));
                } else if (indent == 4) {
                    inImporterDeps = content.matches("(dependencies|devDependencies|optionalDependencies):");
                } else if (indent == 6 && inImporterDeps && ".".equals(importer)) {
                    rootDep = content;
                    String id = pnpmNeed(content);   // v5's "name: version" on one line
                    if (id != null) roots.add(id);
                } else if (indent == 8 && inImporterDeps && ".".equals(importer) && rootDep != null && content.startsWith("version:")) {
                    String id = pnpmNeed(rootDep.substring(0, rootDep.indexOf(':')) + ": " + content.substring(8).strip());
                    if (id != null) roots.add(id);
                }
            } else if ("dependencies".equals(section) || "devDependencies".equals(section) || "optionalDependencies".equals(section)) {
                if (indent == 2) {
                    rootDep = content;
                    String id = pnpmNeed(content);
                    if (id != null) roots.add(id);
                } else if (indent == 4 && rootDep != null && content.startsWith("version:")) {
                    String id = pnpmNeed(rootDep.substring(0, rootDep.indexOf(':')) + ": " + content.substring(8).strip());
                    if (id != null) roots.add(id);
                }
            }
        }
        var paths = DependencyGraph.paths(roots, children);
        var out = new ArrayList<LockEntry>();
        // direct: the version the project's declaration resolves to, not another version of a declared name
        found.forEach((id, nv) -> out.add(new LockEntry(nv[0], nv[1], false,
                declared.contains(nv[0]) && (roots.contains(id) || roots.isEmpty()), paths.get(id))));
        return out;
    }

    /** "name: version" as pnpm writes a need: the version without its peers' suffix, "(react@18.2.0)" or "_react@18.2.0". */
    private static String pnpmNeed(String content) {
        int colon = content.indexOf(": ");
        if (colon < 0 && content.startsWith("'@")) colon = content.indexOf("': ") + 1;
        if (colon <= 0) return null;
        String name = unquote(content.substring(0, colon).strip()), value = unquote(content.substring(colon + 1).strip());
        if (value.startsWith("link:") || value.startsWith("file:") || value.isEmpty()) return null;
        if (value.startsWith("/") || !Character.isDigit(value.charAt(0))) {   // an alias: "/real@1.0.0", "real@1.0.0"
            var m = PNPM_KEY.matcher("  " + value);
            return m.find() ? m.group(1) + "@" + m.group(2) : null;
        }
        int cut = value.length();
        for (char c : new char[]{'(', '_'}) if (value.indexOf(c) > 0) cut = Math.min(cut, value.indexOf(c));
        return name + "@" + value.substring(0, cut);
    }

    private static String unquote(String s) {
        return s.length() >= 2 && (s.startsWith("'") || s.startsWith("\"")) ? s.substring(1, s.length() - 1) : s;
    }
}
