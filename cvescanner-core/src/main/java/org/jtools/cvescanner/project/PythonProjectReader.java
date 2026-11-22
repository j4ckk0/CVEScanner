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
import java.util.Objects;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;

/**
 * Python projects, per folder: a lockfile when there is one (poetry.lock, uv.lock, Pipfile.lock), its versions exact,
 * the packages pyproject.toml or the Pipfile declares said direct, the others transitive; else requirements*.txt and
 * pyproject.toml (or a Pipfile), a pinned version exact, a range's lowest approximate (≈). Names are kept as written:
 * matching compares them in their PEP 503 form.
 */
public final class PythonProjectReader {

    /** A requirement: its name, then its extras, its version specifiers, a URL or a marker after. */
    private static final Pattern REQUIREMENT = Pattern.compile("^([A-Za-z0-9][A-Za-z0-9._-]*)\\s*(?:\\[[^]]*])?\\s*(.*)$");
    private static final Pattern SPECIFIER = Pattern.compile("(===|==|~=|>=|<=|!=|>|<)\\s*([^\\s,;]+)");

    private PythonProjectReader() {}

    /** A version as a specifier gives it: exact, or the lowest a range allows (approximate); or why there is none. */
    record Version(String version, boolean exact, Phrase reason) {}

    public static void scan(List<Path> files, DependencyCollector col, Consumer<Phrase> warn) {
        var byFolder = new TreeMap<Path, List<Path>>();
        for (Path f : files) byFolder.computeIfAbsent(f.getParent(), _ -> new ArrayList<>()).add(f);
        for (var e : byFolder.entrySet()) folder(e.getKey(), e.getValue(), col, warn);
    }

    /** What this reads of a file, or null when it cannot: said, the folder's other files read. */
    private interface Read<T> {
        T from(Path file) throws IOException;
    }

    private static <T> T read(Path file, Read<T> how, DependencyCollector col, Consumer<Phrase> warn) {
        try {
            return how.from(file);
        } catch (IOException | RuntimeException ex) {
            warn.accept(Phrase.of("warning.skipped", col.rel(file), String.valueOf(ex.getMessage())));
            return null;
        }
    }

    private static void folder(Path dir, List<Path> files, DependencyCollector col, Consumer<Phrase> warn) {
        Path pyproject = dir.resolve("pyproject.toml"), pipfile = dir.resolve("Pipfile");
        Map<String, Object> project = files.contains(pyproject) ? read(pyproject, f -> TomlLite.parse(ProjectFiles.readText(f)), col, warn) : null;
        Map<String, Object> pipenv = files.contains(pipfile) ? read(pipfile, f -> TomlLite.parse(ProjectFiles.readText(f)), col, warn) : null;
        if (project == null) project = Map.of();
        if (pipenv == null) pipenv = Map.of();
        // what the project declares, in PEP 503 form, and which of it is for development only
        var declared = new HashSet<String>();
        var dev = new HashSet<String>();
        declaredNames(project, pipenv, declared, dev);
        for (String lock : List.of("poetry.lock", "uv.lock", "Pipfile.lock")) {
            Path file = dir.resolve(lock);
            if (!files.contains(file)) continue;
            // read into a collector of its own: a lockfile that cannot be read leaves no half of its rows
            var locked = new DependencyCollector(col.root);
            boolean read = read(file, f -> {
                if (lock.equals("Pipfile.lock")) pipfileLock(f, declared, locked);
                else tomlLock(f, lock.equals("uv.lock"), declared, dev, locked);
                return Boolean.TRUE;
            }, col, warn) != null;
            if (!read) continue;   // the next lockfile, else the folder's manifests
            locked.deps.forEach(col::add);
            col.unresolved.addAll(locked.unresolved);
            return;   // with a lockfile, its versions: the folder's requirements and declarations are not read again
        }
        // requirements first: a package they pin is not given again at a declaration's lower bound
        var pinned = new HashSet<String>();
        for (Path f : files)
            if (f.getFileName().toString().endsWith(".txt"))
                read(f, file -> { requirements(file, col, pinned, new HashSet<>()); return Boolean.TRUE; }, col, warn);
        if (!project.isEmpty()) pyproject(pyproject, project, col, pinned);
        else if (!pipenv.isEmpty()) pipfile(pipfile, pipenv, col, pinned);
    }

    // ------------------------------------------------------------------------------------------- lockfiles

    /**
     * poetry.lock or uv.lock: [[package]] name and version; uv's own project (its source the folder) left out. What each
     * package depends on gives the packages that bring it, from the declared ones.
     */
    private static void tomlLock(Path file, boolean uv, Set<String> declared, Set<String> dev, DependencyCollector col) throws IOException {
        var packages = Json.arr(TomlLite.parse(ProjectFiles.readText(file)).get("package"));
        Map<String, List<String>> paths = lockPaths(packages, uv, declared);
        for (Object p : packages) {
            var pkg = Json.obj(p);
            String name = Json.str(pkg, "name"), version = Json.str(pkg, "version");
            if (name == null) continue;
            var source = Json.obj(pkg.get("source"));
            if (uv && (".".equals(Json.str(source, "editable")) || ".".equals(Json.str(source, "virtual")))) continue;
            if (version == null || source.containsKey("git") || source.containsKey("path") || source.containsKey("url")
                    || source.containsKey("directory") || (source.containsKey("editable") || source.containsKey("virtual"))) {
                col.miss(Ecosystem.PYPI, name, version == null ? "" : version, file, Phrase.of("reason.nonRegistry"));
                continue;
            }
            String norm = Ecosystem.pep503(name);
            boolean isDev = dev.contains(norm) || "dev".equals(Json.str(pkg, "category"));
            boolean direct = declared.contains(norm);
            col.add(Ecosystem.PYPI, name, version, file, scope(direct, isDev), direct ? List.of() : paths.get(norm + "@" + version));
        }
    }

    /** Each locked package's parents, "name@version", by its PEP 503 name and version: the walk from the declared ones. */
    private static Map<String, List<String>> lockPaths(List<Object> packages, boolean uv, Set<String> declared) {
        var idOf = new HashMap<String, String>();   // PEP 503 name -> its first "name@version"
        for (Object p : packages) {
            var pkg = Json.obj(p);
            String name = Json.str(pkg, "name"), version = Json.str(pkg, "version");
            if (name != null && version != null) idOf.putIfAbsent(Ecosystem.pep503(name), Ecosystem.pep503(name) + "@" + version);
        }
        var children = new HashMap<String, List<String>>();
        for (Object p : packages) {
            var pkg = Json.obj(p);
            String id = idOf.get(Ecosystem.pep503(Objects.requireNonNullElse(Json.str(pkg, "name"), "")));
            if (id == null) continue;
            var names = new ArrayList<String>();
            if (uv) for (Object d : Json.arr(pkg.get("dependencies"))) names.add(Json.str(Json.obj(d), "name"));
            else names.addAll(Json.obj(pkg.get("dependencies")).keySet());
            var kids = children.computeIfAbsent(id, _ -> new ArrayList<>());
            for (String n : names)
                if (n != null && idOf.containsKey(Ecosystem.pep503(n))) kids.add(idOf.get(Ecosystem.pep503(n)));
        }
        var roots = declared.stream().sorted().map(idOf::get).filter(Objects::nonNull).toList();
        var paths = DependencyGraph.paths(roots, children);
        // shown as the lockfile names them, not by their PEP 503 form
        var shown = new HashMap<String, String>();
        for (Object p : packages) {
            var pkg = Json.obj(p);
            String name = Json.str(pkg, "name"), version = Json.str(pkg, "version");
            if (name != null && version != null) shown.putIfAbsent(Ecosystem.pep503(name) + "@" + version, name + "@" + version);
        }
        var out = new HashMap<String, List<String>>();
        paths.forEach((id, path) -> out.put(id, path.stream().map(x -> shown.getOrDefault(x, x)).toList()));
        return out;
    }

    /** Pipfile.lock: "default" and "develop", each package's "version": "==1.2.3". */
    private static void pipfileLock(Path file, Set<String> declared, DependencyCollector col) throws IOException {
        var lock = Json.obj(Json.parse(ProjectFiles.readText(file)));
        for (String section : List.of("default", "develop"))
            for (var e : Json.obj(lock.get(section)).entrySet()) {
                String version = Json.str(Json.obj(e.getValue()), "version");
                if (version == null || !version.startsWith("==")) {
                    col.miss(Ecosystem.PYPI, e.getKey(), version == null ? "" : version, file, Phrase.of("reason.nonRegistry"));
                    continue;
                }
                // Pipfile.lock does not say what brings a package: its parents not recorded
                boolean direct = declared.contains(Ecosystem.pep503(e.getKey()));
                col.add(Ecosystem.PYPI, e.getKey(), version.substring(2).strip(), file, scope(direct, section.equals("develop")),
                        direct ? List.of() : null);
            }
    }

    private static String scope(boolean direct, boolean dev) {
        return (direct ? "direct" : "transitive") + (dev ? " (dev)" : "");
    }

    /** The names pyproject.toml (PEP 621, Poetry) and the Pipfile declare; those for development apart. */
    private static void declaredNames(Map<String, Object> project, Map<String, Object> pipenv, Set<String> declared, Set<String> dev) {
        var pep621 = Json.obj(project.get("project"));
        for (Object r : Json.arr(pep621.get("dependencies"))) nameOf(r).ifPresent(declared::add);
        for (Object list : Json.obj(pep621.get("optional-dependencies")).values())
            for (Object r : Json.arr(list)) nameOf(r).ifPresent(declared::add);
        for (var e : Json.obj(project.get("dependency-groups")).entrySet())   // PEP 735: uv's dev group
            for (Object r : Json.arr(e.getValue())) nameOf(r).ifPresent(n -> { declared.add(n); if (e.getKey().equals("dev")) dev.add(n); });
        var poetry = Json.obj(Json.obj(project.get("tool")).get("poetry"));
        for (String n : Json.obj(poetry.get("dependencies")).keySet()) declared.add(Ecosystem.pep503(n));
        for (String n : Json.obj(poetry.get("dev-dependencies")).keySet()) { declared.add(Ecosystem.pep503(n)); dev.add(Ecosystem.pep503(n)); }
        for (var g : Json.obj(poetry.get("group")).entrySet())
            for (String n : Json.obj(Json.obj(g.getValue()).get("dependencies")).keySet()) {
                declared.add(Ecosystem.pep503(n));
                if (!g.getKey().equals("main")) dev.add(Ecosystem.pep503(n));
            }
        for (String n : Json.obj(pipenv.get("packages")).keySet()) declared.add(Ecosystem.pep503(n));
        for (String n : Json.obj(pipenv.get("dev-packages")).keySet()) { declared.add(Ecosystem.pep503(n)); dev.add(Ecosystem.pep503(n)); }
    }

    private static java.util.Optional<String> nameOf(Object requirement) {
        if (!(requirement instanceof String r)) return java.util.Optional.empty();
        Matcher m = REQUIREMENT.matcher(r.strip());
        return m.matches() ? java.util.Optional.of(Ecosystem.pep503(m.group(1))) : java.util.Optional.empty();
    }

    // ------------------------------------------------------------------------------------------- manifests

    /** A requirements file: one requirement a line, -r followed (once each), options, comments, hashes and markers left. */
    private static void requirements(Path file, DependencyCollector col, Set<String> pinned, Set<Path> seen) throws IOException {
        if (!seen.add(file.toAbsolutePath().normalize()) || !Files.isRegularFile(file)) return;
        String text = ProjectFiles.readText(file).replaceAll("\\\\\\r?\\n", " ");   // a line continued
        for (String raw : text.split("\\R")) {
            String line = raw.replaceAll("(^|\\s)#.*$", "").strip();
            if (line.isEmpty()) continue;
            var include = Pattern.compile("^(?:-r|--requirement)[\\s=]+(\\S+)").matcher(line);
            if (include.find()) {
                requirements(file.resolveSibling(include.group(1)), col, pinned, seen);
                continue;
            }
            if (line.startsWith("-e ") || line.startsWith("--editable")) {
                var egg = Pattern.compile("#egg=([A-Za-z0-9._-]+)").matcher(raw);
                if (egg.find()) col.miss(Ecosystem.PYPI, egg.group(1), line, file, Phrase.of("reason.nonRegistry"));
                continue;
            }
            if (line.startsWith("-")) continue;   // --index-url, -c constraints, --hash on a line of its own…
            if (line.matches("^(?:git|hg|svn|bzr)\\+.*|^[a-z]+://.*")) {   // a VCS or a URL: named only by #egg=
                var egg = Pattern.compile("#egg=([A-Za-z0-9._-]+)").matcher(line);
                if (egg.find()) col.miss(Ecosystem.PYPI, egg.group(1), line, file, Phrase.of("reason.nonRegistry"));
                continue;
            }
            line = line.replaceAll("\\s--hash[=\\s]\\S+", "").strip();
            requirement(line, file, "requirements", col, pinned, true);
        }
    }

    /** pyproject.toml: PEP 621's dependencies and optional ones; Poetry's dependencies and groups. */
    private static void pyproject(Path file, Map<String, Object> project, DependencyCollector col, Set<String> pinned) {
        var pep621 = Json.obj(project.get("project"));
        for (Object r : Json.arr(pep621.get("dependencies"))) if (r instanceof String s) requirement(s, file, "dependencies", col, pinned, false);
        for (var e : Json.obj(pep621.get("optional-dependencies")).entrySet())
            for (Object r : Json.arr(e.getValue())) if (r instanceof String s) requirement(s, file, "optional:" + e.getKey(), col, pinned, false);
        var poetry = Json.obj(Json.obj(project.get("tool")).get("poetry"));
        poetrySection(Json.obj(poetry.get("dependencies")), file, "dependencies", col, pinned);
        poetrySection(Json.obj(poetry.get("dev-dependencies")), file, "group:dev", col, pinned);
        for (var g : Json.obj(poetry.get("group")).entrySet())
            poetrySection(Json.obj(Json.obj(g.getValue()).get("dependencies")), file, "group:" + g.getKey(), col, pinned);
    }

    /** The Pipfile of a project without its lockfile: [packages] and [dev-packages]. */
    private static void pipfile(Path file, Map<String, Object> pipenv, DependencyCollector col, Set<String> pinned) {
        poetrySection(Json.obj(pipenv.get("packages")), file, "packages", col, pinned);
        poetrySection(Json.obj(pipenv.get("dev-packages")), file, "dev-packages", col, pinned);
    }

    /** name = "^1.2" or name = { version = "^1.2", … }; a git, path or url source is not a registry's. */
    private static void poetrySection(Map<String, Object> section, Path file, String scope, DependencyCollector col, Set<String> pinned) {
        for (var e : section.entrySet()) {
            String name = e.getKey();
            if (name.equalsIgnoreCase("python")) continue;
            String spec;
            if (e.getValue() instanceof String s) spec = s;
            else {
                var t = Json.obj(e.getValue());
                if (t.containsKey("git") || t.containsKey("path") || t.containsKey("url") || t.containsKey("file")) {
                    col.miss(Ecosystem.PYPI, name, "", file, Phrase.of("reason.nonRegistry"));
                    continue;
                }
                spec = Json.str(t, "version");
                if (spec == null) {
                    col.miss(Ecosystem.PYPI, name, "", file, Phrase.of("reason.noVersion"));
                    continue;
                }
            }
            String norm = Ecosystem.pep503(name);
            if (pinned.contains(norm)) continue;
            emit(name, poetryVersion(spec.strip()), spec, file, scope, col, pinned);
        }
    }

    /** A PEP 508 requirement: name[extras] specifiers ; marker, or name @ url. */
    private static void requirement(String text, Path file, String scope, DependencyCollector col, Set<String> pinned, boolean pins) {
        String r = text.contains(";") ? text.substring(0, text.indexOf(';')).strip() : text.strip();
        Matcher m = REQUIREMENT.matcher(r);
        if (!m.matches()) return;   // a URL alone, a path: no name to check
        String name = m.group(1), rest = m.group(2).strip();
        String norm = Ecosystem.pep503(name);
        if (rest.startsWith("@")) {
            col.miss(Ecosystem.PYPI, name, rest, file, Phrase.of("reason.nonRegistry"));
            return;
        }
        if (!pins && pinned.contains(norm)) return;
        Version v = pep440Version(rest.replaceAll("^\\(|\\)$", ""));
        if (pins && v.exact()) pinned.add(norm);
        emit(name, v, rest, file, scope, col, pinned);
    }

    private static void emit(String name, Version v, String declared, Path file, String scope, DependencyCollector col, Set<String> pinned) {
        if (v.version() == null) col.miss(Ecosystem.PYPI, name, declared, file, v.reason());
        else col.add(Ecosystem.PYPI, name, v.version(), file, scope, !v.exact());
    }

    /** PEP 440 specifiers: ==1.2.3 exact; >=, ~=, > their version, approximate; only an upper bound, none; none, unpinned. */
    static Version pep440Version(String specifiers) {
        if (specifiers.isBlank() || specifiers.equals("*")) return new Version(null, false, Phrase.of("reason.unpinned", specifiers.isBlank() ? "*" : specifiers));
        String lowest = null;
        boolean upper = false;
        Matcher m = SPECIFIER.matcher(specifiers);
        boolean any = false;
        while (m.find()) {
            any = true;
            String op = m.group(1), v = m.group(2);
            switch (op) {
                case "==", "===" -> {
                    if (!v.contains("*")) return new Version(v, true, null);
                    lowest = v.replaceAll("\\.?\\*$", "");   // ==1.2.*: from 1.2
                }
                case ">=", "~=", ">" -> lowest = v;
                case "<", "<=" -> upper = true;
                default -> { }   // != excludes, says nothing of the lowest
            }
        }
        if (!any) return new Version(null, false, Phrase.of("reason.unparseableRange"));
        if (lowest != null) return new Version(lowest, false, null);
        return new Version(null, false, Phrase.of(upper ? "reason.noLowerBound" : "reason.unparseableRange"));
    }

    /** Poetry's: ^1.2 and ~1.2 from 1.2 (approximate), 1.2.3 exact, * unpinned, PEP 440's otherwise. */
    static Version poetryVersion(String spec) {
        if (spec.equals("*") || spec.isBlank()) return new Version(null, false, Phrase.of("reason.unpinned", spec.isBlank() ? "*" : spec));
        if (spec.startsWith("^") || (spec.startsWith("~") && !spec.startsWith("~="))) {
            String v = spec.substring(1).strip();
            return v.isEmpty() ? new Version(null, false, Phrase.of("reason.unparseableRange")) : new Version(v, false, null);
        }
        if (spec.matches("\\d[\\w.!+-]*")) return new Version(spec, true, null);
        if (spec.matches("\\d[\\w.]*\\.\\*")) return new Version(spec.replaceAll("\\.\\*$", ""), false, null);
        return pep440Version(spec);
    }
}
