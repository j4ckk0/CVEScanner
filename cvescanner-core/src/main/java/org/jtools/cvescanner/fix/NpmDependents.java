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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * What a lockfile says of a package a project only has through others: the versions of it locked, and the ranges its
 * dependents ask of the vulnerable one, so that an override to the fixed version is known to keep within them. pnpm's
 * lockfile keeps only versions: its dependents' ranges are read from their package.json once the project is installed.
 */
final class NpmDependents {

    /** A range asked of the package; by whom when the lockfile says ("mkdirp@0.5.5"), else null. */
    record Asked(String by, String range) {}

    /**
     * @param locked      every version of the package the lockfile holds
     * @param asked       the ranges asked of the vulnerable version
     * @param rangesKnown false when some dependent's range could not be read
     * @param descriptors yarn's: the specs the vulnerable entry is locked under ("minimist@npm:^1.2.5")
     */
    record Found(Set<String> locked, List<Asked> asked, boolean rangesKnown, List<String> descriptors) {}

    private static final Pattern YARN_VERSION = Pattern.compile("^\\s+version:?\\s+\"?([^\"\\s]+)\"?\\s*$");
    /** A pnpm package key's name and version, its peers' suffix apart: 5.x's "_react@18.2.0", 6.0 on "(react@18.2.0)". */
    private static final Pattern PNPM_KEY = Pattern.compile("^  '?/?((?:@[^/@\\s]+/)?[^/@\\s(]+)[@/]([^(:_'\\s]+)(_[^(:'\\s]*)?(\\([^:]*\\))?'?:\\s*(\\{\\})?\\s*$");
    private static final Pattern PNPM_DEP = Pattern.compile("^      '?((?:@[^/@\\s]+/)?[^:'\\s]+)'?:\\s*'?([^(_'\\s]+)");

    private NpmDependents() {}

    static Found of(Path lockfile, String pkg, String from) throws IOException {
        String name = lockfile.getFileName().toString();
        String text = ProjectFiles.readText(lockfile);
        return switch (name) {
            case "yarn.lock" -> yarn(text, pkg, from);
            case "pnpm-lock.yaml" -> pnpm(text, pkg, from, lockfile.getParent());
            default -> packageLock(text, pkg, from);
        };
    }

    // ------------------------------------------------------------------------------- package-lock.json
    private static Found packageLock(String text, String pkg, String from) {
        var json = Json.obj(Json.parse(text));
        var locked = new LinkedHashSet<String>();
        var asked = new ArrayList<Asked>();
        Map<String, Object> packages = Json.obj(json.get("packages"));
        if (!packages.isEmpty()) {
            for (var e : packages.entrySet()) {
                if (pkg.equals(nameOf(e.getKey(), Json.obj(e.getValue())))) locked.add(Json.str(Json.obj(e.getValue()), "version"));
            }
            for (var e : packages.entrySet()) {
                if (e.getKey().isEmpty()) continue;   // the project: a range it asks is a direct dependency
                var info = Json.obj(e.getValue());
                String range = requested(info, "dependencies", "optionalDependencies", "peerDependencies", pkg);
                if (range == null) continue;
                // the copy this dependent uses: the nearest node_modules/<pkg> up from it
                String copy = null;
                for (String base = e.getKey(); copy == null; base = parentOf(base)) {
                    var candidate = Json.obj(packages.get((base.isEmpty() ? "" : base + "/") + "node_modules/" + pkg));
                    if (!candidate.isEmpty()) copy = Json.str(candidate, "version");
                    if (base.isEmpty()) break;
                }
                if (from.equals(copy)) asked.add(new Asked(nameOf(e.getKey(), info) + "@" + Json.str(info, "version"), range));
            }
        } else {
            walkV1(Json.obj(json.get("dependencies")), List.of(), pkg, from, locked, asked);
        }
        locked.remove(null);
        return new Found(locked, asked, true, List.of());
    }

    private static String nameOf(String key, Map<String, Object> info) {
        String n = Json.str(info, "name");
        if (n != null) return n;
        int at = key.lastIndexOf("node_modules/");
        return at < 0 ? key : key.substring(at + "node_modules/".length());
    }

    /** "node_modules/a/node_modules/b" → "node_modules/a"; a top one → "". */
    private static String parentOf(String key) {
        int at = key.lastIndexOf("/node_modules/");
        return at < 0 ? "" : key.substring(0, at);
    }

    private static String requested(Map<String, Object> info, String a, String b, String c, String pkg) {
        for (String section : List.of(a, b, c)) {
            String r = Json.str(Json.obj(info.get(section)), pkg);
            if (r != null) return r;
        }
        return null;
    }

    /** lockfileVersion 1: nested "dependencies", each entry's "requires" naming the ranges. */
    private static void walkV1(Map<String, Object> deps, List<Map<String, Object>> scopes, String pkg, String from,
                               Set<String> locked, List<Asked> asked) {
        var inner = new ArrayList<>(scopes);
        inner.addFirst(deps);
        for (var e : deps.entrySet()) {
            var info = Json.obj(e.getValue());
            if (e.getKey().equals(pkg)) locked.add(Json.str(info, "version"));
            String range = Json.str(Json.obj(info.get("requires")), pkg);
            if (range != null) {
                var own = Json.obj(info.get("dependencies"));
                String copy = own.containsKey(pkg) ? Json.str(Json.obj(own.get(pkg)), "version") : null;
                for (var scope : inner) if (copy == null && scope.containsKey(pkg)) copy = Json.str(Json.obj(scope.get(pkg)), "version");
                if (from.equals(copy)) asked.add(new Asked(e.getKey() + "@" + Json.str(info, "version"), range));
            }
            walkV1(Json.obj(info.get("dependencies")), inner, pkg, from, locked, asked);
        }
    }

    // ------------------------------------------------------------------------------- yarn.lock, 1 and 2+
    private static Found yarn(String text, String pkg, String from) {
        var locked = new LinkedHashSet<String>();
        var asked = new ArrayList<Asked>();
        var descriptors = new ArrayList<String>();
        List<String> specs = null;
        for (String line : text.split("\\R")) {
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0)) && !line.startsWith("#") && line.endsWith(":")) {
                specs = new ArrayList<>();
                for (String spec : line.substring(0, line.length() - 1).split(",")) {
                    String s = spec.strip();
                    if (s.startsWith("\"") && s.endsWith("\"")) s = s.substring(1, s.length() - 1);
                    if (pkg.equals(specName(s))) specs.add(s);
                }
                if (specs.isEmpty()) specs = null;
                continue;
            }
            Matcher v = YARN_VERSION.matcher(line);
            if (specs != null && v.matches()) {
                String version = v.group(1);
                locked.add(version);
                if (version.equals(from)) {
                    for (String s : specs) {
                        descriptors.add(s);
                        String range = s.substring(pkg.length() + 1);
                        asked.add(new Asked(null, range.startsWith("npm:") ? range.substring(4) : range));
                    }
                }
                specs = null;
            }
        }
        return new Found(locked, asked, true, descriptors);
    }

    /** The package a spec names: "minimist@^1.2.5" → minimist, "@scope/x@npm:1" → @scope/x. */
    private static String specName(String spec) {
        int at = spec.indexOf('@', spec.startsWith("@") ? 1 : 0);
        return at < 0 ? spec : spec.substring(0, at);
    }

    // ------------------------------------------------------------------------------- pnpm-lock.yaml
    private static Found pnpm(String text, String pkg, String from, Path project) throws IOException {
        var locked = new LinkedHashSet<String>();
        var dependents = new LinkedHashSet<List<String>>();   // [name, version, peers] of the entries depending on pkg@from
        List<String> entry = null;
        String section = "";
        boolean inDeps = false;
        for (String line : text.split("\\R")) {
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0))) {
                section = line.strip();
                entry = null;
                continue;
            }
            if (!section.equals("packages:") && !section.equals("snapshots:")) continue;
            Matcher k = PNPM_KEY.matcher(line);
            if (k.matches()) {
                String peers = k.group(3) != null ? k.group(3) : k.group(4) != null ? k.group(4) : "";
                entry = List.of(k.group(1), k.group(2), peers);
                if (k.group(1).equals(pkg)) locked.add(k.group(2));
                inDeps = false;
                continue;
            }
            if (line.matches("^    (dependencies|optionalDependencies):\\s*$")) {
                inDeps = true;
                continue;
            }
            if (line.matches("^    \\S.*")) inDeps = false;
            Matcher d = PNPM_DEP.matcher(line);
            if (entry != null && inDeps && d.find() && d.group(1).equals(pkg) && d.group(2).equals(from)) dependents.add(entry);
        }
        var asked = new ArrayList<Asked>();
        boolean known = true;
        for (var dependent : dependents) {
            String name = dependent.get(0), version = dependent.get(1);
            String range = null;
            for (String folder : List.of(storeFolder(name, version, dependent.get(2)), storeFolder(name, version, ""))) {
                Path manifest = project.resolve("node_modules").resolve(".pnpm").resolve(folder)
                        .resolve("node_modules").resolve(name).resolve("package.json");
                if (range == null && Files.isRegularFile(manifest))
                    range = requested(Json.obj(Json.parse(ProjectFiles.readText(manifest))), "dependencies", "optionalDependencies", "peerDependencies", pkg);
            }
            var a = new Asked(name + "@" + version, range);
            if (range == null) known = false;
            else if (!asked.contains(a)) asked.add(a);
        }
        return new Found(locked, asked, known, List.of());
    }

    /**
     * The folder of node_modules/.pnpm a package is installed in, as pnpm names it: "react-dom@18.2.0_react@18.2.0"
     * for 5.x's "_react@18.2.0" and 6.0 on's "(react@18.2.0)", a scope's slash written "+".
     */
    static String storeFolder(String name, String version, String peers) {
        String suffix = peers.startsWith("(") ? peers.replace(")(", "_").replace("(", "_").replaceFirst("\\)$", "") : peers;
        return (name + "@" + version + suffix).replace('/', '+');
    }
}
