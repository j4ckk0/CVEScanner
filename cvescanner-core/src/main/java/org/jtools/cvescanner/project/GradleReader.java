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
import java.io.StringReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;

/**
 * Gradle builds: their declarations in build.gradle(.kts), version catalogs and gradle.properties; their lockfiles,
 * whose versions win (what Gradle resolved); else, given Gradle's cache, their transitive dependencies
 * (GradleTransitive), a platform's versions giving the version-less declarations theirs.
 */
public final class GradleReader {
    private static final Pattern DEP_STRING = Pattern.compile(
            "[\"']([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+):([^\"'\\s:@]+)(?::[A-Za-z0-9_.\\-]+)?(?:@[A-Za-z0-9]+)?[\"']");
    private static final Pattern DEP_MAP = Pattern.compile(
            "group\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*name\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*version\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    /** "group:artifact", no version: a platform gives it one. */
    private static final Pattern DEP_NO_VERSION = Pattern.compile("[\"']([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+)[\"']");
    /** exclude(group = "x", module = "y"), exclude group: 'x', module: 'y': in the block after a declaration. */
    private static final Pattern EXCLUDE = Pattern.compile(
            "exclude\\s*\\(?\\s*((?:\\s*,?\\s*(?:group|module)\\s*[:=]\\s*[\"'][^\"']+[\"'])+)");
    private static final Pattern EXCLUDE_PART = Pattern.compile("(group|module)\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    /** libs.netty.codec.http: a catalog's library, by its accessor. */
    private static final Pattern CATALOG_REF = Pattern.compile("\\blibs\\.([A-Za-z0-9_.]+)");
    private static final List<Pattern> VARS = List.of(
            Pattern.compile("(?m)(?:^|[{;])\\s*(?:def\\s+|val\\s+|var\\s+|(?:project\\.)?ext\\.|extra\\[\\s*)?[\"']?([A-Za-z_][\\w.\\-]*)[\"']?\\s*\\]?\\s*(?::\\s*String\\s*)?=\\s*[\"']([^\"'$\\n]+)[\"']"),
            Pattern.compile("(?:set|put)\\(\\s*[\"']([A-Za-z_][\\w.\\-]*)[\"']\\s*,\\s*[\"']([^\"'$\\n]+)[\"']"),
            Pattern.compile("\\b([A-Za-z_]\\w*)\\s+by\\s+extra\\(\\s*[\"']([^\"'$\\n]+)[\"']"));
    private static final Pattern REF = Pattern.compile("\\$\\{([^}]+)\\}|\\$([A-Za-z_][\\w.]*)");
    private static final Pattern CONFIG = Pattern.compile("\\s*([A-Za-z_]\\w*)");
    private static final Pattern PAIR = Pattern.compile("([\\w.\\-]+)\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern SECTION = Pattern.compile("\\[([^\\]]+)\\]");
    private static final Pattern KEY_VALUE = Pattern.compile("(\"[^\"]+\"|[\\w.\\-]+)\\s*=\\s*(.+)");

    private GradleReader() {}

    static String stripComments(String t) {
        t = t.replaceAll("(?s)/\\*.*?\\*/", "");
        return t.replaceAll("(?m)(^|[\\s;])//.*$", "$1");
    }

    static Map<String, String> variables(String text) {
        var out = new HashMap<String, String>();
        for (Pattern p : VARS) {
            var m = p.matcher(text);
            while (m.find()) out.put(m.group(1), m.group(2));
        }
        return out;
    }

    static String resolve(String v, Map<String, String> vars) {
        for (int k = 0; k < 5; k++) {
            String next = REF.matcher(v).replaceAll(m -> {
                String key = m.group(1) != null ? m.group(1) : m.group(2);
                for (String cand : List.of(key, key.substring(key.lastIndexOf('.') + 1), key.replace("()", ""))) {
                    String val = vars.get(cand);
                    if (val != null) return Matcher.quoteReplacement(val);
                }
                return Matcher.quoteReplacement(m.group());
            });
            if (next.equals(v)) break;
            v = next;
        }
        return v;
    }


    /** A declaration of a build file: its version as written (null when none), its configuration, whether it is a platform. */
    record Decl(String group, String artifact, String raw, String config, String platform, boolean catalogRef, List<String> exclusions) {
        String ga() { return group + ":" + artifact; }
    }

    /** A library of a version catalog: its alias, coordinates, version (null when none). */
    record Lib(String alias, String group, String artifact, String version, Path catalog) {
        String ga() { return group + ":" + artifact; }

        /** How a build file names it: libs.netty.codec.http for netty-codec-http. */
        String accessor() { return alias.replaceAll("[-_.]", ".").toLowerCase(Locale.ROOT); }
    }

    /** A version as resolved, or null when it stays a variable or is dynamic (a range, 1.+, latest.release). */
    static String concrete(String raw, Map<String, String> vars) {
        if (raw == null) return null;
        String v = resolve(raw, vars).replaceAll("!+$", "");
        if (v.contains("$") || v.contains("+") || v.startsWith("latest.") || v.startsWith("[") || v.startsWith("(")) return null;
        return v;
    }

    private static void addDep(DependencyCollector col, String g, String a, String raw, Path path, String scope, Map<String, String> vars) {
        String name = g + ":" + a;
        String v = resolve(raw, vars).replaceAll("!+$", "");
        if (v.contains("$")) col.miss(Ecosystem.MAVEN, name, raw, path, Phrase.of("reason.gradleVariable"));
        else if (v.contains("+") || v.startsWith("latest.") || v.startsWith("[") || v.startsWith("("))
            col.miss(Ecosystem.MAVEN, name, raw, path, Phrase.of("reason.dynamicVersion"));
        else col.add(Ecosystem.MAVEN, name, v, path, scope, false);
    }

    /**
     * The scope a configuration gives its dependencies, as Maven says it: compile, runtime, provided, test; null for
     * what does not reach the program (classpath, annotation processors, an unknown word).
     */
    static String mavenScope(String config) {
        if (config == null) return null;
        String c = config.toLowerCase(Locale.ROOT);
        if (c.equals("classpath") || c.equals("unknown") || c.contains("annotationprocessor") || c.equals("kapt") || c.equals("ksp"))
            return null;
        if (c.startsWith("test")) return c.endsWith("implementation") || c.endsWith("only") || c.endsWith("api") || c.equals("testcompile") ? "test" : null;
        if (c.endsWith("compileonly") || c.endsWith("compileonlyapi")) return "provided";
        if (c.endsWith("runtimeonly") || c.equals("runtime")) return "runtime";
        if (c.endsWith("implementation") || c.endsWith("api") || c.equals("compile")) return "compile";
        return null;
    }

    public static void scan(List<Path> buildFiles, List<Path> propertyFiles, DependencyCollector col) throws IOException {
        scan(buildFiles, propertyFiles, List.of(), List.of(), col, _ -> { }, null);
    }

    /**
     * The builds' dependencies: with a lockfile, its versions (the declared ones direct, the others transitive); else
     * the declarations, and given Gradle's cache, what they bring.
     *
     * @param cache Gradle's cache; null, no transitive dependency but the lockfiles'
     */
    public static void scan(List<Path> buildFiles, List<Path> propertyFiles, List<Path> catalogs, List<Path> lockfiles,
                            DependencyCollector col, Consumer<Phrase> warn, GradleCache cache) throws IOException {
        var global = new HashMap<String, String>();
        for (Path p : propertyFiles) {
            var props = new Properties();
            props.load(new StringReader(ProjectFiles.readText(p)));
            props.forEach((k, v) -> global.put(k.toString(), v.toString().strip()));
        }
        var texts = new LinkedHashMap<Path, String>();
        for (Path p : buildFiles) {
            String text = stripComments(ProjectFiles.readText(p));
            texts.put(p, text);
            variables(text).forEach(global::putIfAbsent);
        }
        var libs = new ArrayList<Lib>();
        for (Path c : catalogs) libs.addAll(catalog(c));
        var byAccessor = new HashMap<String, Lib>();
        for (Lib l : libs) byAccessor.putIfAbsent(l.accessor(), l);

        // the lockfiles of each build file's folder: gradle.lockfile, gradle/dependency-locks/*.lockfile
        var locked = new HashMap<Path, List<GradleLockReader.Locked>>();
        var locks = new HashMap<Path, Path>();
        var lockedAnywhere = new HashSet<String>();
        for (Path l : lockfiles) {
            Path dir = l.getParent();
            if (dir != null && dir.getFileName() != null && dir.getFileName().toString().equals("dependency-locks"))
                dir = dir.getParent() == null ? null : dir.getParent().getParent();
            if (dir == null) continue;
            var entries = GradleLockReader.read(l);
            locked.computeIfAbsent(dir, _ -> new ArrayList<>()).addAll(entries);
            locks.putIfAbsent(dir, l);
            entries.forEach(e -> lockedAnywhere.add(e.ga()));
        }

        var transitive = cache == null ? null : new GradleTransitive(cache);
        // a catalog's library a platform gives a version to, or the graph raises: its row says that version
        var catalogVersions = new HashMap<String, String>();
        for (var e : texts.entrySet()) {
            Path file = e.getKey();
            var vars = new HashMap<>(global);
            vars.putAll(variables(e.getValue()));
            var decls = declarations(e.getValue(), byAccessor);
            var lock = locked.get(file.getParent());
            if (lock != null) locked(col, file, decls, lock, locks.get(file.getParent()), vars);
            else declared(col, file, decls, vars, transitive, catalogVersions);
        }
        // a catalog's library a lockfile holds is said by the lockfile, at the version Gradle resolved
        for (Lib l : libs) {
            if (lockedAnywhere.contains(l.ga())) continue;
            String version = catalogVersions.getOrDefault(l.ga(), l.version());
            if (version == null) col.miss(Ecosystem.MAVEN, l.ga(), "", l.catalog(), Phrase.of("reason.catalogNoVersion"));
            else addDep(col, l.group(), l.artifact(), version, l.catalog(), "catalog:" + l.alias(), Map.of());
        }
        if (transitive != null) transitive.warnings().forEach(warn);
    }

    /** A build with a lockfile: its entries at their versions, then what the build declares that the lockfile does not hold. */
    private static void locked(DependencyCollector col, Path file, List<Decl> decls, List<GradleLockReader.Locked> lock, Path lockfile,
                               Map<String, String> vars) {
        var declared = new HashSet<String>();
        decls.forEach(d -> declared.add(d.ga()));
        var inLock = new HashSet<String>();
        for (var l : lock) {
            if (!inLock.add(l.ga())) continue;
            String scope = declared.contains(l.ga()) ? "direct" : l.testOnly() ? "transitive (test)" : "transitive";
            col.add(Ecosystem.MAVEN, l.ga(), l.version(), lockfile, scope, false);
        }
        for (Decl d : decls) {
            if (d.catalogRef() || inLock.contains(d.ga())) continue;
            if (d.raw() == null) col.miss(Ecosystem.MAVEN, d.ga(), "", file, Phrase.of("reason.platformVersion"));
            else addDep(col, d.group(), d.artifact(), d.raw(), file, d.config(), vars);
        }
    }

    /** A build without a lockfile: its declarations, a platform's versions for those that give none; then what they bring. */
    private static void declared(DependencyCollector col, Path file, List<Decl> decls, Map<String, String> vars, GradleTransitive transitive,
                                 Map<String, String> catalogVersions) {
        var constraints = new LinkedHashMap<String, String>();
        var enforced = new LinkedHashMap<String, String>();
        if (transitive != null)
            for (Decl d : decls) {
                String v = concrete(d.raw(), vars);
                if (d.platform() == null || v == null) continue;
                var managed = transitive.platform(d.group(), d.artifact(), v);
                if (d.platform().equals("enforced")) managed.forEach(enforced::putIfAbsent);
                else managed.forEach(constraints::putIfAbsent);
            }
        var seeds = new ArrayList<GradleTransitive.Seed>();
        var rowVersions = new HashMap<String, String>();
        var catalogSeeds = new HashMap<String, String>();
        for (Decl d : decls) {
            String v = d.raw() == null ? enforced.getOrDefault(d.ga(), constraints.get(d.ga())) : concrete(d.raw(), vars);
            if (d.catalogRef() && v != null) {
                catalogSeeds.putIfAbsent(d.ga(), v);
                if (d.raw() == null) catalogVersions.merge(d.ga(), v, GradleReader::higher);   // the platform's
            }
            if (!d.catalogRef()) {
                if (d.raw() == null) {
                    if (v == null) col.miss(Ecosystem.MAVEN, d.ga(), "", file, Phrase.of("reason.platformVersion"));
                    else col.add(Ecosystem.MAVEN, d.ga(), v, file, d.config(), false);
                } else addDep(col, d.group(), d.artifact(), d.raw(), file, d.config(), vars);
                if (v != null) rowVersions.putIfAbsent(d.ga(), v);
            }
            String scope = mavenScope(d.config());
            if (transitive != null && d.platform() == null && v != null && scope != null)
                seeds.add(new GradleTransitive.Seed(d.group(), d.artifact(), v, scope, d.exclusions()));
        }
        if (transitive == null || seeds.isEmpty()) return;
        for (var r : transitive.resolve(seeds, constraints, enforced).values()) {
            if (r.via() == null) {   // a declaration: raised when the graph asks more
                String declaredVersion = rowVersions.get(r.ga());
                if (declaredVersion != null && Ecosystem.MAVEN.compare(r.version(), declaredVersion) > 0)
                    col.replaceVersion(Ecosystem.MAVEN, r.ga(), declaredVersion, file, r.version());
                String catalogVersion = catalogSeeds.get(r.ga());
                if (catalogVersion != null && Ecosystem.MAVEN.compare(r.version(), catalogVersion) > 0)
                    catalogVersions.merge(r.ga(), r.version(), GradleReader::higher);
                continue;
            }
            col.add(Ecosystem.MAVEN, r.ga(), r.version(), file, MavenTransitive.label(r.scope(), r.via()), false);
        }
    }

    private static String higher(String a, String b) {
        return Ecosystem.MAVEN.compare(a, b) >= 0 ? a : b;
    }

    /** What a build file declares: "g:a:v", group/name/version maps, "g:a" with no version, catalog accessors; platforms said. */
    static List<Decl> declarations(String text, Map<String, Lib> byAccessor) {
        var out = new ArrayList<Decl>();
        for (Pattern p : List.of(DEP_STRING, DEP_MAP, DEP_NO_VERSION, CATALOG_REF)) {
            var m = p.matcher(text);
            while (m.find()) {
                int lineStart = text.lastIndexOf('\n', m.start() - 1) + 1;
                String before = text.substring(lineStart, m.start());
                var cfg = CONFIG.matcher(before);
                String config = cfg.lookingAt() ? cfg.group(1) : "unknown";
                String platform = before.contains("enforcedPlatform(") ? "enforced" : before.contains("platform(") ? "platform" : null;
                var exclusions = exclusions(text, m.end());
                if (p == DEP_NO_VERSION) {
                    if (mavenScope(config) != null || platform != null)
                        out.add(new Decl(m.group(1), m.group(2), null, config, platform, false, exclusions));
                } else if (p == CATALOG_REF) {
                    Lib lib = byAccessor.get(m.group(1).toLowerCase(Locale.ROOT));
                    if (lib != null) out.add(new Decl(lib.group(), lib.artifact(), lib.version(), config, platform, true, exclusions));
                } else {
                    out.add(new Decl(m.group(1), m.group(2), m.group(3), config, platform, false, exclusions));
                }
            }
        }
        return out;
    }

    /**
     * The exclusions of the block that follows a declaration, "group:module" (* for a part not given):
     * implementation("g:a:1") { exclude(group = "x") }, implementation('g:a:1') { exclude group: 'x', module: 'y' }.
     */
    static List<String> exclusions(String text, int after) {
        int i = after;
        while (i < text.length() && (text.charAt(i) == ')' || text.charAt(i) == ' ' || text.charAt(i) == '\t')) i++;
        if (i >= text.length() || text.charAt(i) != '{') return List.of();
        int depth = 0, end = i;
        for (; end < text.length(); end++) {
            if (text.charAt(end) == '{') depth++;
            else if (text.charAt(end) == '}' && --depth == 0) break;
        }
        var out = new ArrayList<String>();
        var m = EXCLUDE.matcher(text.substring(i, Math.min(end + 1, text.length())));
        while (m.find()) {
            String group = "*", module = "*";
            var part = EXCLUDE_PART.matcher(m.group(1));
            while (part.find()) {
                if (part.group(1).equals("group")) group = part.group(2);
                else module = part.group(2);
            }
            out.add(group + ":" + module);
        }
        return List.copyOf(out);
    }

    public static void scanCatalogs(List<Path> catalogs, DependencyCollector col) throws IOException {
        scan(List.of(), List.of(), catalogs, List.of(), col, _ -> { }, null);
    }

    /** A version catalog's libraries, their versions given directly or by reference to [versions]. */
    static List<Lib> catalog(Path path) throws IOException {
        var out = new ArrayList<Lib>();
        String section = null;
        var versions = new HashMap<String, String>();
        var libraries = new ArrayList<String[]>();
        for (String line : ProjectFiles.readText(path).lines().toList()) {
            line = line.replaceAll("\\s+#.*$|^#.*$", "").strip();
            if (line.isEmpty()) continue;
            var sec = SECTION.matcher(line);
            if (sec.matches()) { section = sec.group(1).strip(); continue; }
            var kv = KEY_VALUE.matcher(line);
            if (!kv.matches()) continue;
            String key = kv.group(1).replace("\"", ""), val = kv.group(2).strip();
            if ("versions".equals(section)) {
                if (val.startsWith("\"")) versions.put(key, val.replace("\"", ""));
                else {
                    var pairs = pairs(val);
                    versions.put(key, firstNonNull(pairs.get("strictly"), pairs.get("require"), pairs.get("prefer")));
                }
            } else if ("libraries".equals(section)) {
                libraries.add(new String[]{key, val});
            }
        }
        for (String[] lib : libraries) {
            String alias = lib[0], val = lib[1], g, a, v;
            if (val.startsWith("\"")) {
                String[] parts = val.replace("\"", "").split(":");
                if (parts.length < 2) continue;
                g = parts[0];
                a = parts[1];
                v = parts.length > 2 ? parts[2] : null;
            } else {
                var pairs = pairs(val);
                String module = pairs.get("module");
                if (module != null && module.contains(":")) {
                    g = module.substring(0, module.indexOf(':'));
                    a = module.substring(module.indexOf(':') + 1);
                } else {
                    g = pairs.get("group");
                    a = pairs.get("name");
                }
                if (g == null || a == null) continue;
                String ref = firstNonNull(pairs.get("version.ref"), pairs.get("ref"));
                v = ref != null ? versions.get(ref)
                        : firstNonNull(pairs.get("version"), pairs.get("strictly"), pairs.get("require"), pairs.get("prefer"));
            }
            out.add(new Lib(alias, g, a, v, path));
        }
        return out;
    }

    private static Map<String, String> pairs(String s) {
        var out = new HashMap<String, String>();
        var m = PAIR.matcher(s);
        while (m.find()) out.put(m.group(1), m.group(2));
        return out;
    }

    @SafeVarargs
    private static <T> T firstNonNull(T... values) {
        for (T v : values) if (v != null) return v;
        return null;
    }
}
