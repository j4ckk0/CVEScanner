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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// ---------------------------------------------------------------------------------------------- Gradle
public final class GradleScanner {
    private static final Pattern DEP_STRING = Pattern.compile(
            "[\"']([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+):([^\"'\\s:@]+)(?::[A-Za-z0-9_.\\-]+)?(?:@[A-Za-z0-9]+)?[\"']");
    private static final Pattern DEP_MAP = Pattern.compile(
            "group\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*name\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*version\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    private static final List<Pattern> VARS = List.of(
            Pattern.compile("(?m)(?:^|[{;])\\s*(?:def\\s+|val\\s+|var\\s+|(?:project\\.)?ext\\.|extra\\[\\s*)?[\"']?([A-Za-z_][\\w.\\-]*)[\"']?\\s*\\]?\\s*(?::\\s*String\\s*)?=\\s*[\"']([^\"'$\\n]+)[\"']"),
            Pattern.compile("(?:set|put)\\(\\s*[\"']([A-Za-z_][\\w.\\-]*)[\"']\\s*,\\s*[\"']([^\"'$\\n]+)[\"']"),
            Pattern.compile("\\b([A-Za-z_]\\w*)\\s+by\\s+extra\\(\\s*[\"']([^\"'$\\n]+)[\"']"));
    private static final Pattern REF = Pattern.compile("\\$\\{([^}]+)\\}|\\$([A-Za-z_][\\w.]*)");
    private static final Pattern CONFIG = Pattern.compile("\\s*([A-Za-z_]\\w*)");
    private static final Pattern PAIR = Pattern.compile("([\\w.\\-]+)\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern SECTION = Pattern.compile("\\[([^\\]]+)\\]");
    private static final Pattern KEY_VALUE = Pattern.compile("(\"[^\"]+\"|[\\w.\\-]+)\\s*=\\s*(.+)");

    private GradleScanner() {}

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

    private static void addDep(Collector col, String g, String a, String raw, Path path, String scope, Map<String, String> vars) {
        String name = g + ":" + a;
        String v = resolve(raw, vars).replaceAll("!+$", "");
        if (v.contains("$")) col.miss("Maven", name, raw, path, "unresolved Gradle variable");
        else if (v.contains("+") || v.startsWith("latest.") || v.startsWith("[") || v.startsWith("("))
            col.miss("Maven", name, raw, path, "dynamic version");
        else col.add("Maven", name, v, path, scope, false);
    }

    public static void scan(List<Path> buildFiles, List<Path> propertyFiles, Collector col) throws IOException {
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
        for (var e : texts.entrySet()) {
            String text = e.getValue();
            var vars = new HashMap<>(global);
            vars.putAll(variables(text));
            for (Pattern p : List.of(DEP_STRING, DEP_MAP)) {
                var m = p.matcher(text);
                while (m.find()) {
                    int lineStart = text.lastIndexOf('\n', m.start() - 1) + 1;
                    var cfg = CONFIG.matcher(text.substring(lineStart, m.start()));
                    addDep(col, m.group(1), m.group(2), m.group(3), e.getKey(), cfg.lookingAt() ? cfg.group(1) : "unknown", vars);
                }
            }
        }
    }

    public static void scanCatalogs(List<Path> catalogs, Collector col) throws IOException {
        for (Path path : catalogs) {
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
                if (v == null) col.miss("Maven", g + ":" + a, "", path, "no version in catalog (managed by platform/BOM)");
                else addDep(col, g, a, v, path, "catalog:" + alias, Map.of());
            }
        }
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
