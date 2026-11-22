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


import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * Where npm keeps its cache, read from its configuration files as npm reads them, without starting npm: a CI image or
 * a company machine often sets it in an npmrc (the GitHub Windows runner, in the global one).
 */
final class NpmConfig {

    private static final Pattern VARIABLE = Pattern.compile("\\$\\{([^}]+)}");

    private final Map<String, String> env;
    private final Path home;

    private NpmConfig(Map<String, String> env, Path home) {
        this.env = env;
        this.home = home;
    }

    /**
     * The cache folder npm's configuration names, in npm's order: the npm_config_cache variable, the user's npmrc, the
     * global npmrc, npm's own. Empty when none does: npm's default then.
     *
     * @param node the node program found on PATH, beside which npm and its own npmrc are installed
     */
    static Optional<Path> cache(Map<String, String> env, Path home, Optional<Path> node, boolean windows) {
        var config = new NpmConfig(env, home);
        Path nodeDir = node.map(Path::toAbsolutePath).map(Path::getParent).orElse(null);
        Path installPrefix = nodeDir == null ? null : windows ? nodeDir : nodeDir.getParent();
        Path npmDir = installPrefix == null ? null
                : windows ? installPrefix.resolve("node_modules").resolve("npm") : installPrefix.resolve("lib").resolve("node_modules").resolve("npm");

        Map<String, String> builtin = npmDir == null ? Map.of() : config.read(npmDir.resolve("npmrc"));
        Map<String, String> user = config.read(config.path(config.fromEnv("userconfig"), home.resolve(".npmrc")));
        String prefix = first(config.fromEnv("prefix"), user.get("prefix"), builtin.get("prefix"),
                installPrefix == null ? null : installPrefix.toString());
        Map<String, String> global = Map.of();
        String globalConfig = first(config.fromEnv("globalconfig"), user.get("globalconfig"), builtin.get("globalconfig"));
        if (globalConfig != null) global = config.read(config.path(globalConfig, null));
        else if (prefix != null) global = config.read(config.path(prefix, null).resolve("etc").resolve("npmrc"));

        String cache = first(config.fromEnv("cache"), user.get("cache"), global.get("cache"), builtin.get("cache"));
        return cache == null ? Optional.empty() : Optional.ofNullable(config.path(cache, null));
    }

    private static String first(String... values) {
        for (String v : values) if (v != null && !v.isBlank()) return v;
        return null;
    }

    /** npm_config_KEY, whatever its case, as npm reads it. */
    private String fromEnv(String key) {
        String wanted = "npm_config_" + key;
        for (var e : env.entrySet()) if (e.getKey().equalsIgnoreCase(wanted)) return e.getValue();
        return null;
    }

    /** A path as npm reads it: its ${VARIABLE}s replaced, ~ the home folder. */
    private Path path(String value, Path otherwise) {
        if (value == null || value.isBlank()) return otherwise;
        String v = expand(value.strip());
        if (v.equals("~") || v.startsWith("~/") || v.startsWith("~\\")) return home.resolve(v.length() > 2 ? v.substring(2) : "");
        try {
            return Path.of(v);
        } catch (RuntimeException _) {
            return otherwise;
        }
    }

    private String expand(String value) {
        Matcher m = VARIABLE.matcher(value);
        var sb = new StringBuilder();
        while (m.find()) {
            String name = m.group(1);
            String v = env.get(name);
            if (v == null) for (var e : env.entrySet()) if (e.getKey().equalsIgnoreCase(name)) v = e.getValue();
            m.appendReplacement(sb, Matcher.quoteReplacement(v == null ? m.group() : v));
        }
        return m.appendTail(sb).toString();
    }

    /** An npmrc's keys (lower case) and values; empty when it is not there or cannot be read. */
    private Map<String, String> read(Path file) {
        var out = new HashMap<String, String>();
        if (file == null || !Files.isRegularFile(file)) return out;
        try {
            for (String line : ProjectFiles.readText(file).split("\\R")) {
                String l = line.strip();
                if (l.isEmpty() || l.startsWith(";") || l.startsWith("#") || l.startsWith("[")) continue;
                int eq = l.indexOf('=');
                if (eq <= 0) continue;
                String value = l.substring(eq + 1).strip();
                if (value.length() >= 2 && (value.startsWith("\"") && value.endsWith("\"") || value.startsWith("'") && value.endsWith("'")))
                    value = value.substring(1, value.length() - 1);
                out.putIfAbsent(l.substring(0, eq).strip().toLowerCase(Locale.ROOT), expand(value));
            }
        } catch (Exception _) {
            // unreadable: as if not there
        }
        return out;
    }
}
