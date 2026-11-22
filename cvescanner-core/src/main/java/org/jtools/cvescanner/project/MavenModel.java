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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A pom as Maven sees it: with its parents' properties, dependencies and dependency management, and the dependency
 * management its chain imports (BOMs), read from the scanned folder or the local repository. Its texts resolved
 * as the pom itself would resolve them: its own properties first, then its parents'.
 */
final class MavenModel {

    private static final Pattern PROP = Pattern.compile("\\$\\{([^}]+)\\}");
    private static final int MAX_DEPTH = 20;

    /** A dependency resolved: its version from the pom or its management (null when neither gives one). */
    record Dep(String group, String artifact, String version, String scope, boolean optional, List<String> exclusions) {
        String ga() { return group + ":" + artifact; }
    }

    /** The management of one artifact: its version, its scope (null when not written), the exclusions it adds. */
    record Managed(String version, String scope, List<String> exclusions) {}

    private final MavenReader.Pom pom;
    private final List<MavenReader.Pom> chain = new ArrayList<>();
    private final Function<MavenReader.Pom, MavenReader.Pom> parentOf;
    private final Function<String[], MavenReader.Pom> find;
    private final Collection<String> missing;
    private Map<String, Managed> managed;

    /**
     * @param parentOf a pom's parent, null when not found
     * @param find a pom by {group, artifact, version}, null when not found (a BOM)
     * @param missing where the poms looked for and not found are said, "group:artifact:version"
     */
    MavenModel(MavenReader.Pom pom, Function<MavenReader.Pom, MavenReader.Pom> parentOf, Function<String[], MavenReader.Pom> find,
               Collection<String> missing) {
        this.pom = pom;
        this.parentOf = parentOf;
        this.find = find;
        this.missing = missing;
        for (MavenReader.Pom p = pom; p != null && !chain.contains(p) && chain.size() < MAX_DEPTH; p = parentOf.apply(p)) {
            chain.add(p);
            if (p.parent != null && parentOf.apply(p) == null) missing.add(p.parent[0] + ":" + p.parent[1] + ":" + p.parent[2]);
        }
    }

    String groupId() { return resolve(pom.groupId); }

    String artifactId() { return resolve(pom.artifactId); }

    String property(String key) {
        for (MavenReader.Pom p : chain) if (p.props.containsKey(key)) return p.props.get(key);
        return switch (key) {
            case "project.version", "pom.version", "version" -> pom.version;
            case "project.groupId", "pom.groupId", "groupId" -> pom.groupId;
            case "project.artifactId", "pom.artifactId", "artifactId" -> pom.artifactId;
            case "project.parent.version", "parent.version" -> pom.parent == null ? null : pom.parent[2];
            case "project.parent.groupId", "parent.groupId" -> pom.parent == null ? null : pom.parent[0];
            default -> null;
        };
    }

    String resolve(String s) {
        if (s == null) return null;
        for (int k = 0; k < 10; k++) {
            String next = PROP.matcher(s).replaceAll(m -> {
                String v = property(m.group(1));
                return Matcher.quoteReplacement(v != null ? v : m.group());
            });
            if (next.equals(s)) break;
            s = next;
        }
        return s;
    }

    /** The dependency management in force: the chain's own entries first, the child's before its parents', then the BOMs it imports. */
    Map<String, Managed> managed() {
        if (managed != null) return managed;
        managed = new LinkedHashMap<>();
        var imports = new ArrayList<String[]>();
        for (MavenReader.Pom p : chain)
            for (MavenReader.PomDep d : p.managed) {
                String g = resolve(d.group()), a = resolve(d.artifact()), v = resolve(d.version());
                if (g == null || a == null) continue;
                if ("import".equals(d.scope())) imports.add(new String[]{g, a, v});
                else managed.putIfAbsent(g + ":" + a, new Managed(v, d.scopeWritten() ? d.scope() : null, d.exclusions()));
            }
        for (String[] bom : imports) {
            MavenReader.Pom found = find.apply(bom);
            if (found == null) {
                missing.add(String.join(":", bom));
                continue;
            }
            new MavenModel(found, parentOf, find, missing).managed().forEach(managed::putIfAbsent);
        }
        return managed;
    }

    /** Its dependencies, its parents' included, each resolved: plugins' left out. */
    List<Dep> dependencies() {
        var out = new LinkedHashMap<String, Dep>();
        for (MavenReader.Pom p : chain)
            for (MavenReader.PomDep d : p.deps) {
                if (d.scope().equals("plugin")) continue;
                String g = resolve(d.group()), a = resolve(d.artifact());
                if (g == null || a == null) continue;
                Managed m = managed().get(g + ":" + a);
                String v = d.version() != null ? resolve(d.version()) : m == null ? null : m.version();
                var exclusions = new ArrayList<>(d.exclusions());
                if (m != null) exclusions.addAll(m.exclusions());
                // a scope not written is the management's, else compile
                String scope = d.scopeWritten() || m == null || m.scope() == null ? d.scope() : m.scope();
                out.putIfAbsent(g + ":" + a, new Dep(g, a, v, scope, d.optional(), List.copyOf(exclusions)));
            }
        return List.copyOf(out.values());
    }
}
