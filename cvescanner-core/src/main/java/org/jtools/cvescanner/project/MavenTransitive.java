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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;

/**
 * The transitive dependencies of a project's poms, as Maven would resolve them: breadth first, the nearest version of
 * an artifact winning and a declared one always; the project's dependency management overriding a version; the
 * exclusions along the way; a dependency's optional, test and provided dependencies not followed. Each pom is found
 * among the scanned ones first (a sibling module, never installed), then in the local repository.
 */
final class MavenTransitive {

    private static final int SAID = 5;   // the poms named in a warning, the others counted

    private final PomSource repository;
    private final MavenReader.PomIndex index;
    private final Set<String> missing = new LinkedHashSet<>();
    private final Set<String> unresolved = new LinkedHashSet<>();
    private final Map<MavenReader.Pom, MavenModel> models = new HashMap<>();

    MavenTransitive(PomSource repository, MavenReader.PomIndex index) {
        this.repository = repository;
        this.index = index;
    }

    /** The model of a scanned pom: its parents and BOMs found in the folder, else in the repository. */
    MavenModel model(MavenReader.Pom pom) {
        return models.computeIfAbsent(pom, p -> new MavenModel(p, this::parentOf, this::find, missing));
    }

    private MavenReader.Pom parentOf(MavenReader.Pom pom) {
        if (pom.parent == null) return null;
        MavenReader.Pom local = index.parentOf(pom);
        return local != null ? local : find(new String[]{pom.parent[0], pom.parent[1], pom.parent[2]});
    }

    /** A pom by its coordinates: a scanned one of that group and artifact, else the repository's of that version. */
    private MavenReader.Pom find(String[] gav) {
        MavenReader.Pom scanned = index.byCoordinates(gav[0], gav[1]);
        return scanned != null ? scanned : repository.pom(gav[0], gav[1], gav[2]).orElse(null);
    }

    /**
     * The transitive dependencies of this scanned pom, added to the collector against it. The version is the nearest
     * path's; the scope the widest of every path's (compile over runtime over provided over test), as Maven's.
     */
    void resolve(MavenReader.Pom pom, DependencyCollector col) {
        MavenModel module = model(pom);
        Map<String, MavenModel.Managed> managed = module.managed();
        Set<String> declared = new HashSet<>();   // the pom's own, and itself: never overridden by a transitive one
        declared.add(module.groupId() + ":" + module.artifactId());
        record Node(String group, String artifact, String version, String scope, String via, List<String> exclusions) {}
        Map<String, Node> found = new LinkedHashMap<>();
        Set<String> skipped = new HashSet<>();
        var queue = new ArrayDeque<Node>();
        for (MavenModel.Dep d : module.dependencies()) {
            declared.add(d.ga());
            if (!List.of("compile", "runtime", "provided", "test").contains(d.scope()) || !resolved(d.version())) continue;
            queue.add(new Node(d.group(), d.artifact(), d.version(), d.scope(), d.ga(), d.exclusions()));
        }
        while (!queue.isEmpty()) {
            Node node = queue.poll();
            MavenReader.Pom pomFound = find(new String[]{node.group(), node.artifact(), node.version()});
            if (pomFound == null) {
                missing.add(node.group() + ":" + node.artifact() + ":" + node.version());
                continue;
            }
            for (MavenModel.Dep d : model(pomFound).dependencies()) {
                if (d.optional() || !List.of("compile", "runtime").contains(d.scope()) || excluded(d, node.exclusions())) continue;
                if (declared.contains(d.ga()) || skipped.contains(d.ga())) continue;
                String scope = scope(node.scope(), d.scope());
                var exclusions = new ArrayList<>(node.exclusions());
                exclusions.addAll(d.exclusions());
                Node seen = found.get(d.ga());
                if (seen != null) {
                    // a nearer path gave its version; a wider scope along this one widens it, and what it brings
                    if (rank(scope) > rank(seen.scope())) {
                        Node wider = new Node(seen.group(), seen.artifact(), seen.version(), scope, node.via(), List.copyOf(exclusions));
                        found.put(d.ga(), wider);
                        queue.add(wider);
                    }
                    continue;
                }
                MavenModel.Managed m = managed.get(d.ga());
                String version = m != null && m.version() != null ? m.version() : d.version();
                if (!resolved(version)) {
                    unresolved.add(d.ga() + (version == null ? "" : ":" + version));
                    skipped.add(d.ga());
                    continue;
                }
                Node child = new Node(d.group(), d.artifact(), version, scope, node.via(), List.copyOf(exclusions));
                found.put(d.ga(), child);
                queue.add(child);
            }
        }
        for (Node n : found.values())
            col.add(Ecosystem.MAVEN, n.group() + ":" + n.artifact(), n.version(), pom.path, label(n.scope(), n.via()), false);
    }

    static int rank(String scope) {
        return switch (scope) {
            case "compile" -> 4;
            case "runtime" -> 3;
            case "provided" -> 2;
            default -> 1;
        };
    }

    /** What the scan says of the poms it could not follow: one warning for those missing, one for those unresolved. */
    List<Phrase> warnings() {
        var out = new ArrayList<Phrase>();
        if (!missing.isEmpty())
            out.add(Phrase.of("warning.mavenPomsMissing", missing.size(), repository.shown(), named(missing)));
        if (!unresolved.isEmpty()) out.add(Phrase.of("warning.mavenUnresolved", unresolved.size(), named(unresolved)));
        return out;
    }

    static String named(Set<String> coordinates) {
        var first = coordinates.stream().limit(SAID).toList();
        return String.join(", ", first) + (coordinates.size() > SAID ? ", …" : "");
    }

    static boolean resolved(String version) {
        return version != null && !version.isBlank() && !version.contains("${") && !version.startsWith("[") && !version.startsWith("(");
    }

    static boolean excluded(MavenModel.Dep d, List<String> exclusions) {
        for (String x : exclusions) {
            int colon = x.indexOf(':');
            String g = x.substring(0, colon), a = x.substring(colon + 1);
            if ((g.equals("*") || g.equals(d.group())) && (a.equals("*") || a.equals(d.artifact()))) return true;
        }
        return false;
    }

    /** Maven's scope of a dependency's dependency: test and provided stay so, runtime wins over compile. */
    static String scope(String parent, String child) {
        return switch (parent) {
            case "test", "provided" -> parent;
            case "runtime" -> "runtime";
            default -> child;
        };
    }

    /** As the tables show it: "transitive via g:a", its scope said when not compile. */
    static String label(String scope, String via) {
        return (scope.equals("compile") ? "transitive" : "transitive (" + scope + ")") + " via " + via;
    }
}
