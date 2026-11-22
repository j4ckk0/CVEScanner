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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;

/**
 * The transitive dependencies of a Gradle build, from the poms of Gradle's cache, as Gradle resolves them: the highest
 * version requested anywhere in the graph wins, a declared one included, a platform's version taking part (an
 * enforced platform's forcing it); the walk is run again with the versions chosen until none changes, so that what only
 * a lower version brought is gone. The exclusions, scopes and labels are Maven's (MavenTransitive).
 */
final class GradleTransitive {

    private static final int MAX_PASSES = 10;

    /** A declaration of the build: its coordinates, the version it asks, its scope as Maven says it (compile, test…). */
    record Seed(String group, String artifact, String version, String scope, List<String> exclusions) {
        String ga() { return group + ":" + artifact; }
    }

    /** A dependency of the graph: its version once resolved, its scope, the declaration that brings it. */
    record Resolved(String group, String artifact, String version, String scope, String via) {
        String ga() { return group + ":" + artifact; }
    }

    private final GradleCache cache;
    private final Set<String> missing = new LinkedHashSet<>();
    private final Set<String> unresolved = new LinkedHashSet<>();
    private final Map<MavenReader.Pom, MavenModel> models = new HashMap<>();

    GradleTransitive(GradleCache cache) {
        this.cache = cache;
    }

    private MavenReader.Pom find(String[] gav) {
        return cache.pom(gav[0], gav[1], gav[2]).orElse(null);
    }

    private MavenReader.Pom parentOf(MavenReader.Pom pom) {
        return pom.parent == null ? null : find(new String[]{pom.parent[0], pom.parent[1], pom.parent[2]});
    }

    MavenModel model(MavenReader.Pom pom) {
        return models.computeIfAbsent(pom, p -> new MavenModel(p, this::parentOf, this::find, missing));
    }

    /** The versions a platform's pom manages, as constraints; empty when the cache does not hold it. */
    Map<String, String> platform(String group, String artifact, String version) {
        var out = new LinkedHashMap<String, String>();
        Optional<MavenReader.Pom> bom = cache.pom(group, artifact, version);
        if (bom.isEmpty()) {
            missing.add(group + ":" + artifact + ":" + version);
            return out;
        }
        model(bom.get()).managed().forEach((ga, m) -> {
            if (MavenTransitive.resolved(m.version())) out.put(ga, m.version());
        });
        return out;
    }

    /**
     * The graph of these declarations: every dependency reached, the declarations among them at the version the graph
     * gives them (higher than declared when a transitive one asks more).
     *
     * @param constraints the versions platforms give (they take part in "the highest wins"), by group:artifact
     * @param enforced    the versions enforced platforms force, by group:artifact
     */
    Map<String, Resolved> resolve(List<Seed> seeds, Map<String, String> constraints, Map<String, String> enforced) {
        Map<String, String> chosen = new HashMap<>();
        Map<String, Resolved> reached = new LinkedHashMap<>();
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            Map<String, String> requested = new HashMap<>();
            reached = new LinkedHashMap<>();
            record Node(String group, String artifact, String scope, String via, List<String> exclusions) {}
            var queue = new ArrayDeque<Node>();
            for (Seed s : seeds) {
                request(requested, s.ga(), s.version());
                if (!reached.containsKey(s.ga())) {
                    reached.put(s.ga(), new Resolved(s.group(), s.artifact(), null, s.scope(), null));
                    queue.add(new Node(s.group(), s.artifact(), s.scope(), s.ga(), s.exclusions()));
                }
            }
            while (!queue.isEmpty()) {
                Node node = queue.poll();
                String version = version(node.group() + ":" + node.artifact(), chosen, requested, constraints, enforced);
                if (version == null) continue;
                MavenReader.Pom pom = find(new String[]{node.group(), node.artifact(), version});
                if (pom == null) {
                    missing.add(node.group() + ":" + node.artifact() + ":" + version);
                    continue;
                }
                for (MavenModel.Dep d : model(pom).dependencies()) {
                    if (d.optional() || !List.of("compile", "runtime").contains(d.scope()) || MavenTransitive.excluded(d, node.exclusions()))
                        continue;
                    if (!MavenTransitive.resolved(d.version()) && !constraints.containsKey(d.ga()) && !enforced.containsKey(d.ga())) {
                        unresolved.add(d.ga() + (d.version() == null ? "" : ":" + d.version()));
                        continue;
                    }
                    if (MavenTransitive.resolved(d.version())) request(requested, d.ga(), d.version());
                    String scope = MavenTransitive.scope(node.scope(), d.scope());
                    Resolved seen = reached.get(d.ga());
                    var exclusions = new ArrayList<>(node.exclusions());
                    exclusions.addAll(d.exclusions());
                    if (seen != null) {
                        if (MavenTransitive.rank(scope) > MavenTransitive.rank(seen.scope())) {   // widened, and what it brings
                            reached.put(d.ga(), new Resolved(d.group(), d.artifact(), null, scope, seen.via() == null ? null : node.via()));
                            queue.add(new Node(d.group(), d.artifact(), scope, node.via(), List.copyOf(exclusions)));
                        }
                        continue;
                    }
                    reached.put(d.ga(), new Resolved(d.group(), d.artifact(), null, scope, node.via()));
                    queue.add(new Node(d.group(), d.artifact(), scope, node.via(), List.copyOf(exclusions)));
                }
            }
            Map<String, String> next = new HashMap<>();
            for (String ga : reached.keySet()) {
                String v = version(ga, Map.of(), requested, constraints, enforced);
                if (v != null) next.put(ga, v);
            }
            boolean stable = next.equals(chosen);
            chosen = next;
            if (stable) break;
        }
        var out = new LinkedHashMap<String, Resolved>();
        for (var r : reached.values()) {
            String v = chosen.get(r.ga());
            if (v != null) out.put(r.ga(), new Resolved(r.group(), r.artifact(), v, r.scope(), r.via()));
        }
        return out;
    }

    private static void request(Map<String, String> requested, String ga, String version) {
        if (!MavenTransitive.resolved(version)) return;
        requested.merge(ga, version, (a, b) -> Ecosystem.MAVEN.compare(a, b) >= 0 ? a : b);
    }

    /** The version a dependency resolves to: an enforced platform's; else the highest of what was chosen, asked, constrained. */
    private static String version(String ga, Map<String, String> chosen, Map<String, String> requested,
                                  Map<String, String> constraints, Map<String, String> enforced) {
        if (enforced.containsKey(ga)) return enforced.get(ga);
        String best = null;
        for (String v : new String[]{chosen.get(ga), requested.get(ga), constraints.get(ga)})
            if (v != null && (best == null || Ecosystem.MAVEN.compare(v, best) > 0)) best = v;
        return best;
    }

    /** What the walk could not follow: the poms not in the cache, the versions not resolved. */
    List<Phrase> warnings() {
        var out = new ArrayList<Phrase>();
        if (!missing.isEmpty()) out.add(Phrase.of("warning.gradlePomsMissing", missing.size(), cache.shown(), MavenTransitive.named(missing)));
        if (!unresolved.isEmpty()) out.add(Phrase.of("warning.gradleUnresolved", unresolved.size(), MavenTransitive.named(unresolved)));
        return out;
    }
}
