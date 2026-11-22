package org.jtools.cvescanner.model;

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
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * A file's dependencies as a tree: its declared ones, each with the packages it brings below it, from the packages
 * each dependency records as bringing it (Dependency.parents). Those whose parents the file does not record (a Gradle
 * lockfile, a Pipfile.lock) are apart.
 *
 * @param unrecorded the indirect dependencies whose parents are not recorded
 */
public record DependencyTree(String file, List<Node> roots, List<Dependency> unrecorded) {

    /** A dependency and what it brings. */
    public record Node(Dependency dependency, List<Node> children) {}

    /** A dependency as a tree lists it: its depth (0 for a declared one), null when its parents are not recorded. */
    public record Row(Dependency dependency, Integer depth) {}

    /** One tree per file, the files in order, each file's dependencies in the order the scan found them. */
    public static List<DependencyTree> of(List<Dependency> dependencies) {
        var byFile = new TreeMap<String, List<Dependency>>();
        for (Dependency d : dependencies) byFile.computeIfAbsent(d.file(), _ -> new ArrayList<>()).add(d);
        var out = new ArrayList<DependencyTree>();
        byFile.forEach((file, deps) -> out.add(tree(file, deps)));
        return out;
    }

    private static DependencyTree tree(String file, List<Dependency> deps) {
        // a node per dependency: a package version in two scopes of one file (managed and used) is two rows
        var all = new ArrayList<Node>();
        var nodes = new HashMap<String, Node>();   // "name@version" -> the first node of that id, what brings its children
        for (Dependency d : deps) {
            var node = new Node(d, new ArrayList<>());
            all.add(node);
            nodes.putIfAbsent(id(d), node);
        }
        var roots = new ArrayList<Node>();
        var unrecorded = new ArrayList<Dependency>();
        for (Node node : all) {
            Dependency d = node.dependency();
            if (d.parents() == null) {
                unrecorded.add(d);
                continue;
            }
            // under its parent; a parent the file does not list (left out by a filter): the nearest one it does
            Node parent = null;
            for (int i = d.parents().size() - 1; i >= 0 && parent == null; i--) parent = nodes.get(d.parents().get(i));
            if (parent == null || parent == node) roots.add(node);
            else parent.children().add(node);
        }
        return new DependencyTree(file, List.copyOf(roots), List.copyOf(unrecorded));
    }

    /** "name@version", as parents name a dependency. */
    public static String id(Dependency d) {
        return d.name() + "@" + d.version();
    }

    /** "name version", as a person reads a parent's id. */
    public static String shown(String id) {
        int at = id.lastIndexOf('@');
        return at > 0 ? id.substring(0, at) + " " + id.substring(at + 1) : id;
    }

    /** Its dependencies in tree order, each followed by what it brings; those whose parents are not recorded last. */
    public List<Row> rows() {
        var out = new ArrayList<Row>();
        Set<Node> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Node r : roots) walk(r, 0, out, seen);
        for (Dependency d : unrecorded) out.add(new Row(d, null));
        return out;
    }

    private static void walk(Node node, int depth, List<Row> out, Set<Node> seen) {
        if (!seen.add(node)) return;
        out.add(new Row(node.dependency(), depth));
        for (Node c : node.children()) walk(c, depth + 1, out, seen);
    }

    /** How many dependencies it holds. */
    public int size() {
        return rows().size();
    }

    /** The findings of each dependency, by its ecosystem, name, version, file and scope: a finding is a dependency's. */
    public static Map<String, List<Finding>> findingsBy(List<Finding> findings) {
        var out = new HashMap<String, List<Finding>>();
        for (Finding f : findings)
            out.computeIfAbsent(key(f.ecosystem(), f.pkg(), f.version(), f.file(), f.scope()), _ -> new ArrayList<>()).add(f);
        return out;
    }

    public static String key(Dependency d) {
        return key(d.ecosystem(), d.name(), d.version(), d.file(), d.scope());
    }

    private static String key(Ecosystem e, String name, String version, String file, String scope) {
        return String.join("\u0001", e.id(), name, version, file, scope);
    }
}
