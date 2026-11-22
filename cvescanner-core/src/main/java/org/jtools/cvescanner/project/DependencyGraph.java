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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The packages that bring each package of a lockfile, from what each entry depends on: the first path a breadth-first
 * walk from the declared ones finds, the shortest, as `mvn dependency:tree` lists a package once.
 */
final class DependencyGraph {

    private DependencyGraph() {}

    /**
     * Each package reached from the roots, with the packages that bring it (a root's list is empty). Ids are the
     * lockfile's own ("name@version"); one the walk never reaches is absent.
     */
    static Map<String, List<String>> paths(Collection<String> roots, Map<String, ? extends Collection<String>> children) {
        var out = new LinkedHashMap<String, List<String>>();
        var queue = new ArrayDeque<String>();
        for (String r : roots)
            if (out.putIfAbsent(r, List.of()) == null) queue.add(r);
        while (!queue.isEmpty()) {
            String id = queue.poll();
            var below = new ArrayList<>(out.get(id));
            below.add(id);
            Collection<String> next = children.get(id);
            if (next == null) continue;
            for (String child : next)
                if (!out.containsKey(child)) {
                    out.put(child, List.copyOf(below));
                    queue.add(child);
                }
        }
        return out;
    }
}
