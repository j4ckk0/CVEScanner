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

import java.util.List;

/**
 * A package version found, where and how it is used.
 *
 * @param bundle a jar's OSGi name (Bundle-SymbolicName) when the jar has no Maven coordinates: which group an advisory
 *               for its artifactId must name to be its own; null otherwise
 * @param parents the packages that bring it, from the declared one down to its parent, each "name@version": empty for
 *               a declared or installed package; null when its file does not record them (a Gradle lockfile)
 */
public record Dependency(Ecosystem ecosystem, String name, String version, String file, String scope, boolean approximate,
                         String bundle, List<String> parents) {

    public Dependency {
        if (parents != null) parents = List.copyOf(parents);
    }

    public Dependency(Ecosystem ecosystem, String name, String version, String file, String scope, boolean approximate, String bundle) {
        this(ecosystem, name, version, file, scope, approximate, bundle, List.of());
    }

    public Dependency(Ecosystem ecosystem, String name, String version, String file, String scope, boolean approximate) {
        this(ecosystem, name, version, file, scope, approximate, null);
    }

    /** Whether another package brings it: not declared by the project itself. */
    public boolean transitive() {
        return isTransitive(scope);
    }

    /** Whether a dependency of this scope is brought by another package: "transitive", "transitive (test) via g:a". */
    public static boolean isTransitive(String scope) {
        return scope.startsWith("transitive");
    }

    /** Whether this OSGi name is of that group's artifact: the group itself, or under it (org.apache.logging.log4j.core). */
    public boolean bundleOf(String group) {
        return bundle != null && !group.isEmpty() && (bundle.equals(group) || (group.contains(".") && bundle.startsWith(group + ".")));
    }
}
