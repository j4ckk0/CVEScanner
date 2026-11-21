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


/**
 * A package version found, where and how it is used.
 *
 * @param bundle a jar's OSGi name (Bundle-SymbolicName) when the jar has no Maven coordinates: which group an advisory
 *               for its artifactId must name to be its own; null otherwise
 */
public record Dependency(Ecosystem ecosystem, String name, String version, String file, String scope, boolean approximate,
                         String bundle) {

    public Dependency(Ecosystem ecosystem, String name, String version, String file, String scope, boolean approximate) {
        this(ecosystem, name, version, file, scope, approximate, null);
    }

    /** Whether this OSGi name is of that group's artifact: the group itself, or under it (org.apache.logging.log4j.core). */
    public boolean bundleOf(String group) {
        return bundle != null && !group.isEmpty() && (bundle.equals(group) || (group.contains(".") && bundle.startsWith(group + ".")));
    }
}
