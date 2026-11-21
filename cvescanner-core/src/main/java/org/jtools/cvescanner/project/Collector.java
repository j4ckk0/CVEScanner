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


import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Unresolved;

public final class Collector {
    final Path root;
    public final List<Dependency> deps = new ArrayList<>();
    public final List<Unresolved> unresolved = new ArrayList<>();
    private final Set<List<Object>> seen = new HashSet<>();

    public Collector(Path root) { this.root = root; }

    public String rel(Path p) { return root.relativize(p.toAbsolutePath().normalize()).toString().replace('\\', '/'); }

    public void add(String eco, String name, String version, Path file, String scope, boolean approximate) {
        String f = rel(file);
        if (seen.add(List.of(eco, name, version, f, scope))) deps.add(new Dependency(eco, name, version, f, scope, approximate));
    }

    public void miss(String eco, String name, String declared, Path file, Phrase reason) {
        unresolved.add(new Unresolved(eco, name, declared == null ? "" : declared, rel(file), reason));
    }
}
