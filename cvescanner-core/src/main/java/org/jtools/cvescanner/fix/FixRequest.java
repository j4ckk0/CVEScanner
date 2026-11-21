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

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;

/**
 * An upgrade asked for: this package, from this version to the one fixing its findings, wherever the scan found it.
 * The target is the one the Packages tab showed when asked: the window's filters change no request once made.
 *
 * @param declarations the files declaring it (a pom, a build file, a catalog, a package.json or its lockfile), with the
 *                     scope the scan gave each
 */
public record FixRequest(Ecosystem ecosystem, String pkg, String from, String to, List<Declaration> declarations) {

    public record Declaration(Path file, String scope) {}

    public FixRequest {
        declarations = List.copyOf(declarations);
    }

    /** The upgrade of a package version to the version its row shows, declared where its findings were found. */
    public static FixRequest of(PackageSummary p, List<Finding> findings, Path root) {
        var where = new LinkedHashSet<Declaration>();
        for (var f : findings)
            if (f.ecosystem() == p.ecosystem() && f.pkg().equals(p.pkg()) && f.version().equals(p.version()))
                where.add(new Declaration(root.resolve(f.file()).toAbsolutePath().normalize(), f.scope()));
        return new FixRequest(p.ecosystem(), p.pkg(), p.version(), p.fixedIn(), List.copyOf(where));
    }
}
