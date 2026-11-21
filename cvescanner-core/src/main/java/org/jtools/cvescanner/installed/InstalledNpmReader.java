package org.jtools.cvescanner.installed;

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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The npm packages an installed product ships: each node_modules/<name>/package.json (and @scope/<name>), the nested
 * ones too, says the exact version installed — the transitive packages included, which no project manifest names.
 */
public final class InstalledNpmReader {

    private InstalledNpmReader() {}

    public static void scan(List<Path> packageJsons, DependencyCollector col, Consumer<Phrase> warn) {
        for (Path file : packageJsons) {
            try {
                var json = Json.obj(Json.parse(ProjectFiles.readText(file)));
                String name = Json.str(json, "name"), version = Json.str(json, "version");
                if (name != null && version != null && !name.isBlank() && !version.isBlank())
                    col.add(Ecosystem.NPM, name.strip(), version.strip(), file, "installed", false);
            } catch (IOException | RuntimeException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(file), e.getMessage()));
            }
        }
    }
}
