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
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The Python packages an installed product ships: each *.dist-info/METADATA (or *.egg-info/PKG-INFO) of its
 * site-packages, its Name and Version headers, which come before the first blank line.
 */
public final class PythonReader {

    private PythonReader() {}

    public static void scan(List<Path> metadata, DependencyCollector col, Consumer<Phrase> warn) {
        for (Path file : metadata) {
            try {
                String name = null, version = null;
                for (String line : ProjectFiles.readText(file).lines().toList()) {
                    if (line.isBlank()) break;
                    if (line.startsWith("Name:") && name == null) name = line.substring(5).strip();
                    else if (line.startsWith("Version:") && version == null) version = line.substring(8).strip();
                }
                if (name != null && version != null && !name.isEmpty() && !version.isEmpty())
                    col.add(Ecosystem.PYPI, name, version, file, "installed", false);
            } catch (IOException | RuntimeException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(file), e.getMessage()));
            }
        }
    }
}
