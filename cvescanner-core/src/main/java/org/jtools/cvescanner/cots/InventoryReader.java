package org.jtools.cvescanner.cots;

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
import java.util.Locale;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The components off-the-shelf a project lists itself, in a cots.csv (or a *.cots.csv): a line each,
 * name,version[,vendor][,cpe] — "gdal,3.4.1", "libfoo,1.2,acme", "x,,,cpe:2.3:a:osgeo:gdal:3.4.1" —, lines beginning
 * with # left out, a header line "name,…" too. A CPE names the component exactly; a vendor with the name, or the name
 * known to KnownProducts, gives vendor:product; any other name is a product alone.
 */
public final class InventoryReader {

    private InventoryReader() {
    }

    public static void scan(List<Path> inventories, DependencyCollector col, Consumer<Phrase> warn) {
        for (Path file : inventories) {
            try {
                for (String line : ProjectFiles.readText(file).lines().toList()) read(line, file, col);
            } catch (IOException | RuntimeException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(file), e.getMessage()));
            }
        }
    }

    private static void read(String line, Path file, DependencyCollector col) {
        String text = line.strip();
        if (text.isEmpty() || text.startsWith("#") || text.toLowerCase(Locale.ROOT).startsWith("name,")) return;
        String[] f = (text + ",,,").split(",", -1);
        String name = f[0].strip(), version = f[1].strip(), vendor = f[2].strip(), cpe = f[3].strip();
        String id;
        String[] parts = cpe.startsWith("cpe:2.3:") ? Cpe.fields(cpe) : null;
        if (parts != null && (!names(parts[3]) || !names(parts[4]))) {
            // a CPE without a vendor or a product names no component: said, with what the line gives
            col.miss(Ecosystem.COTS, name.isEmpty() ? cpe : name, version, file, Phrase.of("reason.cpeNoProduct"));
            return;
        }
        if (parts != null) {
            id = parts[3] + ":" + parts[4];
            if (version.isEmpty() && !parts[5].equals("*") && !parts[5].equals("-")) version = parts[5];
            if (name.isEmpty()) name = parts[4];
        } else if (!vendor.isEmpty()) {
            id = vendor.toLowerCase(Locale.ROOT) + ":" + name.toLowerCase(Locale.ROOT);
        } else {
            id = KnownProducts.identify(name);
        }
        if (name.isEmpty() && cpe.isEmpty()) return;
        if (version.isEmpty()) col.miss(Ecosystem.COTS, id, "", file, Phrase.of("reason.noVersion"));
        else col.add(Ecosystem.COTS, id, version, file, "inventory", false);
    }

    /** Whether a CPE field names something: not empty, not ANY (*) nor NA (-). */
    private static boolean names(String field) {
        return !field.isEmpty() && !field.equals("*") && !field.equals("-");
    }
}
