package org.jtools.cvescanner.cli;

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
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoreFile;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.Ignores;

/**
 * The ignore file edited from the command line, as the window's Ignore this finding… and Stop ignoring do: an entry
 * added, the entries naming a vulnerability removed, or the entries listed. No scan runs.
 */
final class CliIgnore {

    private CliIgnore() {}

    /** 0 once done; 1 when the file cannot be read or written, or when no entry is there to remove. */
    static int run(Options o, PrintStream out, PrintStream err) {
        try {
            if (o.ignoreAdd != null) return add(o, out);
            var ignores = Ignores.load(o.scanDir, o.ignoreFile, w -> err.println(I18n.text("cli.warning", w)));
            return o.ignoreRemove != null ? remove(o, ignores, out, err) : list(ignores, out);
        } catch (IOException e) {
            err.println(I18n.text("cli.error", e.getMessage()));
            return 1;
        }
    }

    private static int add(Options o, PrintStream out) throws IOException {
        Path file = (o.ignoreFile != null ? o.ignoreFile : o.scanDir.resolve(IgnoreFile.NAME)).toAbsolutePath().normalize();
        var rule = new IgnoreRule(o.ignoreAdd, o.ignorePackage, o.ignoreVersion, o.ignoreUntil, o.ignoreReason, 0);
        IgnoreFile.append(file, rule);
        out.println(I18n.text("cli.ignore.added", file, describe(rule)));
        return 0;
    }

    private static int remove(Options o, Ignores ignores, PrintStream out, PrintStream err) throws IOException {
        List<IgnoreRule> named = ignores.rules().stream()
                .filter(r -> r.id().equalsIgnoreCase(o.ignoreRemove.strip()))
                .filter(r -> o.ignorePackage == null || r.pkg().equalsIgnoreCase(o.ignorePackage.strip()))
                .filter(r -> o.ignoreVersion == null || r.version().equals(o.ignoreVersion.strip()))
                .toList();
        if (named.isEmpty()) {
            err.println(I18n.text("cli.ignore.noneRemoved", ignores.shown(), o.ignoreRemove.strip()));
            return 1;
        }
        for (var rule : named)
            if (IgnoreFile.remove(ignores.file(), rule)) out.println(I18n.text("cli.ignore.removed", ignores.shown(), describe(rule)));
        return 0;
    }

    private static int list(Ignores ignores, PrintStream out) {
        if (ignores.rules().isEmpty()) out.println(I18n.text("cli.ignore.empty", ignores.shown()));
        for (var rule : ignores.rules()) out.println(rule.line() + ": " + describe(rule));
        return 0;
    }

    /** An entry in one line: id · package · version · last day · reason, "any" for an empty package or version. */
    static String describe(IgnoreRule rule) {
        String any = I18n.text("cli.ignore.any");
        return String.join("  ·  ", rule.id(), rule.pkg().isEmpty() ? any : rule.pkg(), rule.version().isEmpty() ? any : rule.version(),
                rule.until() == null ? I18n.text("cli.ignore.noEnd") : rule.until().toString(), rule.reason());
    }
}
