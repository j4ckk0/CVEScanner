package org.jtools.cvescanner.ignore;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Finding;

/**
 * The ignore file of a scan and its entries.
 *
 * @param file  where the entries are read from and written to; null when the scan ignores nothing (--no-ignore)
 * @param shown the file as the reports and warnings name it: from the folder scanned when it is in it
 * @param read  whether the file was there and read: the reports speak of it only then
 */
public record Ignores(Path file, String shown, List<IgnoreRule> rules, boolean read) {

    /** No ignore file: everything is reported. */
    public static final Ignores NONE = new Ignores(null, "", List.of(), false);

    /** Asks a scan to read no ignore file, not even the folder's own (--no-ignore). */
    public static final Path DISABLED = Path.of("");

    public Ignores {
        rules = List.copyOf(rules);
    }

    /**
     * The ignore file of a scan of root: the one named, else the folder's own cvescanner-ignore.csv when there is one.
     * A file named that is not there is an error; a line that cannot be read is left out, and said with warn.
     *
     * @param named the file asked for; null for the folder's own, DISABLED for none
     */
    public static Ignores load(Path root, Path named, Consumer<Phrase> warn) throws IOException {
        if (DISABLED.equals(named)) return NONE;
        Path file = (named == null ? root.resolve(IgnoreFile.NAME) : named).toAbsolutePath().normalize();
        String shown = shown(root, file);
        if (!Files.isRegularFile(file)) {
            if (named != null) throw new IOException(I18n.text("error.ignoreMissing", file));
            return new Ignores(file, shown, List.of(), false);
        }
        return new Ignores(file, shown, IgnoreFile.read(file, shown, warn), true);
    }

    /** The same file read again, after the window wrote it. */
    public Ignores reload(Consumer<Phrase> warn) throws IOException {
        if (file == null) return this;
        if (!Files.isRegularFile(file)) return new Ignores(file, shown, List.of(), false);
        return new Ignores(file, shown, IgnoreFile.read(file, shown, warn), true);
    }

    private static String shown(Path root, Path file) {
        Path r = root.toAbsolutePath().normalize();
        return (file.startsWith(r) ? r.relativize(file) : file).toString().replace('\\', '/');
    }

    /**
     * The findings it sets aside and those it leaves, after the first entry naming each that has not expired; the
     * entries that have expired, and those in force that set none of these findings aside.
     *
     * @param today the day it is: an entry applies up to its date, that day included
     */
    public Split split(List<Finding> findings, LocalDate today) {
        var active = new ArrayList<Finding>();
        var ignored = new ArrayList<IgnoredFinding>();
        var used = new HashSet<IgnoreRule>();
        var live = rules.stream().filter(r -> !r.expired(today)).toList();
        for (var f : findings) {
            var rule = live.stream().filter(r -> r.matches(f)).findFirst();
            if (rule.isPresent()) {
                ignored.add(new IgnoredFinding(f, rule.get()));
                used.add(rule.get());
            } else {
                active.add(f);
            }
        }
        return new Split(this, active, ignored, rules.stream().filter(r -> r.expired(today)).toList(),
                live.stream().filter(r -> !used.contains(r)).toList());
    }

    /**
     * A scan's findings, those an ignore file sets aside apart.
     *
     * @param expired the entries past their date: their findings are reported again
     * @param unused  the entries in force that set aside no finding
     */
    public record Split(Ignores ignores, List<Finding> active, List<IgnoredFinding> ignored, List<IgnoreRule> expired,
                        List<IgnoreRule> unused) {

        public Split {
            active = List.copyOf(active);
            ignored = List.copyOf(ignored);
            expired = List.copyOf(expired);
            unused = List.copyOf(unused);
        }

        /** Findings without an ignore file. */
        public static Split none(List<Finding> findings) {
            return new Split(NONE, findings, List.of(), List.of(), List.of());
        }

        /** The findings, set aside or not, that pass this filter (--cve-only); the entries kept. */
        public Split filter(Predicate<Finding> keep) {
            return new Split(ignores, active.stream().filter(keep).toList(),
                    ignored.stream().filter(i -> keep.test(i.finding())).toList(), expired, unused);
        }

        /** The same set aside, these reported in place of the active ones (the window's filtered table, exported). */
        public Split withActive(List<Finding> shown) {
            return new Split(ignores, shown, ignored, expired, unused);
        }

        /** What a scan says of the file: its entries that expired, and those that set nothing aside. */
        public List<Phrase> warnings() {
            var out = new ArrayList<Phrase>();
            for (var r : expired) out.add(Phrase.of("ignore.warning.expired", ignores.shown(), r.line(), r.id(), r.until().toString()));
            for (var r : unused) out.add(Phrase.of("ignore.warning.unused", ignores.shown(), r.line(), r.id()));
            return out;
        }
    }
}
