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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.project.ProjectFiles;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * An ignore file, cvescanner-ignore.csv: id,package,version,until,reason, one entry a line, as a spreadsheet writes CSV
 * (a field holding a comma is quoted). Lines starting with # are comments, a line starting with "id," is the header.
 * Written only when asked to (the window's Ignore… and Stop ignoring), every other line kept as it was.
 */
public final class IgnoreFile {

    /** The ignore file a scan reads when none is named: at the root of the folder scanned. */
    public static final String NAME = "cvescanner-ignore.csv";

    static final String HEADER = """
            # CVEScanner: the findings reviewed and set aside. One entry a line:
            #   id       an advisory (GHSA-…), a CVE or an alias; a CVE sets aside every advisory naming it
            #   package  the package as CVEScanner shows it (group:artifact, an npm name, vendor:product); empty: any
            #   version  that version only; empty: any
            #   until    the last day it applies, yyyy-MM-dd; empty: for ever
            #   reason   why
            id,package,version,until,reason
            """;

    private IgnoreFile() {}

    /**
     * Its entries. A line without an id, or with a date that is not one, is left out, and said with warn.
     *
     * @param shown the file as the warnings name it
     */
    public static List<IgnoreRule> read(Path file, String shown, Consumer<Phrase> warn) throws IOException {
        var rules = new ArrayList<IgnoreRule>();
        List<String> lines = ProjectFiles.readText(file).lines().toList();
        for (int i = 0; i < lines.size(); i++) {
            String line = i == 0 ? lines.get(i).replace("﻿", "") : lines.get(i);
            if (skipped(line)) continue;
            List<String> f = split(line);
            String id = field(f, 0), until = field(f, 3);
            if (id.isEmpty()) {
                warn.accept(Phrase.of("ignore.warning.noId", shown, i + 1));
                continue;
            }
            LocalDate date = null;
            if (!until.isEmpty()) {
                try {
                    date = LocalDate.parse(until);
                } catch (DateTimeParseException _) {
                    warn.accept(Phrase.of("ignore.warning.badDate", shown, i + 1, until));
                    continue;
                }
            }
            rules.add(new IgnoreRule(id, field(f, 1), field(f, 2), date, reason(f), i + 1));
        }
        return rules;
    }

    /** Adds an entry at its end; writes the file, with its header, when there is none. */
    public static void append(Path file, IgnoreRule rule) throws IOException {
        String text = Files.exists(file) ? ProjectFiles.readText(file) : HEADER;
        String lineBreak = text.contains("\r\n") ? "\r\n" : "\n";   // the file's own, should it be Windows'
        if (!text.isEmpty() && !text.endsWith("\n")) text += lineBreak;
        write(file, text + line(rule) + lineBreak);
    }

    /**
     * Takes out the line of this entry, found by what it says rather than by its number, so that the file may have been
     * edited meanwhile; every other line stays as written. False when no line says it.
     */
    public static boolean remove(Path file, IgnoreRule rule) throws IOException {
        if (!Files.exists(file)) return false;
        String text = ProjectFiles.readText(file);
        String[] lines = text.split("(?<=\n)", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = (i == 0 ? lines[i].replace("﻿", "") : lines[i]).strip();
            if (skipped(line)) continue;
            List<String> f = split(line);
            LocalDate until;
            try {
                until = field(f, 3).isEmpty() ? null : LocalDate.parse(field(f, 3));
            } catch (DateTimeParseException _) {
                continue;
            }
            if (new IgnoreRule(field(f, 0), field(f, 1), field(f, 2), until, reason(f), i + 1).sameEntry(rule)) {
                var kept = new ArrayList<>(Arrays.asList(lines));
                kept.remove(i);
                write(file, String.join("", kept));
                return true;
            }
        }
        return false;
    }

    /** An entry as a line of the file, without its line break. */
    static String line(IgnoreRule rule) {
        return join(List.of(rule.id(), rule.pkg(), rule.version(), rule.until() == null ? "" : rule.until().toString(),
                rule.reason()));
    }

    private static boolean skipped(String line) {
        String s = line.strip();
        return s.isEmpty() || s.startsWith("#") || s.toLowerCase(Locale.ROOT).startsWith("id,");
    }

    private static String field(List<String> fields, int i) {
        return i < fields.size() ? fields.get(i).strip() : "";
    }

    /** The reason: the fifth field, and those after it when a comma in an unquoted reason made more. */
    private static String reason(List<String> fields) {
        return fields.size() <= 4 ? "" : String.join(",", fields.subList(4, fields.size())).strip();
    }

    /** The written file in one move: never a half-written one, should the program stop meanwhile. */
    private static void write(Path file, String text) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path temp = Files.createTempFile(dir, ".cvescanner-ignore", ".tmp");
        try {
            Files.writeString(temp, text, UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException _) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** A CSV line's fields: separated by commas, a quoted field holding commas and doubled quotes. */
    static List<String> split(String line) {
        var fields = new ArrayList<String>();
        var field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = false;
                } else {
                    field.append(c);
                }
            } else if (c == '"' && field.toString().isBlank()) {
                field.setLength(0);
                quoted = true;
            } else if (c == ',') {
                fields.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        fields.add(field.toString());
        return fields;
    }

    /** Fields as a CSV line: quoted when they hold a comma, a quote or blanks at an end; a line break becomes a space. */
    static String join(List<String> fields) {
        var out = new ArrayList<String>();
        for (String f : fields) {
            String s = f.replaceAll("[\\r\\n]+", " ");
            boolean quote = s.contains(",") || s.contains("\"") || !s.equals(s.strip());
            out.add(quote ? "\"" + s.replace("\"", "\"\"") + "\"" : s);
        }
        return String.join(",", out);
    }
}
