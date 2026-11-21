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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.ScanMode;

public final class Options {
    /** The options and what they do, in the language in use. */
    public static String usage() { return I18n.text("cli.usage"); }

    public Path scanDir = Path.of(".");
    public boolean dirGiven;
    public Path outDir = Path.of("cve-report");
    public boolean cveOnly, noGui, help;
    /** The language --lang asks for; null when none is given. */
    public I18nLanguage language;
    Severity failOn;
    public final List<Path> dbFiles = new ArrayList<>();
    public Path dbDir;
    public Environment environment = Environment.NONE;
    public boolean environmentGiven;
    public boolean preferV4 = true, cvssGiven;
    /** The ignore file --ignore names; null for the folder's own. */
    public Path ignoreFile;
    /** --no-ignore: every finding reported, the folder's ignore file left unread. */
    public boolean noIgnore;
    /** --installed: an installed product, read from what it ships, rather than source projects. */
    public boolean installed;

    public static Options parse(String[] args) {
        var o = new Options();
        Environment preset = Environment.NONE;
        Reach reach = null;
        Requirement cr = null, ir = null, ar = null;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-d", "--dir" -> { o.scanDir = Path.of(value(args, ++i, a)); o.dirGiven = true; }
                case "-o", "--out" -> o.outDir = Path.of(value(args, ++i, a));
                case "--db" -> o.dbFiles.add(Path.of(value(args, ++i, a)));
                case "--db-dir" -> o.dbDir = Path.of(value(args, ++i, a));
                case "--env" -> { preset = Environment.preset(value(args, ++i, a)); o.environmentGiven = true; }
                case "--reach" -> { reach = Reach.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--cr" -> { cr = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--ir" -> { ir = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--ar" -> { ar = Requirement.parse(value(args, ++i, a)); o.environmentGiven = true; }
                case "--cvss" -> {
                    String v = value(args, ++i, a);
                    if (!v.equals("4") && !v.equals("3")) throw new IllegalArgumentException(I18n.text("option.cvss"));
                    o.preferV4 = v.equals("4");
                    o.cvssGiven = true;
                }
                case "--ignore" -> o.ignoreFile = Path.of(value(args, ++i, a));
                case "--no-ignore" -> o.noIgnore = true;
                case "--installed" -> o.installed = true;
                case "--cve-only" -> o.cveOnly = true;
                case "--no-gui" -> o.noGui = true;
                case "--fail-on" -> o.failOn = Severity.parseThreshold(value(args, ++i, a));
                case "--lang" -> o.language = language(value(args, ++i, a));
                case "-h", "--help" -> o.help = true;
                default -> {
                    if (a.startsWith("-")) throw new IllegalArgumentException(I18n.text("option.unknown", a));
                    o.scanDir = Path.of(a);
                    o.dirGiven = true;
                }
            }
        }
        if (o.noIgnore && o.ignoreFile != null) throw new IllegalArgumentException(I18n.text("option.ignoreBoth"));
        o.environment = reach == null && cr == null && ir == null && ar == null ? preset
                : Environment.of(reach != null ? reach : preset.reach(), cr != null ? cr : preset.confidentiality(),
                                 ir != null ? ir : preset.integrity(), ar != null ? ar : preset.availability());
        if (o.dbDir != null && Files.isDirectory(o.dbDir)) {
            try (var files = Files.list(o.dbDir)) {
                files.filter(f -> f.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zip") && Files.isRegularFile(f))
                        .sorted().forEach(o.dbFiles::add);
            } catch (IOException e) {
                throw new IllegalArgumentException(I18n.text("option.dbDir", o.dbDir, e.getMessage()));
            }
        }
        return o;
    }

    /**
     * The language the arguments ask for (--lang fr|en), read before the others so that what they say is said in it;
     * null when they ask for none, or for one the program does not speak (parse then says so).
     */
    public static I18nLanguage requestedLanguage(String[] args) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (args[i].equals("--lang")) {
                for (I18nLanguage l : I18nLanguage.values()) if (l.code().equals(args[i + 1])) return l;
            }
        }
        return null;
    }

    public ScanMode mode() {
        return installed ? ScanMode.INSTALLED : ScanMode.SOURCES;
    }

    /** The ignore file for Engine.scan: the one named, none (--no-ignore), or null for the folder's own. */
    public Path ignoreChoice() {
        return noIgnore ? Ignores.DISABLED : ignoreFile;
    }

    private static I18nLanguage language(String code) {
        for (I18nLanguage l : I18nLanguage.values()) if (l.code().equals(code)) return l;
        throw new IllegalArgumentException(I18n.text("option.lang"));
    }

    private static String value(String[] args, int i, String opt) {
        if (i >= args.length) throw new IllegalArgumentException(I18n.text("option.needsValue", opt));
        return args[i];
    }
}
