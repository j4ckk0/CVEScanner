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
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.FindingFilter;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.project.GradleCache;
import org.jtools.cvescanner.project.MavenRepository;

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
    /** The report's filters, the window's own: --min-severity, --ecosystem, --hide-approximate, --hide-name-matches, --search. */
    public Severity minSeverity;
    public final Set<Ecosystem> ecosystems = new LinkedHashSet<>();
    public boolean hideApproximate, hideNameMatches;
    public final List<String> searchWords = new ArrayList<>();
    /** --apply-fixes: the fixes planned and said; applied with --yes, a major version change only with --allow-major. */
    public boolean applyFixes, yes, allowMajor;
    /** --fix-packages: the packages to fix, the others left; empty for every one the report keeps. */
    public final Set<String> fixPackages = new LinkedHashSet<>();
    /** --ignore-add ID, --ignore-remove ID, --ignore-list: the ignore file edited or listed, no scan run. */
    public String ignoreAdd, ignoreRemove;
    public boolean ignoreList;
    /** The entry's --package, --version, --reason, --until; null when not given. */
    public String ignorePackage, ignoreVersion, ignoreReason;
    public LocalDate ignoreUntil;
    /** --vex FILE: VEX documents read besides the *.vex.json of the folder scanned. */
    public final List<Path> vexFiles = new ArrayList<>();
    /** --db-max-age: a database whose newest record is older than this many days is said to be; 0 for never. */
    public int dbMaxAgeDays = ScanOptions.DEFAULT_DB_MAX_AGE_DAYS;
    /** --maven-repo DIR: the local Maven repository read for the transitive dependencies; null for the home folder's. */
    public Path mavenRepository;
    /** --gradle-cache DIR: Gradle's cache (files-2.1) read for the builds' transitive dependencies; null for the home folder's. */
    public Path gradleCache;
    /** --no-transitive: neither the local Maven repository nor Gradle's cache read, the declared dependencies only. */
    public boolean noTransitive;
    /** The day the scan counts from: today, a fixed one in the tests. */
    LocalDate today = LocalDate.now();
    /** Whether the home folder's Maven repository and Gradle cache are read when none is named: never in the tests. */
    boolean homeCaches = true;

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
                case "--vex" -> o.vexFiles.add(Path.of(value(args, ++i, a)));
                case "--maven-repo" -> o.mavenRepository = Path.of(value(args, ++i, a));
                case "--no-transitive" -> o.noTransitive = true;
                case "--gradle-cache" -> o.gradleCache = Path.of(value(args, ++i, a));
                case "--installed" -> o.installed = true;
                case "--min-severity" -> {
                    o.minSeverity = Severity.fromRating(value(args, ++i, a));
                    if (o.minSeverity == Severity.UNKNOWN) throw new IllegalArgumentException(I18n.text("option.minSeverity"));
                }
                case "--ecosystem" -> {
                    for (String name : value(args, ++i, a).split(",")) {
                        Ecosystem e = Ecosystem.named(name);
                        if (e == null) throw new IllegalArgumentException(I18n.text("option.ecosystem", name.strip()));
                        o.ecosystems.add(e);
                    }
                }
                case "--hide-approximate" -> o.hideApproximate = true;
                case "--hide-name-matches" -> o.hideNameMatches = true;
                case "--search" -> o.searchWords.addAll(List.of(value(args, ++i, a).strip().split("\\s+")));
                case "--apply-fixes" -> o.applyFixes = true;
                case "--yes" -> o.yes = true;
                case "--allow-major" -> o.allowMajor = true;
                case "--fix-packages" -> {
                    for (String name : value(args, ++i, a).split(",")) if (!name.isBlank()) o.fixPackages.add(name.strip());
                }
                case "--ignore-add" -> o.ignoreAdd = value(args, ++i, a);
                case "--ignore-remove" -> o.ignoreRemove = value(args, ++i, a);
                case "--ignore-list" -> o.ignoreList = true;
                case "--db-max-age" -> {
                    try {
                        o.dbMaxAgeDays = Integer.parseInt(value(args, ++i, a).strip());
                    } catch (NumberFormatException _) {
                        o.dbMaxAgeDays = -1;
                    }
                    if (o.dbMaxAgeDays < 0) throw new IllegalArgumentException(I18n.text("option.dbMaxAge"));
                }
                case "--package" -> o.ignorePackage = value(args, ++i, a);
                case "--version" -> o.ignoreVersion = value(args, ++i, a);
                case "--reason" -> o.ignoreReason = value(args, ++i, a);
                case "--until" -> o.ignoreUntil = IgnoreRule.until(value(args, ++i, a), LocalDate.now());
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
        if (o.noTransitive && (o.mavenRepository != null || o.gradleCache != null))
            throw new IllegalArgumentException(I18n.text("option.mavenRepoBoth"));
        long edits = (o.ignoreAdd != null ? 1 : 0) + (o.ignoreRemove != null ? 1 : 0) + (o.ignoreList ? 1 : 0);
        if (edits > 1 || (edits == 1 && o.noIgnore)) throw new IllegalArgumentException(I18n.text("option.ignoreEdit"));
        if (o.ignoreAdd != null && (o.ignoreReason == null || o.ignoreReason.isBlank()))
            throw new IllegalArgumentException(I18n.text("option.ignoreReason"));
        boolean entryFields = o.ignorePackage != null || o.ignoreVersion != null;
        if ((o.ignoreAdd == null && (o.ignoreReason != null || o.ignoreUntil != null))
                || (o.ignoreAdd == null && o.ignoreRemove == null && entryFields))
            throw new IllegalArgumentException(I18n.text("option.ignoreFields"));
        if (!o.applyFixes && (o.yes || o.allowMajor || !o.fixPackages.isEmpty()))
            throw new IllegalArgumentException(I18n.text("option.fixNeedsApply"));
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

    /** The findings the reports keep, the counts and --fail-on count: the window's filters, as the options set them. */
    public FindingFilter filter() {
        return new FindingFilter(minSeverity, ecosystems, cveOnly, hideApproximate, hideNameMatches, searchWords);
    }

    /** Whether the ignore file is to be edited or listed (--ignore-add, --ignore-remove, --ignore-list) rather than a scan run. */
    public boolean ignoreEdit() {
        return ignoreAdd != null || ignoreRemove != null || ignoreList;
    }

    /** How Engine.scan runs: the ignore file, the mode, the databases' age limit, today, the VEX documents, the Maven repository. */
    /** The local Maven repository a scan reads: --maven-repo's, else the home folder's if there is one; null with --no-transitive. */
    public Path mavenRepository() {
        if (noTransitive) return null;
        if (mavenRepository != null) return mavenRepository;
        if (!homeCaches) return null;
        Path home = MavenRepository.locate(Path.of(System.getProperty("user.home")));
        return java.nio.file.Files.isDirectory(home) ? home : null;   // no Maven here: none read, the reports saying so
    }

    /** Gradle's cache a scan reads: --gradle-cache's, else the home folder's (GRADLE_USER_HOME) if there is one; null with --no-transitive. */
    public Path gradleCache() {
        if (noTransitive) return null;
        if (gradleCache != null) return gradleCache;
        if (!homeCaches) return null;
        Path home = GradleCache.locate(Path.of(System.getProperty("user.home")), System.getenv("GRADLE_USER_HOME"));
        return java.nio.file.Files.isDirectory(home) ? home : null;
    }

    public ScanOptions scanOptions() {
        return new ScanOptions(ignoreChoice(), mode(), dbMaxAgeDays, today, vexFiles, mavenRepository(), gradleCache());
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
