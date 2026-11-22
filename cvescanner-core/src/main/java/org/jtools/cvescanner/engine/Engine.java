package org.jtools.cvescanner.engine;

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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jtools.cvescanner.cots.BinaryReader;
import org.jtools.cvescanner.cots.InventoryReader;
import org.jtools.cvescanner.cots.ManifestReader;
import org.jtools.cvescanner.cots.SbomReader;
import org.jtools.cvescanner.db.VulnDb;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.ignore.VexFile;
import org.jtools.cvescanner.ignore.VexStatement;
import org.jtools.cvescanner.installed.InstalledNpmReader;
import org.jtools.cvescanner.installed.JarReader;
import org.jtools.cvescanner.installed.PythonReader;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.GradleCache;
import org.jtools.cvescanner.project.GradleReader;
import org.jtools.cvescanner.project.MavenReader;
import org.jtools.cvescanner.project.MavenRepository;
import org.jtools.cvescanner.project.NpmReader;
import org.jtools.cvescanner.project.ProjectFiles;
import org.jtools.cvescanner.project.PythonProjectReader;

public final class Engine {
    private Engine() {}

    /** The statements of the folder's VEX documents and of those named, each document read once. */
    private static Ignores withVex(Ignores ignores, Path root, List<Path> found, List<Path> named, ScanListener l) {
        var documents = new LinkedHashSet<Path>();
        for (Path p : found) documents.add(p.toAbsolutePath().normalize());
        for (Path p : named) documents.add(p.toAbsolutePath().normalize());
        var statements = new ArrayList<VexStatement>();
        for (Path doc : documents) {
            String shown = (doc.startsWith(root) ? root.relativize(doc) : doc).toString().replace('\\', '/');
            try {
                statements.addAll(VexFile.read(doc, shown, l::warn));
            } catch (IOException e) {
                l.warn(Phrase.of("vex.warning.unreadable", shown, e.getMessage()));
            }
        }
        return statements.isEmpty() ? ignores : ignores.withVex(statements);
    }

    /** A scan reading the folder's own ignore file, if it has one. */
    public static ScanResult scan(Path dir, List<Path> dbFiles, ScanListener listener) throws IOException {
        return scan(dir, dbFiles, (Path) null, listener);
    }

    /**
     * @param dbFiles    the database zips the user gave: the only source of vulnerability data, the program fetching none
     * @param ignoreFile the ignore file: null for the folder's own cvescanner-ignore.csv, if any; Ignores.DISABLED for none
     */
    public static ScanResult scan(Path dir, List<Path> dbFiles, Path ignoreFile, ScanListener listener) throws IOException {
        return scan(dir, dbFiles, ignoreFile, ScanMode.SOURCES, listener);
    }

    public static ScanResult scan(Path dir, List<Path> dbFiles, Path ignoreFile, ScanMode mode, ScanListener listener) throws IOException {
        return scan(dir, dbFiles, ScanOptions.of(ignoreFile, mode), listener);
    }

    public static ScanResult scan(Path dir, List<Path> dbFiles, ScanOptions options, ScanListener listener) throws IOException {
        Path ignoreFile = options.ignoreFile();
        ScanMode mode = options.mode();
        Path root = dir.toAbsolutePath().normalize();
        var warnings = new ArrayList<Phrase>();
        ScanListener l = recording(listener, warnings);

        var ignores = Ignores.load(root, ignoreFile, l::warn);
        for (Path named : options.vexFiles())   // as the ignore file: a document named that is not there stops the scan, before any search
            if (!Files.isRegularFile(named)) throw new IOException(I18n.text("error.vexMissing", named));
        l.status(I18n.text("status.lookingFor", root));
        l.progress(-1);
        var files = ProjectFiles.find(root, mode);
        ignores = withVex(ignores, root, files.vexFiles, options.vexFiles(), l);
        var col = new DependencyCollector(root);
        boolean direct = options.directOnly() && mode == ScanMode.SOURCES;
        Path m2 = direct ? null : options.mavenRepository(), gradleCache = direct ? null : options.gradleCache();
        MavenReader.scan(files.poms, col, l::warn, m2 == null ? null : new MavenRepository(m2));
        GradleReader.scan(files.gradle, files.gradleProps, files.catalogs, files.gradleLocks, col, l::warn,
                gradleCache == null ? null : new GradleCache(gradleCache));
        NpmReader.scan(files.packageJsons, root, col, l::warn);
        InventoryReader.scan(files.cotsInventories, col, l::warn);
        SbomReader.scan(files.sboms, col, l::warn);
        ManifestReader.scan(files.pkgConfigs, files.vcpkgManifests, files.conanFiles, col, l::warn);
        BinaryReader.scan(files.binaries, col);
        JarReader.scan(files.jars, col, l::warn);
        InstalledNpmReader.scan(files.installedPackageJsons, col, l::warn);
        PythonReader.scan(files.pythonMetadata, col, l::warn);
        PythonProjectReader.scan(files.pythonProjects, col, l::warn);
        if (direct) col.deps.removeIf(Dependency::transitive);   // the lockfiles' indirect packages: what the project declares only

        var matched = match(col.deps, dbFiles, options, l);
        var counts = new LinkedHashMap<String, Integer>();
        if (mode == ScanMode.SOURCES) {
            counts.put("files.pom", files.poms.size());
            counts.put("files.gradle", files.gradle.size());
            counts.put("files.catalogs", files.catalogs.size());
            counts.put("files.packageJson", files.packageJsons.size());
        }
        // what an installed product ships, and the Python projects, said only when there are some
        if (!files.jars.isEmpty()) counts.put("files.jars", files.jars.size());
        if (!files.installedPackageJsons.isEmpty()) counts.put("files.installedPackages", files.installedPackageJsons.size());
        if (!files.pythonMetadata.isEmpty()) counts.put("files.pythonPackages", files.pythonMetadata.size());
        if (!files.pythonProjects.isEmpty()) counts.put("files.pythonProjects", files.pythonProjects.size());
        // the files of components off-the-shelf, said only when there are some
        if (!files.cotsInventories.isEmpty()) counts.put("files.cotsInventories", files.cotsInventories.size());
        if (!files.sboms.isEmpty()) counts.put("files.sboms", files.sboms.size());
        int manifests = files.pkgConfigs.size() + files.vcpkgManifests.size() + files.conanFiles.size();
        if (manifests > 0) counts.put("files.manifests", manifests);
        if (!files.binaries.isEmpty()) counts.put("files.binaries", files.binaries.size());
        return new ScanResult(root, matched.findings(), List.copyOf(col.deps), List.copyOf(col.unresolved),
                matched.databases(), counts, List.copyOf(warnings), ignores, mode, mode == ScanMode.SOURCES ? m2 : null,
                mode == ScanMode.SOURCES && !files.gradle.isEmpty() ? gradleCache : null, !direct && !files.gradleLocks.isEmpty(), direct);
    }

    /** The warnings of the databases a scan read: an analysis re-checked here says those of this computer's instead. */
    private static final Set<String> DATABASE_WARNINGS = Set.of("warning.noRecords", "warning.noDatabaseFor", "warning.dbOld");

    /**
     * An analysis made on another computer (AnalysisFile) matched again against these databases: its dependencies as
     * that computer read them, its unchecked ones, its warnings but its databases'. Its ignore entries apply, unless
     * options name another ignore file (Ignores.DISABLED: none); its VEX statements apply, and those of the documents
     * options name. With directOnly, the indirect dependencies of its projects are left out.
     */
    public static ScanResult recheck(ScanResult analysis, List<Path> dbFiles, ScanOptions options, ScanListener listener) throws IOException {
        boolean otherIgnores = options.ignoreFile() != null;
        var warnings = new ArrayList<Phrase>();
        for (Phrase w : analysis.warnings())
            if (!DATABASE_WARNINGS.contains(w.key()) && !(otherIgnores && w.key().startsWith("ignore."))) warnings.add(w);
        ScanListener l = recording(listener, warnings);
        Ignores ignores = otherIgnores ? Ignores.load(analysis.root(), options.ignoreFile(), l::warn) : analysis.ignores().withoutVex();
        for (Path named : options.vexFiles())
            if (!Files.isRegularFile(named)) throw new IOException(I18n.text("error.vexMissing", named));
        ignores = withVex(ignores.withVex(analysis.ignores().vex()), analysis.root(), List.of(), options.vexFiles(), l);
        boolean direct = analysis.directOnly() || options.directOnly() && analysis.mode() == ScanMode.SOURCES;
        var deps = direct ? analysis.dependencies().stream().filter(d -> !d.transitive()).toList() : analysis.dependencies();
        var matched = match(deps, dbFiles, options, l);
        var from = analysis.imported();
        var imported = new ScanResult.Imported(from == null ? null : from.file(), from == null ? null : from.exportedAt(),
                from == null ? null : from.version(), from == null ? analysis.root().toString() : from.root(), true,
                from == null ? null : from.environment(), from == null || from.preferV4());
        return new ScanResult(analysis.root(), matched.findings(), deps, analysis.unresolved(), matched.databases(),
                analysis.fileCounts(), List.copyOf(warnings), ignores, analysis.mode(), analysis.mavenRepository(),
                analysis.gradleCache(), analysis.gradleLocked(), direct, imported);
    }

    /** A listener passing everything on, the warnings kept too. */
    private static ScanListener recording(ScanListener listener, List<Phrase> warnings) {
        return new ScanListener() {
            public void status(String m) { listener.status(m); }
            public void progress(double f) { listener.progress(f); }
            public void warn(Phrase m) { warnings.add(m); listener.warn(m); }
        };
    }

    /** What matching the dependencies found: the findings, in Finding.ORDER, and the databases read (ScanResult.snapshots). */
    private record Matched(List<Finding> findings, Map<String, Phrase> databases) {}

    /**
     * The dependencies matched against the databases: loaded (none when there is nothing to match), said when they cover
     * none of an ecosystem's dependencies, or when they are old.
     */
    private static Matched match(List<Dependency> deps, List<Path> dbFiles, ScanOptions options, ScanListener l) throws IOException {
        var wanted = VulnDb.Wanted.of(deps);
        var index = new VulnDb.Index();
        if (!deps.isEmpty()) {
            if (dbFiles.isEmpty())
                throw new IOException(I18n.text("error.noDatabase"));
            index = VulnDb.load(dbFiles, wanted, l, options.cacheDir());
        }
        // the dependencies of an ecosystem none of the databases covers: said, as no finding would say it
        var unchecked = new java.util.TreeSet<Ecosystem>();
        for (Dependency d : deps)
            if (d.ecosystem() == Ecosystem.COTS ? !index.components : !index.packages) unchecked.add(d.ecosystem());
        if (!deps.isEmpty() && !unchecked.isEmpty())
            l.warn(Phrase.of("warning.noDatabaseFor", String.join(", ", unchecked.stream().map(Ecosystem::id).toList())));
        // how old each database is: the NVD feeds as one, by their newest record (a fresh 2003 feed may not have changed for weeks)
        var ages = new LinkedHashMap<Object, LocalDate>();
        for (var e : index.newest.entrySet()) {
            if (index.nvdFeeds.contains(e.getKey()) && index.nvdFeeds.size() > 1)
                ages.merge(Phrase.of("database.nvdFeeds", index.nvdFeeds.size()), e.getValue(), (a, b) -> a.isAfter(b) ? a : b);
            else ages.put(e.getKey(), e.getValue());
        }
        ages.forEach((database, newest) -> {
            long days = ChronoUnit.DAYS.between(newest, options.today());
            if (options.dbMaxAgeDays() > 0 && days > options.dbMaxAgeDays())
                l.warn(Phrase.of("warning.dbOld", database, newest.toString(), days, options.dbMaxAgeDays()));
        });

        l.status(I18n.text("status.matching", deps.size()));
        l.progress(-1);
        var findings = new ArrayList<Finding>();
        for (var d : deps) findings.addAll(Matcher.findings(d, index));
        findings.sort(Finding.ORDER);
        return new Matched(List.copyOf(findings), index.sources);
    }
}
