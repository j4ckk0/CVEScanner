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
import java.nio.file.Path;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.jtools.cvescanner.cots.BinaryReader;
import org.jtools.cvescanner.cots.InventoryReader;
import org.jtools.cvescanner.cots.ManifestReader;
import org.jtools.cvescanner.cots.SbomReader;
import org.jtools.cvescanner.db.VulnDb;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.installed.InstalledNpmReader;
import org.jtools.cvescanner.installed.JarReader;
import org.jtools.cvescanner.installed.PythonReader;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.project.DependencyCollector;
import org.jtools.cvescanner.project.GradleReader;
import org.jtools.cvescanner.project.MavenReader;
import org.jtools.cvescanner.project.NpmReader;
import org.jtools.cvescanner.project.ProjectFiles;

public final class Engine {
    private Engine() {}

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
        ScanListener l = new ScanListener() {
            public void status(String m) { listener.status(m); }
            public void progress(double f) { listener.progress(f); }
            public void warn(Phrase m) { warnings.add(m); listener.warn(m); }
        };

        var ignores = Ignores.load(root, ignoreFile, l::warn);   // first: a file named that is not there stops the scan now
        l.status(I18n.text("status.lookingFor", root));
        l.progress(-1);
        var files = ProjectFiles.find(root, mode);
        var col = new DependencyCollector(root);
        MavenReader.scan(files.poms, col, l::warn);
        GradleReader.scan(files.gradle, files.gradleProps, col);
        GradleReader.scanCatalogs(files.catalogs, col);
        NpmReader.scan(files.packageJsons, root, col, l::warn);
        InventoryReader.scan(files.cotsInventories, col, l::warn);
        SbomReader.scan(files.sboms, col, l::warn);
        ManifestReader.scan(files.pkgConfigs, files.vcpkgManifests, files.conanFiles, col, l::warn);
        BinaryReader.scan(files.binaries, col);
        JarReader.scan(files.jars, col, l::warn);
        InstalledNpmReader.scan(files.installedPackageJsons, col, l::warn);
        PythonReader.scan(files.pythonMetadata, col, l::warn);

        var wanted = VulnDb.Wanted.of(col.deps);
        var index = new VulnDb.Index();
        if (!col.deps.isEmpty()) {
            if (dbFiles.isEmpty())
                throw new IOException(I18n.text("error.noDatabase"));
            index = VulnDb.load(dbFiles, wanted, l);
        }
        index.newest.forEach((file, newest) -> {
            long days = ChronoUnit.DAYS.between(newest, options.today());
            if (options.dbMaxAgeDays() > 0 && days > options.dbMaxAgeDays())
                l.warn(Phrase.of("warning.dbOld", file, newest.toString(), days, options.dbMaxAgeDays()));
        });

        l.status(I18n.text("status.matching", col.deps.size()));
        l.progress(-1);
        var findings = new ArrayList<Finding>();
        for (var d : col.deps) findings.addAll(Matcher.findings(d, index));
        findings.sort(Finding.ORDER);
        var counts = new LinkedHashMap<String, Integer>();
        if (mode == ScanMode.SOURCES) {
            counts.put("files.pom", files.poms.size());
            counts.put("files.gradle", files.gradle.size());
            counts.put("files.catalogs", files.catalogs.size());
            counts.put("files.packageJson", files.packageJsons.size());
        }
        // what an installed product ships, said only when there is some
        if (!files.jars.isEmpty()) counts.put("files.jars", files.jars.size());
        if (!files.installedPackageJsons.isEmpty()) counts.put("files.installedPackages", files.installedPackageJsons.size());
        if (!files.pythonMetadata.isEmpty()) counts.put("files.pythonPackages", files.pythonMetadata.size());
        // the files of components off-the-shelf, said only when there are some
        if (!files.cotsInventories.isEmpty()) counts.put("files.cotsInventories", files.cotsInventories.size());
        if (!files.sboms.isEmpty()) counts.put("files.sboms", files.sboms.size());
        int manifests = files.pkgConfigs.size() + files.vcpkgManifests.size() + files.conanFiles.size();
        if (manifests > 0) counts.put("files.manifests", manifests);
        if (!files.binaries.isEmpty()) counts.put("files.binaries", files.binaries.size());
        return new ScanResult(root, List.copyOf(findings), List.copyOf(col.deps), List.copyOf(col.unresolved),
                index.sources, counts, List.copyOf(warnings), ignores, mode);
    }
}
