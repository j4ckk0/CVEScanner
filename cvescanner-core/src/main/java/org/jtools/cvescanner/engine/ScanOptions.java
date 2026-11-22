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

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import org.jtools.cvescanner.model.ScanMode;

/**
 * How a scan runs, besides its folder and its databases.
 *
 * @param ignoreFile   the ignore file: null for the folder's own cvescanner-ignore.csv, if any; Ignores.DISABLED for none
 * @param mode         the projects' manifests (SOURCES), or what an installed product ships (INSTALLED)
 * @param dbMaxAgeDays a database whose newest record is older than this many days is said to be; 0 for never
 * @param today        the day the ages and the ignore file's last days are counted from
 * @param vexFiles     VEX documents named (--vex), read besides the *.vex.json of the folder scanned
 * @param mavenRepository the local Maven repository, read for the transitive dependencies of the poms; null for none
 * @param gradleCache  Gradle's cache (its files-2.1 folder), read for the transitive dependencies of the builds; null for none
 * @param cacheDir     where the databases' index is kept between scans (IndexCache); null for none
 * @param directOnly   the project's declared dependencies only, in a scan of SOURCES: no Maven repository or Gradle
 *                     cache read, and the lockfiles' indirect packages left out (a declared one at its locked version)
 */
public record ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today, List<Path> vexFiles,
                          Path mavenRepository, Path gradleCache, Path cacheDir, boolean directOnly) {

    /** A database older than a month is said to be. */
    public static final int DEFAULT_DB_MAX_AGE_DAYS = 30;

    public ScanOptions {
        vexFiles = List.copyOf(vexFiles);
    }

    public ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today, List<Path> vexFiles, Path mavenRepository,
                       Path gradleCache, Path cacheDir) {
        this(ignoreFile, mode, dbMaxAgeDays, today, vexFiles, mavenRepository, gradleCache, cacheDir, false);
    }

    public ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today, List<Path> vexFiles, Path mavenRepository,
                       Path gradleCache) {
        this(ignoreFile, mode, dbMaxAgeDays, today, vexFiles, mavenRepository, gradleCache, null);
    }

    public ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today, List<Path> vexFiles, Path mavenRepository) {
        this(ignoreFile, mode, dbMaxAgeDays, today, vexFiles, mavenRepository, null);
    }

    public ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today, List<Path> vexFiles) {
        this(ignoreFile, mode, dbMaxAgeDays, today, vexFiles, null);
    }

    public ScanOptions(Path ignoreFile, ScanMode mode, int dbMaxAgeDays, LocalDate today) {
        this(ignoreFile, mode, dbMaxAgeDays, today, List.of());
    }

    public static ScanOptions of(Path ignoreFile, ScanMode mode) {
        return new ScanOptions(ignoreFile, mode, DEFAULT_DB_MAX_AGE_DAYS, LocalDate.now());
    }
}
