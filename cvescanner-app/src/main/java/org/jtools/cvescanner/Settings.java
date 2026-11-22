package org.jtools.cvescanner;

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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * The program's settings — the folder analyzed last, the databases and VEX documents chosen, its look, its language,
 * how to scan and to score —, kept in cvescanner.properties in the user's own folder (userFolder): each user keeps
 * theirs, whichever copy of the program runs. Those an earlier version kept beside the program are read once, the
 * first time. Written only when a setting changes; a folder that cannot be written in keeps nothing, and the program
 * goes on. Help ▸ Preferences folder says where, and clears them.
 */
final class Settings {

    /** The look's class (View ▸ Look). */
    static final String LOOK = "look";
    /** The language's code: "fr", "en". */
    static final String LANGUAGE = "language";
    /** The folder analyzed last: the window's, the next time it opens without one. */
    static final String LAST_FOLDER = "lastFolder";
    /** The database zips chosen, their paths separated by the system's path separator. */
    static final String DATABASES = "databases";
    /** The environment: a preset's key, or "custom" with its four values below. */
    static final String ENVIRONMENT = "environment";
    static final String REACH = "env.reach";
    static final String CONFIDENTIALITY = "env.confidentiality";
    static final String INTEGRITY = "env.integrity";
    static final String AVAILABILITY = "env.availability";
    /** "true" when CVSS 4.0 is preferred to 3.x for an advisory that has both. */
    static final String PREFER_CVSS4 = "cvss.prefer4";
    /** What a scan reads: SOURCES (the projects' manifests) or INSTALLED (what an installed product ships). */
    static final String SCAN_MODE = "scanMode";
    /** The days past which a database's newest record is said to be old: a number, 0 for never (View ▸ Database age). */
    static final String DB_MAX_AGE = "dbMaxAge";
    /** The VEX documents chosen, their paths separated by the system's path separator. */
    static final String VEX_FILES = "vexFiles";
    /** "true" when a scan keeps the declared dependencies only (the toolbar's Direct dependencies only). */
    static final String DIRECT_ONLY = "directOnly";
    /** The folders scanned last, newest first, separated by the system's path separator (RecentFolders). */
    static final String RECENT_FOLDERS = "recentFolders";
    /** "true", the default, when the toolbar's settings are collapsed to the folder's row once there are findings (▴, ▾). */
    static final String SETTINGS_COLLAPSED = "settingsCollapsed";
    /** "true" when the window shows the expert's settings too: the ignore file, the VEX documents, the CVSS version (View ▸ Mode). */
    static final String EXPERT = "expert";
    /** Older settings files' key: "false" (no Maven repository nor Gradle cache read) is read as DIRECT_ONLY. */
    private static final String MAVEN_TRANSITIVE = "mavenTransitive";
    private static final String FILE = "cvescanner.properties";

    private final Path file;
    /** The program's own folder (cvescanner.jar's): its examples, its index cache; null when it runs from its classes. */
    private final Path programFolder;
    private final Properties values = new Properties();

    private Settings(Path file, Path programFolder) {
        this.file = file;
        this.programFolder = programFolder;
        if (file != null && Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                values.load(in);
            } catch (IOException | IllegalArgumentException _) {
                // unreadable: the defaults
            }
        }
    }

    /**
     * The settings of the user, in their folder; none kept when the program runs from its classes, nor when keep is false
     * (the packaging's training run, which must leave no file in a home folder).
     */
    static Settings load(boolean keep) {
        String classPath = System.getProperty("java.class.path", "");
        if (!classPath.endsWith(".jar") || classPath.contains(File.pathSeparator)) {
            return new Settings(null, null);
        }
        Path program = Path.of(classPath).toAbsolutePath().getParent();
        if (!keep) return new Settings(null, program);
        Path file = userFolder().resolve(FILE);
        Path beside = program == null ? null : program.resolve(FILE);
        if (beside != null && !Files.exists(file) && Files.isRegularFile(beside)) {
            try {   // an earlier version's, beside the program: taken over, once
                Files.createDirectories(file.getParent());
                Files.copy(beside, file);
            } catch (IOException _) {
                // left where it is: the defaults
            }
        }
        return new Settings(file, program);
    }

    /**
     * The user's folder for the program's preferences: %APPDATA%\CVEScanner on Windows, ~/Library/Application
     * Support/CVEScanner on macOS, $XDG_CONFIG_HOME/cvescanner elsewhere (~/.config/cvescanner).
     */
    static Path userFolder() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        Path home = Path.of(System.getProperty("user.home"));
        String appData = System.getenv("APPDATA");
        if (os.contains("win")) return appData != null && !appData.isBlank() ? Path.of(appData, "CVEScanner") : home.resolve("CVEScanner");
        if (os.contains("mac")) return home.resolve("Library/Application Support/CVEScanner");
        String config = System.getenv("XDG_CONFIG_HOME");
        return (config != null && !config.isBlank() ? Path.of(config) : home.resolve(".config")).resolve("cvescanner");
    }

    /** The file the settings are kept in; null when none is kept. */
    Path file() {
        return file;
    }

    /** The program's own folder: its examples, its index cache; null when it runs from its classes. */
    Path programFolder() {
        return programFolder;
    }

    /** The settings kept in this folder, the program's folder too (the tests'). */
    static Settings in(Path folder) {
        return new Settings(folder.resolve(FILE), folder);
    }

    /** Whether a scan keeps the declared dependencies only: as set, else as an older file's MAVEN_TRANSITIVE has it. */
    boolean directOnly() {
        String set = get(DIRECT_ONLY, null);
        return set != null ? Boolean.parseBoolean(set) : "false".equals(get(MAVEN_TRANSITIVE, "true"));
    }

    /** Every setting forgotten, its file deleted: the defaults from the next start (Help ▸ Preferences folder). */
    void clear() throws IOException {
        values.clear();
        if (file != null) Files.deleteIfExists(file);
    }

    String get(String key, String otherwise) {
        return values.getProperty(key, otherwise);
    }

    /** Sets a value, and keeps it if the program's folder can be written in. */
    void set(String key, String value) {
        values.setProperty(key, value);
        if (file == null) {
            return;
        }
        try {
            Files.createDirectories(file.getParent());
        } catch (IOException _) {
            return;   // a folder that cannot be made: the setting holds until the program ends
        }
        try (OutputStream out = Files.newOutputStream(file)) {
            values.store(out, "CVEScanner's settings");
        } catch (IOException _) {
            // a folder that cannot be written in: the setting holds until the program ends
        }
    }
}
