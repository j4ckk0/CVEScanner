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
 * The program's settings — its look, its language, the databases and VEX documents chosen, how to scan and to score —,
 * kept in cvescanner.properties, beside the program (cvescanner.jar): in its folder, as a portable program keeps them,
 * never in the registry or the user's folder. Written only when a setting changes; a folder that cannot be written in
 * keeps nothing, and the program goes on.
 */
final class Settings {

    /** The look's class (View ▸ Look). */
    static final String LOOK = "look";
    /** The language's code: "fr", "en". */
    static final String LANGUAGE = "language";
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
    /** "true" when the toolbar's settings are collapsed to the folder's row (▴ at its end). */
    static final String SETTINGS_COLLAPSED = "settingsCollapsed";
    /** "true" when the window shows the expert's settings too: the ignore file, the VEX documents, the CVSS version (View ▸ Mode). */
    static final String EXPERT = "expert";
    /** Older settings files' key: "false" (no Maven repository nor Gradle cache read) is read as DIRECT_ONLY. */
    private static final String MAVEN_TRANSITIVE = "mavenTransitive";
    private static final String FILE = "cvescanner.properties";

    private final Path file;
    private final Properties values = new Properties();

    private Settings(Path file) {
        this.file = file;
        if (file != null && Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                values.load(in);
            } catch (IOException | IllegalArgumentException _) {
                // unreadable: the defaults
            }
        }
    }

    /** The settings beside the program's jar; none kept when the program runs from its classes. */
    static Settings load() {
        String classPath = System.getProperty("java.class.path", "");
        if (!classPath.endsWith(".jar") || classPath.contains(File.pathSeparator)) {
            return new Settings(null);
        }
        Path folder = Path.of(classPath).toAbsolutePath().getParent();
        return folder == null ? new Settings(null) : in(folder);
    }

    /** The folder the settings are kept in, the program's; null when none is kept (run from its classes). */
    Path folder() {
        return file == null ? null : file.getParent();
    }

    /** The settings kept in this folder. */
    static Settings in(Path folder) {
        return new Settings(folder.resolve(FILE));
    }

    /** Whether a scan keeps the declared dependencies only: as set, else as an older file's MAVEN_TRANSITIVE has it. */
    boolean directOnly() {
        String set = get(DIRECT_ONLY, null);
        return set != null ? Boolean.parseBoolean(set) : "false".equals(get(MAVEN_TRANSITIVE, "true"));
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
        try (OutputStream out = Files.newOutputStream(file)) {
            values.store(out, "CVEScanner's settings");
        } catch (IOException _) {
            // a folder that cannot be written in: the setting holds until the program ends
        }
    }
}
