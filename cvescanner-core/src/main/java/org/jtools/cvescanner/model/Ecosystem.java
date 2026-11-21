package org.jtools.cvescanner.model;

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

import java.util.Collection;
import java.util.Comparator;
import java.util.Locale;
import org.jtools.cvescanner.version.Versions;

/**
 * The kind of a dependency: a Maven or an npm package, or a component off-the-shelf (COTS: GDAL, FFmpeg…, named
 * vendor:product). Its name is the one OSV advisories give their ecosystem, and the one the reports write.
 */
public enum Ecosystem {
    MAVEN("Maven"),
    NPM("npm"),
    COTS("COTS");

    private final String id;

    Ecosystem(String id) {
        this.id = id;
    }

    /** The name the reports, the window and OSV's advisories give it. */
    public String id() {
        return id;
    }

    @Override
    public String toString() {
        return id;
    }

    /** The ecosystem of this name, as an OSV advisory writes it; null for one CVEScanner does not check. */
    public static Ecosystem of(String id) {
        for (Ecosystem e : values()) if (e.id.equals(id)) return e;
        return null;
    }

    /** Two versions in this ecosystem's order: npm's semantic versions, Maven's order otherwise (COTS too). */
    public int compare(String a, String b) {
        if (this == NPM) {
            Integer c = Versions.compareSemver(a, b);
            if (c != null) return Integer.signum(c);
        }
        return Versions.compareMaven(a, b);
    }

    public Comparator<String> versionOrder() {
        return this::compare;
    }

    /** The fix to upgrade to, among these, from this version (Versions.nearestFix). */
    public String nearestFix(String version, Collection<String> fixes) {
        return Versions.nearestFix(versionOrder(), version, fixes);
    }

    /** A package at a version as this ecosystem writes it: group:artifact:1.0, name@1.0. */
    public String coordinate(String name, String version) {
        return name + (this == NPM ? "@" : ":") + version;
    }

    /** A COTS component's product, in lower case: "gdal" for "osgeo:gdal" and for "gdal". */
    public static String product(String name) {
        return name.substring(name.indexOf(':') + 1).toLowerCase(Locale.ROOT);
    }
}
