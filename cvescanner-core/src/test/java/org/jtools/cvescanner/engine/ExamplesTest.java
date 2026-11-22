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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jtools.cvescanner.model.Dependency;
import org.junit.jupiter.api.Test;
import org.jtools.cvescanner.model.ScanListener;

/**
 * The example projects (examples/README.md) stay readable as they are: every package they declare found, with its
 * version, none left unchecked, no file skipped. Scanned against a sample database: what they are vulnerable to is a
 * real database's business.
 */
class ExamplesTest {

    private static final Path ROOT = Path.of("..").toAbsolutePath().normalize();

    @Test
    void everyPackageOfTheExamplesIsRead() throws Exception {
        var result = Engine.scan(ROOT.resolve("examples"), List.of(ROOT.resolve("samples/db/advisory-database-main.zip")),
                new ScanListener() {
                    public void status(String message) { }
                });
        Set<String> packages = new TreeSet<>();
        for (Dependency d : result.dependencies()) packages.add(d.name() + "@" + d.version());
        assertEquals(new TreeSet<>(List.of(
                "ch.qos.logback:logback-classic@1.2.3", "com.fasterxml.jackson.core:jackson-databind@2.9.8",
                "com.google.guava:guava@31.1-jre", "com.google.protobuf:protobuf-java@3.21.5", "com.h2database:h2@1.4.199",
                "com.thoughtworks.xstream:xstream@1.4.17", "commons-collections:commons-collections@3.2.1",
                "commons-io:commons-io@2.6", "io.netty:netty-codec-http@4.1.68.Final", "junit:junit@4.12",
                "org.apache.commons:commons-text@1.9", "org.apache.httpcomponents:httpclient@4.5.12",
                "org.apache.logging.log4j:log4j-core@2.14.1", "org.springframework:spring-beans@5.3.17",
                "org.springframework:spring-webmvc@5.3.17", "org.yaml:snakeyaml@1.33",
                "async@2.6.3", "axios@0.21.0", "follow-redirects@1.13.0", "glob-parent@5.1.1", "is-extglob@2.1.1",
                "is-glob@4.0.1", "jquery@3.4.1", "json5@2.2.1", "lodash@4.17.11", "lodash@4.17.15", "marked@1.1.0",
                "minimist@1.2.5", "mkdirp@0.5.5", "moment@2.29.1", "node-fetch@2.6.0", "semver@5.7.1",
                "shell-quote@1.7.2", "ua-parser-js@0.7.21", "ws@7.4.5",
                "osgeo:gdal@3.4.1", "ffmpeg:ffmpeg@4.4.2", "openssl:openssl@1.1.1k", "zlib:zlib@1.2.11",
                "haxx:libcurl@7.79.1", "sqlite:sqlite@3.36.0", "xmlsoft:libxml2@2.9.12", "libpng:libpng@1.6.37",
                "libtiff:libtiff@4.3.0", "libexpat_project:libexpat@2.4.1", "freetype:freetype@2.10.4",
                "webmproject:libwebp@1.2.0", "freedesktop:poppler@21.01.0", "uclouvain:openjpeg@2.4.0",
                "libarchive:libarchive@3.5.1")), packages);
        assertEquals(List.of(), result.unresolved(), "a dependency left unchecked");
        assertEquals(List.of(), result.warnings(), "a file skipped");
    }

    /**
     * With the samples' made-up databases for them (db/examples.zip, and the components' CVE List and NVD feed) every
     * example shows its vulnerable packages, each folder's and the installed product's: see make_fixtures.py.
     */
    @Test
    void everyExampleShowsItsVulnerablePackagesWithTheExamplesDatabase() throws Exception {
        ScanListener quiet = message -> { };
        var db = ROOT.resolve("samples/db");
        var sources = Engine.scan(ROOT.resolve("examples"), List.of(db.resolve("examples.zip"), db.resolve("cots-cvelist.zip"),
                db.resolve("nvdcve-2.0-2024.json.zip")), quiet);
        var vulnerable = new java.util.TreeMap<String, Set<String>>();
        for (var f : sources.findings())
            vulnerable.computeIfAbsent(f.file().substring(0, f.file().indexOf('/')), _ -> new TreeSet<>()).add(f.pkg() + "@" + f.version());
        assertEquals(java.util.Map.of("cots-app", 7, "gradle-app", 7, "maven-webapp", 9, "npm-app", 9, "yarn-app", 8),
                sizes(vulnerable), vulnerable.toString());
        var installed = Engine.scan(ROOT.resolve("examples/installed-app"), List.of(db.resolve("examples.zip")), null,
                org.jtools.cvescanner.model.ScanMode.INSTALLED, quiet);
        assertEquals(22, installed.findings().stream().map(f -> f.pkg() + "@" + f.version()).distinct().count());
    }

    private static java.util.Map<String, Integer> sizes(java.util.Map<String, Set<String>> byFolder) {
        var out = new java.util.HashMap<String, Integer>();
        byFolder.forEach((k, v) -> out.put(k, v.size()));
        return out;
    }
}
