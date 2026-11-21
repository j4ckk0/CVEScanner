package org.jtools.cvescanner.cots;

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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jtools.cvescanner.project.Collector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The components C and C++ builds declare: pkg-config, vcpkg, Conan; what they leave to elsewhere, unchecked. */
class ManifestReaderTest {

    @TempDir
    Path dir;

    private Set<String> read(String fileName, String text) throws Exception {
        Path file = dir.resolve(fileName);
        Files.writeString(file, text);
        var col = new Collector(dir);
        List<Path> one = List.of(file), none = List.of();
        if (fileName.endsWith(".pc")) ManifestReader.scan(one, none, none, col, w -> { throw new AssertionError(w.text()); });
        else if (fileName.equals("vcpkg.json")) ManifestReader.scan(none, one, none, col, w -> { throw new AssertionError(w.text()); });
        else ManifestReader.scan(none, none, one, col, w -> { throw new AssertionError(w.text()); });
        var found = new TreeSet<String>();
        col.deps.forEach(d -> found.add(d.name() + " " + d.version() + (d.approximate() ? " ≈" : "") + " " + d.scope()));
        col.unresolved.forEach(u -> found.add(u.name() + (u.declared().isEmpty() ? "" : " " + u.declared()) + " unchecked: " + u.reason().key()));
        return found;
    }

    @Test
    void aPkgConfigFile() throws Exception {
        assertEquals(Set.of("osgeo:gdal 3.4.1 pkg-config"), read("gdal.pc", "prefix=/usr\nName: GDAL\nVersion: 3.4.1\n"));
        assertEquals(Set.of("osgeo:gdal unchecked: reason.noVersion"), read("gdal.pc", "Name: Something else\n"));
    }

    @Test
    void aVcpkgManifest() throws Exception {
        assertEquals(new TreeSet<>(Set.of("osgeo:gdal 3.4.1 vcpkg", "sqlite:sqlite 3.36.0 ≈ vcpkg",
                "xmlsoft:libxml2 unchecked: reason.vcpkgBaseline")), read("vcpkg.json", """
                {"dependencies":["libxml2",{"name":"sqlite3","version>=":"3.36.0"},{"name":"gdal"}],
                 "overrides":[{"name":"gdal","version":"3.4.1#2"}]}
                """));
    }

    @Test
    void aConanfileTxt() throws Exception {
        assertEquals(new TreeSet<>(Set.of("haxx:libcurl 7.79.1 conan", "zlib:zlib [>=1.2.11 <2] unchecked: reason.versionRange",
                "ffmpeg:ffmpeg 4.4.2 conan")), read("conanfile.txt", """
                [requires]
                libcurl/7.79.1
                zlib/[>=1.2.11 <2]
                # a comment
                [tool_requires]
                ffmpeg/4.4.2@user/stable
                [generators]
                notaref/1.0
                """));
    }

    @Test
    void aConanfilePy() throws Exception {
        assertEquals(new TreeSet<>(Set.of("osgeo:gdal 3.4.1 conan", "openssl:openssl 1.1.1k conan", "zlib:zlib 1.2.11 conan")),
                read("conanfile.py", """
                        class App(ConanFile):
                            requires = "gdal/3.4.1", "openssl/1.1.1k"
                            def requirements(self):
                                self.requires("zlib/1.2.11")
                        """));
    }

    @Test
    void conanLockfilesOfBothFormats() throws Exception {
        assertEquals(Set.of("openssl:openssl 1.1.1k conan"),
                read("conan.lock", "{\"version\":\"0.5\",\"requires\":[\"openssl/1.1.1k#a1b2%165\"]}"));
        assertEquals(Set.of("osgeo:gdal 3.4.1 conan"),
                read("conan.lock", "{\"graph_lock\":{\"nodes\":{\"1\":{\"ref\":\"gdal/3.4.1#rev\"}}}}"));
    }
}
