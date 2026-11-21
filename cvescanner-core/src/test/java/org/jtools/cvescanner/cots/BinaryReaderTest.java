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
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.jtools.cvescanner.project.Collector;
import org.junit.jupiter.api.Test;

/** The binaries of the sample: named by their version resource, else by their file name; the unknown ones left out. */
class BinaryReaderTest {

    private static final Path BINARIES = Path.of("..", "samples", "cots-projects", "binaries").toAbsolutePath().normalize();

    @Test
    void theSamplesBinaries() throws Exception {
        var col = new Collector(BINARIES);
        try (Stream<Path> files = Files.walk(BINARIES)) {
            BinaryReader.scan(files.filter(Files::isRegularFile).sorted().toList(), col);
        }
        var found = new TreeSet<String>();
        col.deps.forEach(d -> found.add(d.file() + " " + d.name() + " " + d.version() + (d.approximate() ? " ≈" : "")));
        col.unresolved.forEach(u -> found.add(u.file() + " " + u.name() + " unchecked"));
        assertEquals(new TreeSet<>(Set.of(
                "gdal304.dll osgeo:gdal 3.4.1",
                "ffmpeg-4.4.2.exe ffmpeg:ffmpeg 4.4.2 ≈",
                "avcodec-58.dll ffmpeg:ffmpeg unchecked",           // avformat-58.dll beside it counts once
                "libssl-1_1-x64.dll openssl:openssl unchecked",
                "linux/libgdal.so.30 osgeo:gdal unchecked")), found);
    }

    @Test
    void aResourcesVersionAsDottedNumbers() {
        assertEquals("3.4.1.0", BinaryReader.version("3, 4, 1, 0"));
        assertEquals("4.4.2", BinaryReader.version("n4.4.2-full_build"));
        assertEquals(null, BinaryReader.version("unknown"));
    }
}
