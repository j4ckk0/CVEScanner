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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A DLL's version information, read without trusting the file: the sample's DLL gives its strings; a truncated, a
 * corrupted, a looping or a lying one gives nothing, never an error, never a read beyond its end.
 */
class PeVersionInfoTest {

    private static final Path DLL = Path.of("..", "samples", "cots-projects", "binaries", "gdal304.dll");
    private static final PeVersionInfo.Info GDAL = new PeVersionInfo.Info("GDAL", "3.4.1", "3.4.1.0", "OSGeo");

    @TempDir
    Path dir;

    private Optional<PeVersionInfo.Info> readBytes(byte[] bytes) throws Exception {
        Path file = dir.resolve("x.dll");
        Files.write(file, bytes);
        return PeVersionInfo.read(file);
    }

    @Test
    void theSampleDllSaysWhatItIs() {
        assertEquals(Optional.of(GDAL), PeVersionInfo.read(DLL));
    }

    @Test
    void whatIsNoPeFileGivesNothing() throws Exception {
        assertEquals(Optional.empty(), readBytes(new byte[0]));
        assertEquals(Optional.empty(), readBytes("MZ but nothing else".getBytes()));
        assertEquals(Optional.empty(), PeVersionInfo.read(dir.resolve("missing.dll")));
    }

    @Test
    void everyTruncationGivesNothingOrTheTruth() throws Exception {
        byte[] whole = Files.readAllBytes(DLL);
        for (int length = 0; length < whole.length; length += 3) {
            var info = readBytes(java.util.Arrays.copyOf(whole, length));
            assertTrue(info.isEmpty() || info.get().equals(GDAL), length + ": " + info);
        }
    }

    @Test
    void corruptedFilesNeverThrow() throws Exception {
        byte[] whole = Files.readAllBytes(DLL);
        var random = new Random(20261121);
        for (int i = 0; i < 2000; i++) {
            byte[] bytes = whole.clone();
            for (int flips = 1 + random.nextInt(8); flips > 0; flips--) bytes[random.nextInt(bytes.length)] = (byte) random.nextInt(256);
            readBytes(bytes);   // any answer will do; an exception would fail the test
        }
    }

    @Test
    void aDirectoryPointingAtItselfOrAResourceOfFourGigabytesGiveNothing() throws Exception {
        byte[] whole = Files.readAllBytes(DLL);
        ByteBuffer loop = ByteBuffer.wrap(whole.clone()).order(ByteOrder.LITTLE_ENDIAN);
        loop.putInt(0x200 + 0x18 + 16 + 4, 0x80000000 | 0x18);   // the second level's entry: back to itself
        assertEquals(Optional.empty(), readBytes(loop.array()));
        ByteBuffer huge = ByteBuffer.wrap(whole.clone()).order(ByteOrder.LITTLE_ENDIAN);
        huge.putInt(0x200 + 0x48 + 4, 0xFFFFFFF0);   // the data entry's size
        assertEquals(Optional.empty(), readBytes(huge.array()));
    }
}
