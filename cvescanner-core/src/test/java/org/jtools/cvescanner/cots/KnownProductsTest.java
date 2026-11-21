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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** The names components go by, and the products their CVEs are filed under. */
class KnownProductsTest {

    @Test
    void namesGiveVendorAndProduct() {
        assertEquals("osgeo:gdal", KnownProducts.identify(" GDAL "));
        assertEquals("ffmpeg:ffmpeg", KnownProducts.identify("avcodec"));
        assertEquals("haxx:libcurl", KnownProducts.identify("libcurl"));
        assertEquals("something", KnownProducts.identify("Something"));
        assertTrue(KnownProducts.isKnown("zlib1"));
        assertFalse(KnownProducts.isKnown("unrelated"));
    }

    @Test
    void curlsCvesAreFiledUnderBothItsNames() {
        assertEquals(Set.of("curl", "libcurl"), KnownProducts.products("libcurl"));
        assertEquals(Set.of("curl", "libcurl"), KnownProducts.products("curl"));
        assertEquals(Set.of("gdal"), KnownProducts.products("gdal"));
    }
}
