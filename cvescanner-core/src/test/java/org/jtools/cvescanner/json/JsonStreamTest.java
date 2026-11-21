package org.jtools.cvescanner.json;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** An array's elements read one at a time, the document never held whole. */
class JsonStreamTest {

    private static List<String> elements(String json, String key) throws IOException {
        var out = new ArrayList<String>();
        JsonStream.forEachElement(new StringReader(json), key, out::add);
        return out;
    }

    @Test
    void theElementsOfTheTopLevelArray() throws IOException {
        String json = """
                {"format":"NVD_CVE","nested":{"vulnerabilities":[{"no":1}]},
                 "vulnerabilities":[ {"cve":{"id":"A","t":"a } ] { [ brace"}} , {"cve":{"id":"B","t":"quote \\" and \\\\"}}, 7, "s" ]}
                """;
        var found = elements(json, "vulnerabilities");
        assertEquals(4, found.size(), found.toString());
        assertEquals("A", Json.str(Json.obj(Json.obj(Json.parse(found.get(0))).get("cve")), "id"));
        assertEquals("quote \" and \\", Json.str(Json.obj(Json.obj(Json.parse(found.get(1))).get("cve")), "t"));
        assertEquals("7", found.get(2));
        assertEquals("\"s\"", found.get(3));
    }

    @Test
    void noSuchArrayGivesNothing() throws IOException {
        assertEquals(List.of(), elements("{\"other\":[1,2]}", "vulnerabilities"));
    }

    @Test
    void aBrokenOffArraySaysSo() {
        assertThrows(IllegalArgumentException.class, () -> elements("{\"vulnerabilities\":[{\"a\":\"b", "vulnerabilities"));
    }

    /** A million elements, read from a reader that makes them as it goes: the document never exists whole. */
    @Test
    void aLargeArrayIsStreamed() throws IOException {
        int count = 1_000_000;
        Reader generated = new Reader() {
            private final String head = "{\"vulnerabilities\":[";
            private int element = 0, position = 0;
            private String current = head;

            @Override
            public int read(char[] buffer, int offset, int length) {
                int written = 0;
                while (written < length) {
                    if (position == current.length()) {
                        if (element > count) break;
                        current = element < count ? (element == 0 ? "" : ",") + "{\"cve\":{\"id\":\"CVE-" + element + "\"}}" : "]}";
                        element++;
                        position = 0;
                    }
                    buffer[offset + written++] = current.charAt(position++);
                }
                return written == 0 ? -1 : written;
            }

            @Override
            public void close() { }
        };
        long[] seen = {0};
        JsonStream.forEachElement(generated, "vulnerabilities", text -> seen[0]++);
        assertEquals(count, seen[0]);
        assertTrue(Runtime.getRuntime().totalMemory() < 2L * 1024 * 1024 * 1024, "the test's heap stayed small");
    }
}
