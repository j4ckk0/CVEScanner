package org.jtools.cvescanner.cvss;

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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The program's CVSS scores are those of another implementation: reference.tsv, 9,000 random vectors — CVSS 3.0 and
 * 3.1 with temporal and environmental metrics, CVSS 4.0 with threat and environmental ones — scored by the Python
 * library cvss (scripts/cvss-reference.py). Up to 20 mismatches are shown, with their count, not only the first.
 */
class CvssReferenceTest {

    @Test
    void everyScoreIsTheReferences() throws IOException {
        List<String> mismatches = new ArrayList<>();
        int read = 0;
        try (InputStream in = CvssReferenceTest.class.getResourceAsStream("reference.tsv")) {
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] f = line.split("\t");
                Double base = Cvss.baseScore(f[0]), environmental = Cvss.environmentalScore(f[0]);
                if (base == null || base != Double.parseDouble(f[1]))
                    mismatches.add(f[0] + ": base " + base + ", reference " + f[1]);
                if (environmental == null || environmental != Double.parseDouble(f[2]))
                    mismatches.add(f[0] + ": environmental " + environmental + ", reference " + f[2]);
                read++;
            }
        }
        assertTrue(read >= 9000, read + " vectors read: the test would pass reading nothing");
        assertEquals(List.of(), mismatches.subList(0, Math.min(20, mismatches.size())), mismatches.size() + " mismatches");
    }
}
