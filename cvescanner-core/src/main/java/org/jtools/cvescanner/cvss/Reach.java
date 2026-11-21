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


import java.util.Locale;

/** How reachable the vulnerable component is in the user's environment; caps the CVSS attack vector. */
public enum Reach {
    UNRESTRICTED("Unrestricted (Internet)", "unrestricted", null),
    INTERNAL("Internal network only", "internal network only", "A"),
    LOCAL("Local access only", "local access only", "L");

    final String label, shortLabel, attackVectorCap;

    Reach(String label, String shortLabel, String cap) { this.label = label; this.shortLabel = shortLabel; this.attackVectorCap = cap; }

    @Override public String toString() { return label; }

    public static Reach parse(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "internet", "unrestricted", "network", "n" -> UNRESTRICTED;
            case "internal", "adjacent", "a" -> INTERNAL;
            case "local", "airgapped", "air-gapped", "l" -> LOCAL;
            default -> throw new IllegalArgumentException("reach must be internet, internal or local");
        };
    }
}
