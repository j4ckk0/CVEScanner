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
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

/** How reachable the vulnerable component is in the user's environment; caps the CVSS attack vector. */
public enum Reach {
    UNRESTRICTED(null), INTERNAL("A"), LOCAL("L");

    final String attackVectorCap;

    Reach(String cap) { this.attackVectorCap = cap; }

    /** Its name in a list: "Local access only". */
    public String label(I18nLanguage language) { return I18n.text(language, "reach." + name()); }

    /** Its name in a sentence: "local access only". */
    public String shortLabel(I18nLanguage language) { return I18n.text(language, "reach.short." + name()); }

    @Override public String toString() { return label(I18n.language()); }

    public static Reach parse(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "internet", "unrestricted", "network", "n" -> UNRESTRICTED;
            case "internal", "adjacent", "a" -> INTERNAL;
            case "local", "airgapped", "air-gapped", "l" -> LOCAL;
            default -> throw new IllegalArgumentException(I18n.text("option.reach"));
        };
    }
}
