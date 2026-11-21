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


import java.util.Locale;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

/** How severe a finding is, the least first: the ordinal is the rank. Its colour is the window's (SeverityColors). */
public enum Severity {
    UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL;

    /** Its name in the language in use: "Critical", "Critique". */
    public String label() { return label(I18n.language()); }

    public String label(I18nLanguage language) { return I18n.text(language, "severity." + name()); }

    public static Severity fromRating(String s) {
        return switch (s.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> CRITICAL;
            case "HIGH", "IMPORTANT" -> HIGH;
            case "MODERATE", "MEDIUM" -> MEDIUM;
            case "LOW" -> LOW;
            default -> UNKNOWN;
        };
    }

    public static Severity fromScore(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        return score > 0 ? LOW : UNKNOWN;
    }

    public static Severity parseThreshold(String s) {
        var sev = fromRating(s);
        if (sev == UNKNOWN) throw new IllegalArgumentException(I18n.text("option.failOn"));
        return sev;
    }
}
