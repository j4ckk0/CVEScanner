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


import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

/** One environment applied to the whole scan. */
public record Environment(String key, Reach reach, Requirement confidentiality, Requirement integrity,
                   Requirement availability) {
    /** The key of an environment of the user's own values, matching no preset. */
    public static final String CUSTOM = "custom";
    public static final Environment NONE = new Environment("none", Reach.UNRESTRICTED,
            Requirement.NOT_DEFINED, Requirement.NOT_DEFINED, Requirement.NOT_DEFINED);
    public static final List<Environment> PRESETS = List.of(NONE,
            new Environment("internet", Reach.UNRESTRICTED, Requirement.HIGH, Requirement.HIGH, Requirement.HIGH),
            new Environment("internal", Reach.INTERNAL, Requirement.MEDIUM, Requirement.MEDIUM, Requirement.MEDIUM),
            new Environment("airgapped", Reach.LOCAL, Requirement.MEDIUM, Requirement.MEDIUM, Requirement.MEDIUM),
            new Environment("devci", Reach.INTERNAL, Requirement.MEDIUM, Requirement.HIGH, Requirement.LOW));

    public boolean active() { return !sameSettings(NONE); }

    /** Its name: the preset's ("Air-gapped / offline system"), or "Custom". */
    public String name(I18nLanguage language) { return I18n.text(language, "environment." + key); }

    @Override public String toString() { return name(I18n.language()); }

    boolean sameSettings(Environment o) {
        return reach == o.reach && confidentiality == o.confidentiality && integrity == o.integrity && availability == o.availability;
    }

    /** A custom environment, named after the preset it matches if any. */
    public static Environment of(Reach reach, Requirement c, Requirement i, Requirement a) {
        var e = new Environment(CUSTOM, reach, c, i, a);
        return PRESETS.stream().filter(p -> p.sameSettings(e)).findFirst().orElse(e);
    }

    public static Environment preset(String key) {
        return PRESETS.stream().filter(p -> p.key.equalsIgnoreCase(key)).findFirst().orElseThrow(() ->
                new IllegalArgumentException(I18n.text("option.env", PRESETS.stream().map(Environment::key).collect(Collectors.joining(", ")))));
    }

    /** Its name and, when it applies, its values: "Air-gapped / offline system (reachable: local access only; …)". */
    public String describe(I18nLanguage language) {
        if (!active()) return name(language);
        Locale locale = language.locale();
        return I18n.text(language, "environment.described", name(language), reach.shortLabel(language),
                confidentiality.label(language).toLowerCase(locale), integrity.label(language).toLowerCase(locale),
                availability.label(language).toLowerCase(locale));
    }

    public String describe() { return describe(I18n.language()); }
}
