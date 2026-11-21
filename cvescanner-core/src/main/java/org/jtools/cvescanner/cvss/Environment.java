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

/** One environment applied to the whole scan. */
public record Environment(String key, String name, Reach reach, Requirement confidentiality, Requirement integrity,
                   Requirement availability) {
    public static final Environment NONE = new Environment("none", "Not applied (base score)", Reach.UNRESTRICTED,
            Requirement.NOT_DEFINED, Requirement.NOT_DEFINED, Requirement.NOT_DEFINED);
    public static final List<Environment> PRESETS = List.of(NONE,
            new Environment("internet", "Internet-facing production", Reach.UNRESTRICTED, Requirement.HIGH, Requirement.HIGH, Requirement.HIGH),
            new Environment("internal", "Internal network service", Reach.INTERNAL, Requirement.MEDIUM, Requirement.MEDIUM, Requirement.MEDIUM),
            new Environment("airgapped", "Air-gapped / offline system", Reach.LOCAL, Requirement.MEDIUM, Requirement.MEDIUM, Requirement.MEDIUM),
            new Environment("devci", "Developer workstation / CI only", Reach.INTERNAL, Requirement.MEDIUM, Requirement.HIGH, Requirement.LOW));

    public boolean active() { return !sameSettings(NONE); }

    @Override public String toString() { return name; }

    boolean sameSettings(Environment o) {
        return reach == o.reach && confidentiality == o.confidentiality && integrity == o.integrity && availability == o.availability;
    }

    /** A custom environment, named after the preset it matches if any. */
    public static Environment of(Reach reach, Requirement c, Requirement i, Requirement a) {
        var e = new Environment("custom", "Custom", reach, c, i, a);
        return PRESETS.stream().filter(p -> p.sameSettings(e)).findFirst().orElse(e);
    }

    public static Environment preset(String key) {
        return PRESETS.stream().filter(p -> p.key.equalsIgnoreCase(key)).findFirst().orElseThrow(() ->
                new IllegalArgumentException("--env must be one of " + PRESETS.stream().map(Environment::key).collect(Collectors.joining(", "))));
    }

    public String describe() {
        if (!active()) return name;
        return "%s (reachable: %s; confidentiality: %s, integrity: %s, availability: %s)".formatted(name,
                reach.shortLabel, confidentiality.label.toLowerCase(Locale.ROOT),
                integrity.label.toLowerCase(Locale.ROOT), availability.label.toLowerCase(Locale.ROOT));
    }
}
