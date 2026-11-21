package org.jtools.cvescanner;

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


import java.awt.Color;
import java.util.EnumMap;
import java.util.Map;
import org.jtools.cvescanner.cvss.Severity;

/**
 * The colour each severity is shown in, in light looks and in dark ones (lighter there, to be read on a dark
 * background): the window's business, so the scan needs no java.desktop.
 */
final class SeverityColors {

    private static final Map<Severity, Color> LIGHT = new EnumMap<>(Map.of(
            Severity.UNKNOWN, new Color(0x757575), Severity.LOW, new Color(0x1565C0), Severity.MEDIUM, new Color(0xB7791F),
            Severity.HIGH, new Color(0xE4572E), Severity.CRITICAL, new Color(0xB00020)));
    private static final Map<Severity, Color> DARK = new EnumMap<>(Map.of(
            Severity.UNKNOWN, new Color(0x9E9E9E), Severity.LOW, new Color(0x64B5F6), Severity.MEDIUM, new Color(0xE0B040),
            Severity.HIGH, new Color(0xFF8A65), Severity.CRITICAL, new Color(0xFF5C7A)));

    private SeverityColors() {
    }

    /** Its colour in the look in use. */
    static Color of(Severity severity) {
        return (Looks.isDark() ? DARK : LIGHT).get(severity);
    }
}
