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
import org.jtools.cvescanner.model.Severity;

/** The colour each severity is shown in: the window's business, so the scan needs no java.desktop. */
final class SeverityColors {

    private static final Color UNKNOWN = new Color(0x757575);
    private static final Color LOW = new Color(0x1565C0);
    private static final Color MEDIUM = new Color(0xB7791F);
    private static final Color HIGH = new Color(0xE4572E);
    private static final Color CRITICAL = new Color(0xB00020);

    private SeverityColors() {
    }

    static Color of(Severity severity) {
        return switch (severity) {
            case UNKNOWN -> UNKNOWN;
            case LOW -> LOW;
            case MEDIUM -> MEDIUM;
            case HIGH -> HIGH;
            case CRITICAL -> CRITICAL;
        };
    }
}
