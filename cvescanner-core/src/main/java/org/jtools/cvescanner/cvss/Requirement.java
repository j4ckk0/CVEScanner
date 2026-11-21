package org.jtools.cvescanner.cvss;

import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

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


/** CVSS security requirement (CR / IR / AR). */
public enum Requirement {
    NOT_DEFINED("X"), LOW("L"), MEDIUM("M"), HIGH("H");

    /** Its letter in a CVSS vector, and on the command line. */
    public final String code;

    Requirement(String code) { this.code = code; }

    public String label(I18nLanguage language) { return I18n.text(language, "requirement." + name()); }

    @Override public String toString() { return label(I18n.language()); }

    public static Requirement parse(String s) {
        for (var r : values()) if (r.code.equalsIgnoreCase(s) || r.name().equalsIgnoreCase(s)) return r;
        throw new IllegalArgumentException(I18n.text("option.requirement"));
    }
}
