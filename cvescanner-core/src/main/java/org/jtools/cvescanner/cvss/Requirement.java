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


/** CVSS security requirement (CR / IR / AR). */
public enum Requirement {
    NOT_DEFINED("Not defined", "X"), LOW("Low", "L"), MEDIUM("Medium", "M"), HIGH("High", "H");

    public final String label, code;

    Requirement(String label, String code) { this.label = label; this.code = code; }

    @Override public String toString() { return label; }

    public static Requirement parse(String s) {
        for (var r : values()) if (r.code.equalsIgnoreCase(s) || r.name().equalsIgnoreCase(s)) return r;
        throw new IllegalArgumentException("requirement must be L, M, H or X");
    }
}
