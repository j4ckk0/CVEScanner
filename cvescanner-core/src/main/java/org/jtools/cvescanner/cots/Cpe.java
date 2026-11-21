package org.jtools.cvescanner.cots;

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

import java.util.ArrayList;
import java.util.Locale;

/** A CPE 2.3 name's fields, split on the colons a backslash does not escape, unescaped and in lower case. */
final class Cpe {

    private Cpe() {
    }

    /** The fields of cpe:2.3:part:vendor:product:version:…, at least six (missing ones are "*"). */
    static String[] fields(String cpe) {
        var parts = new ArrayList<String>();
        var field = new StringBuilder();
        for (int i = 0; i < cpe.length(); i++) {
            char c = cpe.charAt(i);
            if (c == '\\' && i + 1 < cpe.length()) {
                field.append(cpe.charAt(++i));
            } else if (c == ':') {
                parts.add(field.toString().toLowerCase(Locale.ROOT));
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        parts.add(field.toString().toLowerCase(Locale.ROOT));
        while (parts.size() < 6) parts.add("*");
        return parts.toArray(String[]::new);
    }
}
