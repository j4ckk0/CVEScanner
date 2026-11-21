package org.jtools.cvescanner.i18n;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Something the program says, kept as data until it is said: a key of the texts and its arguments. A reason, a note,
 * a warning found by a scan is said in the window's language, in the report's, and in English in findings.csv and
 * findings.json, from the same Phrase.
 */
public record Phrase(String key, List<Object> arguments) {

    /** Its arguments as given, a null among them (an exception's message may be one): said as "null". */
    public Phrase {
        arguments = Collections.unmodifiableList(new ArrayList<>(arguments));
    }

    public static Phrase of(String key, Object... arguments) {
        return new Phrase(key, Arrays.asList(arguments));
    }

    /** Said in the language in use. */
    public String text() {
        return text(I18n.language());
    }

    public String text(I18nLanguage language) {
        return I18n.text(language, key, arguments.toArray());
    }

    @Override
    public String toString() {
        return text();
    }
}
