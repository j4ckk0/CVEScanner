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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** A Phrase is said in the language asked for, its arguments as given. */
class PhraseTest {

    @Test
    void aNullArgumentIsSaidAsNull() {
        // a file skipped for an exception without a message: the scan goes on, saying so
        Phrase skipped = Phrase.of("warning.skipped", "pom.xml", null);
        assertEquals("skipped pom.xml (null)", skipped.text(I18nLanguage.ENGLISH));
    }

    @Test
    void aPhraseAmongTheArgumentsIsSaidInTheSameLanguage() {
        Phrase description = Phrase.of("database.description", Phrase.of("database.kind.osv"), 1234, 12, "2026-11-21");
        assertEquals("avis OSV / GitHub, 1 234 enregistrements (12 utiles), fichier daté du 2026-11-21",
                description.text(I18nLanguage.FRENCH));
        assertEquals("OSV / GitHub advisories, 1,234 records (12 relevant), file dated 2026-11-21",
                description.text(I18nLanguage.ENGLISH));
    }
}
