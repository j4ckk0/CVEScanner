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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.Test;

/** The manual shipped beside cvescanner.sh (src/dist/cvescanner.1) names every option --help names, in both languages. */
class ManPageTest {

    private static final Pattern OPTION = Pattern.compile("(?<![\\w-])--[a-z][a-z0-9-]*");

    @Test
    void theManualNamesEveryOptionOfTheHelp() throws Exception {
        String manual = Files.readString(Path.of("src/dist/cvescanner.1")).replace("\\-", "-").replaceAll("\\\\f[BIR]", "");
        for (I18nLanguage language : List.of(I18nLanguage.ENGLISH, I18nLanguage.FRENCH)) {
            I18n.use(language);
            try {
                var options = new TreeSet<String>();
                OPTION.matcher(Options.usage()).results().forEach(m -> options.add(m.group()));
                assertTrue(options.size() > 40, "the help's options: " + options);
                var missing = new TreeSet<String>();
                for (String option : options) if (!OPTION.matcher(manual).results().anyMatch(m -> m.group().equals(option))) missing.add(option);
                assertEquals(new TreeSet<String>(), missing, "options of the " + language + " help the manual does not name");
            } finally {
                I18n.use(I18nLanguage.ENGLISH);
            }
        }
    }
}
