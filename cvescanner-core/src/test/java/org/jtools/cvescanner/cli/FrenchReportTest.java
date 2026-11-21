package org.jtools.cvescanner.cli;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A scan in French writes report.md in French, its numbers as French writes them, and findings.csv as in English:
 * its readers are programs (README, "Languages").
 */
class FrenchReportTest {

    private static final Path SAMPLES = Path.of("..", "samples").toAbsolutePath().normalize();

    /** A key left untranslated: a word, a dot, a word, as the keys are written. */
    private static final Pattern KEY = Pattern.compile("\\b(markdown|severity|match|environment|reason|files|database|scoring|upgrade)\\.[a-zA-Z_]+");

    @TempDir
    Path out;

    @Test
    void theReportSpeaksFrenchAndTheMachineFormatsEnglish() throws Exception {
        I18n.use(I18nLanguage.FRENCH);
        int exit = Cli.run(Options.parse(new String[] {"--no-gui", "-d", SAMPLES.resolve("projects").toString(),
                "-o", out.toString(), "--db", SAMPLES.resolve("db/advisory-database-main.zip").toString(),
                "--db", SAMPLES.resolve("db/2026-11-19_all_CVEs_at_midnight.zip.zip").toString(), "--env", "airgapped"}));
        I18n.use(I18nLanguage.ENGLISH);

        assertEquals(0, exit);
        String report = Files.readString(out.resolve("report.md"));
        assertTrue(report.startsWith("# Rapport de vulnérabilités des dépendances"), report);
        assertTrue(report.contains("Système isolé / hors ligne"), report);
        assertTrue(report.contains("| CRITIQUE |"), report);
        assertTrue(report.contains("10,0 (v4.0)"), "a French decimal comma: " + report);
        assertFalse(KEY.matcher(report).find(), "an untranslated key: " + KEY.matcher(report).results().map(m -> m.group()).toList());

        Path golden = Path.of(FrenchReportTest.class.getResource("golden/both-airgapped").toURI());
        assertEquals(Files.readString(golden.resolve("findings.csv")), Files.readString(out.resolve("findings.csv")));
    }
}
