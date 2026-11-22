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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.awt.Frame;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import javax.swing.JButton;
import org.jtools.cvescanner.analysis.AnalysisFile;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An analysis made on another computer, in the window: opened as it was scanned with no database, Apply fixes off,
 * exported again from File ▸ Export analysis; re-checked by Scan against the database given. Only with
 * -Dcvescanner.windowTest=true, on a virtual display (scripts/window-check.sh).
 */
class WindowAnalysisTest {

    private static final Path SAMPLES = Path.of("..").toAbsolutePath().normalize().resolve("samples");
    private static final String GHSA = SAMPLES.resolve("db/advisory-database-main.zip").toString();

    @TempDir
    Path dir;
    private WindowDriver w;
    private Path analysis;

    @BeforeEach
    void exported() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("cvescanner.windowTest"), "the window test runs with -Dcvescanner.windowTest=true");
        var scan = Engine.scan(SAMPLES.resolve("projects"), List.of(Path.of(GHSA)),
                new ScanOptions(null, ScanMode.SOURCES, 0, LocalDate.now()), new ScanListener() { public void status(String m) { } });
        analysis = dir.resolve("elsewhere/projects.cvescan");
        AnalysisFile.write(scan, analysis);
    }

    @AfterEach
    void stop() throws Exception {
        if (w != null) w.close();
        I18n.use(I18nLanguage.ENGLISH);
    }

    private void findingsShown() throws Exception {
        w.waitUntil("the analysis's findings", () -> w.find(Component.class, k -> "tabs".equals(k.getName())) != null
                && w.tabTitle(MainWindow.FINDINGS_TAB).equals("Findings (12)"));
    }

    @Test
    void openedAsItWasScannedThenExported() throws Exception {
        w = WindowDriver.start(Files.createDirectories(dir.resolve("settings")), "--from-analysis", analysis.toString());
        findingsShown();
        w.waitUntil("the status naming the analysis", () -> w.text("status").contains("Analysis projects.cvescan")
                && w.text("status").contains("as it was scanned"));
        Frame frame = (Frame) javax.swing.SwingUtilities.getWindowAncestor(w.named("tabs"));
        assertTrue(WindowDriver.onEdt(frame::getTitle).endsWith("projects.cvescan"), WindowDriver.onEdt(frame::getTitle));
        var scan = w.named("scan", JButton.class);
        assertEquals("Re-check", WindowDriver.onEdt(scan::getText));
        assertFalse(WindowDriver.onEdt(scan::isEnabled), "no database chosen to re-check against");
        // Apply fixes: the projects are on the other computer
        w.clickRow("lodash", FindingGroups.FIX);
        var fixes = w.named("applyFixes", JButton.class);
        assertFalse(WindowDriver.onEdt(fixes::isEnabled), "Apply fixes on an analysis from elsewhere");

        Path again = dir.resolve("again.cvescan");
        w.menu(I18n.text("menu.file"), I18n.text("menu.file.exportAnalysis"));
        w.dialog(I18n.text("analysis.export.title"));
        w.typeInFocus(again.toString());
        w.key(java.awt.event.KeyEvent.VK_ENTER);
        w.waitUntil("the analysis written", () -> Files.isRegularFile(again));
        w.waitUntil("said where", () -> w.text("status").contains("Analysis written to"));
        assertEquals(12, AnalysisFile.read(again).findings().size());
    }

    @Test
    void reCheckedAgainstTheDatabaseGiven() throws Exception {
        w = WindowDriver.start(Files.createDirectories(dir.resolve("settings")), "--from-analysis", analysis.toString(), "--db", GHSA);
        findingsShown();
        w.scan();
        w.waitUntil("the status saying it was re-checked", () -> w.text("status").contains("re-checked here"));
        findingsShown();
    }
}
