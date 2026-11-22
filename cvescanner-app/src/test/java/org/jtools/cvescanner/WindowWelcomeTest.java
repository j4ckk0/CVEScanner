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

import java.awt.Component;
import java.nio.file.Path;
import javax.swing.JTextField;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The window opened without a folder: the welcome alone, below the toolbar; its Scan, then the findings with the search
 * and the filters, the settings collapsed until ▾ shows them with the environment; the folder among the recent ones. Only with -Dcvescanner.windowTest=true,
 * on a virtual display (scripts/window-check.sh).
 */
class WindowWelcomeTest {

    private static final Path SAMPLES = Path.of("..").toAbsolutePath().normalize().resolve("samples");

    @TempDir
    Path settings;
    private WindowDriver w;

    @AfterEach
    void stop() throws Exception {
        if (w != null) w.close();
        I18n.use(I18nLanguage.ENGLISH);
    }

    @Test
    void theWelcomeUntilTheFirstScan() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("cvescanner.windowTest"), "the window test runs with -Dcvescanner.windowTest=true");
        w = WindowDriver.start(settings, "--db", SAMPLES.resolve("db/advisory-database-main.zip").toString());
        w.named("welcome");
        assertEquals(null, w.find(Component.class, k -> "tryExamples".equals(k.getName())), "no examples beside this program");
        assertEquals(null, w.find(Component.class, k -> "tabs".equals(k.getName())), "no table before a scan");
        assertEquals(null, w.find(Component.class, k -> "ecosystem".equals(k.getName())), "no filters before a scan");
        assertEquals(null, w.find(Component.class, k -> "reach".equals(k.getName()) || "envCustomise".equals(k.getName())),
                "no environment before a scan");
        w.type(w.named("folder", JTextField.class), SAMPLES.resolve("projects").toString());
        w.click(w.named("welcomeScan"));
        w.waitUntil("the findings in place of the welcome", () -> w.find(Component.class, k -> "tabs".equals(k.getName())) != null
                && w.tabTitle(0).equals("Findings (12)"));
        assertEquals(null, w.find(Component.class, k -> "welcome".equals(k.getName())));
        Component filters = w.named("ecosystem").getParent();   // the filters' row, shown with the findings
        w.waitUntil("no empty rows below the filters", () -> WindowDriver.onEdt(() -> filters.getHeight() == filters.getPreferredSize().height));
        assertEquals(null, w.find(Component.class, k -> "envCustomise".equals(k.getName())), "the settings collapsed after the welcome");
        w.click(w.named("collapseSettings"));
        w.named("envCustomise");   // the environment, shown with the settings
        w.click(w.named("recentFolders"));
        assertTrue(w.find(javax.swing.JMenuItem.class, i -> i.getText().equals(SAMPLES.resolve("projects").toString())) != null,
                "the folder among the recent ones");
        w.key(java.awt.event.KeyEvent.VK_ESCAPE);
    }

    @Test
    void scanWaitsForTheFolderAndADatabaseTheirFieldsOutlinedUntilThen() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("cvescanner.windowTest"), "the window test runs with -Dcvescanner.windowTest=true");
        w = WindowDriver.start(settings);   // no database given, none kept
        Component scan = w.named("scan"), welcomeScan = w.named("welcomeScan");
        var folder = w.named("folder", JTextField.class);
        var databases = w.named("databases", JTextField.class);
        assertTrue(WindowDriver.onEdt(() -> !scan.isEnabled() && !welcomeScan.isEnabled()), "no database: nothing to scan with");
        assertEquals("error", WindowDriver.onEdt(() -> databases.getClientProperty("JComponent.outline")));
        assertEquals(null, WindowDriver.onEdt(() -> folder.getClientProperty("JComponent.outline")), "the working folder is one");
        w.type(folder, SAMPLES.resolve("no such folder").toString());
        w.waitUntil("the folder outlined", () -> "error".equals(WindowDriver.onEdt(() -> folder.getClientProperty("JComponent.outline"))));
        w.type(folder, SAMPLES.resolve("projects").toString());
        w.waitUntil("the folder no longer outlined", () -> WindowDriver.onEdt(() -> folder.getClientProperty("JComponent.outline")) == null);
        assertTrue(WindowDriver.onEdt(() -> !welcomeScan.isEnabled()), "still no database");
    }
}
