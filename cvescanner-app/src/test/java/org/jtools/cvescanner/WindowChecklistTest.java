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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Component;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.JTextField;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The window clicked through, as a person would check it: a scan, the packages ticked for Apply fixes, the plan, an
 * installed product, a VEX document, the database age, the other language. Only with -Dcvescanner.windowTest=true,
 * on a virtual display (scripts/window-check.sh): never on a desktop, which it would take over.
 */
class WindowChecklistTest {

    private static final Path ROOT = Path.of("..").toAbsolutePath().normalize();
    private static final Path SAMPLES = ROOT.resolve("samples");

    @TempDir
    Path settings;
    private WindowDriver w;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("cvescanner.windowTest"), "the window test runs with -Dcvescanner.windowTest=true");
        w = WindowDriver.start(settings, "-d", SAMPLES.resolve("projects").toString(),
                "--db", SAMPLES.resolve("db/advisory-database-main.zip").toString());
    }

    @AfterEach
    void stop() throws Exception {
        if (w != null) w.close();
        I18n.use(I18nLanguage.ENGLISH);
    }

    @Test
    void theChecklist() throws Exception {
        // 1. the scan: its counts on the status line and the tabs
        String status = w.text("status");
        assertTrue(status.startsWith("Scanned 7 files, 13 dependencies → 12 findings"), status);
        assertTrue(w.tabTitle(0).contains("12"), w.tabTitle(0));

        // the critical chip shows the critical findings only; Clear filters shows them all again
        w.click(w.find(javax.swing.JLabel.class, l -> l.getText() != null && l.getText().startsWith("Critical")));
        w.waitUntil("the critical findings only", () -> !w.tabTitle(0).equals("Findings (12)"));
        assertTrue(w.text(w.window).contains("Showing "), w.text(w.window));
        w.clickButton("Clear filters");
        w.waitUntil("every finding shown", () -> w.tabTitle(0).equals("Findings (12)"));

        // View ▸ Look: the window in a dark look, then back
        w.menu("View", "Look", "FlatLaf Dark");
        w.waitUntil("the dark look", () -> Looks.isDark());
        w.menu("View", "Look", "FlatLaf Light");
        w.waitUntil("the light look", () -> !Looks.isDark());

        // 2. the packages: a tick, the button's count, the package's finding in the details
        w.clickTab(1);
        w.clickRow("lodash", 3);
        assertTrue(w.details().contains("lodash"), w.details());
        w.clickRow("lodash", 0);
        w.waitUntil("one fix ticked", () -> w.text("applyFixes").contains("(1)"));

        // 3. Apply fixes: the plan names the package; cancelled, nothing is applied
        w.click(w.named("applyFixes"));
        var plan = w.dialog(I18n.text("fixDialog.title"));
        assertTrue(w.text(plan).contains("lodash"), w.text(plan));
        if (w.find(Component.class, k -> k instanceof javax.swing.JButton b && I18n.text("fixDialog.cancel").equals(b.getText())) != null)
            w.clickButton(I18n.text("fixDialog.cancel"));
        else w.clickButton("OK");   // no plan applicable on this machine: the plan shown, with OK only
        w.waitUntil("the plan closed", () -> !w.dialogShowing());
        assertEquals(I18n.text("fixDialog.cancelled"), w.text("status"));

        // 4. an installed product: nothing to tick
        w.choose(w.named("scanMode", JComboBox.class), I18n.text("toolbar.scanMode.installed"));
        w.type(w.named("folder", JTextField.class), ROOT.resolve("examples/installed-app").toString());
        w.scan();
        w.clickTab(1);
        JTable packages = w.table();
        int rows = WindowDriver.onEdt(packages::getRowCount);
        assertTrue(rows > 0);
        for (int r = 0; r < rows; r++) {
            int row = r;
            assertEquals(null, WindowDriver.onEdt(() -> packages.getValueAt(row, 0)), "row " + r + " has a tick box");
        }

        // 5. a VEX document: its statements set two findings aside, said with the document
        w.choose(w.named("scanMode", JComboBox.class), I18n.text("toolbar.scanMode.sources"));
        w.type(w.named("folder", JTextField.class), SAMPLES.resolve("projects").toString());
        w.click(w.named("vexChoose"));
        w.dialog(I18n.text("vex.chooser.title"));
        w.typeInFocus(SAMPLES.resolve("vex/product.vex.json").toString());
        w.key(java.awt.event.KeyEvent.VK_ENTER);
        w.waitUntil("the chooser closed", () -> !w.dialogShowing());
        assertTrue(w.text("vexField").contains("(from the next scan)"), w.text("vexField"));
        w.scan();
        assertFalse(w.text("vexField").contains("(from the next scan)"), w.text("vexField"));
        assertTrue(w.tabTitle(3).contains("2"), w.tabTitle(3));
        w.clickTab(3);
        w.clickRow("lodash", 3);
        assertTrue(w.details().contains("stated in the VEX document"), w.details());

        // 6. the database age: a day, and the sample database is not older
        w.menu("View", "Database age");
        var age = w.dialog("Database age");
        w.type(w.find(JTextField.class, f -> javax.swing.SwingUtilities.getWindowAncestor(f) == age), "1");
        w.tab();
        w.clickButton("OK");
        w.waitUntil("the age dialog closed", () -> !w.dialogShowing());
        w.scan();
        assertFalse(w.text("status").contains("days old"), w.text("status"));

        // 7. French: the window relabelled
        String scanInEnglish = w.text("scan");
        w.choose(w.named("language", JComboBox.class), I18nLanguage.FRENCH.toString());
        w.waitUntil("the window in French", () -> I18n.language() == I18nLanguage.FRENCH);
        assertNotEquals(scanInEnglish, w.text("scan"));
        assertEquals(I18n.text("toolbar.scan"), w.text("scan"));
        assertTrue(Files.isDirectory(SAMPLES));
    }
}
