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
 * The window clicked through, as a person would check it: a scan and its filters, a header's ▾, the looks, the packages
 * ticked for Apply fixes, the plan, an installed product, standard and expert modes, the settings collapsed, a VEX
 * document, the database age, the Dependencies tab, Direct dependencies only, the other language. Only with
 * -Dcvescanner.windowTest=true, on a virtual display (scripts/window-check.sh): never on a desktop, which it would take
 * over.
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

        // just after the welcome: the settings collapsed to the folder's row, the findings' table showing 8 rows; ▾ shows
        // the settings again
        assertEquals(null, w.find(Component.class, k -> "databases".equals(k.getName())), "the settings collapsed after the welcome");
        JTable list = w.table();
        w.waitUntil("8 rows shown", () -> WindowDriver.onEdt(() ->
                ((javax.swing.JViewport) list.getParent()).getExtentSize().height == MainWindow.ROWS_SHOWN * list.getRowHeight()));
        w.click(w.named("collapseSettings"));
        w.named("databases");

        // the critical chip shows the critical findings only; Clear filters shows them all again
        w.click(w.find(javax.swing.JLabel.class, l -> l.getText() != null && l.getText().startsWith("Critical")));
        w.waitUntil("the critical findings only", () -> !w.tabTitle(0).equals("Findings (12)"));
        assertTrue(w.text(w.window).contains("Showing "), w.text(w.window));
        w.clickButton("Clear filters");
        w.waitUntil("every finding shown", () -> w.tabTitle(0).equals("Findings (12)"));

        // Hide indirect dependencies: the lockfile's indirect minimist finding left out, then back
        w.click(w.named("hideTransitive"));
        w.waitUntil("the indirect finding hidden", () -> w.tabTitle(0).equals("Findings (11 of 12)"));
        w.clickButton("Clear filters");
        w.waitUntil("every finding shown", () -> w.tabTitle(0).equals("Findings (12)"));

        // the Ecosystem header's ▾: npm unticked leaves the other ecosystems' findings, Clear filters them all again
        JTable findings = w.table();
        var header = findings.getTableHeader();
        java.awt.Rectangle ecosystem = WindowDriver.onEdt(() -> {
            for (int c = 0; c < findings.getColumnCount(); c++)
                if ("Ecosystem".equals(findings.getColumnModel().getColumn(c).getHeaderValue())) return header.getHeaderRect(c);
            throw new AssertionError("no Ecosystem column");
        });
        w.clickAt(header, ecosystem.x + ecosystem.width - 10, ecosystem.height / 2);
        w.named("headerFilter");   // the list of the column's values, waited for
        w.click(w.find(javax.swing.JCheckBox.class, b -> "npm".equals(b.getText())));
        w.waitUntil("the npm findings left out", () -> w.tabTitle(0).startsWith("Findings (") && w.tabTitle(0).contains(" of 12"));
        assertTrue(WindowDriver.onEdt(() -> {
            for (int r = 0; r < findings.getRowCount(); r++) if ("npm".equals(findings.getModel().getValueAt(r, FindingGroups.ECOSYSTEM))) return false;
            return true;
        }), "no npm row");
        w.clickButton("Close");
        w.clickButton("Clear filters");
        w.waitUntil("every finding shown", () -> w.tabTitle(0).equals("Findings (12)"));

        // another environment scores the findings anew: the package version selected stays selected, closed
        w.clickRow("lodash", FindingGroups.PACKAGE);
        int before = WindowDriver.onEdt(findings::getRowCount);
        var environments = w.named("environment", JComboBox.class);
        WindowDriver.onEdt(() -> { environments.setSelectedIndex(1); return null; });
        w.waitUntil("scored for it", () -> w.tabTitle(0).equals("Findings (12)") && WindowDriver.onEdt(environments::getSelectedIndex) == 1);
        assertEquals(before, (int) WindowDriver.onEdt(findings::getRowCount), "a package opened by the new scores");
        assertTrue(WindowDriver.onEdt(() -> findings.getSelectedRow() >= 0
                && findings.getModel().getValueAt(findings.getSelectedRow(), FindingGroups.PACKAGE).toString().contains("lodash")), "lodash still selected");
        WindowDriver.onEdt(() -> { environments.setSelectedIndex(0); return null; });

        // View ▸ Look: the window in a dark look, then back
        w.menu("View", "Look", "FlatLaf Dark");
        w.waitUntil("the dark look", () -> Looks.isDark());
        w.menu("View", "Look", "FlatLaf Light");
        w.waitUntil("the light look", () -> !Looks.isDark());

        // 2. a package version's row: its most severe finding in the details; ▸ opens its findings below it, ← closes it;
        // its tick, the button's count
        w.clickRow("lodash", FindingGroups.PACKAGE);
        assertTrue(w.details().contains("lodash"), w.details());
        int closed = WindowDriver.onEdt(findings::getRowCount);
        w.clickRow("lodash", FindingGroups.EXPAND);
        w.waitUntil("lodash's findings below it", () -> WindowDriver.onEdt(findings::getRowCount) > closed);
        w.key(java.awt.event.KeyEvent.VK_LEFT);
        w.waitUntil("lodash closed again", () -> WindowDriver.onEdt(findings::getRowCount) == closed);
        w.clickRow("lodash", FindingGroups.FIX);
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
        JTable packages = w.table();
        int rows = WindowDriver.onEdt(packages::getRowCount);
        assertTrue(rows > 0);
        for (int r = 0; r < rows; r++) {
            int row = r;
            assertEquals(null, WindowDriver.onEdt(() -> packages.getModel().getValueAt(row, FindingGroups.FIX)), "row " + r + " has a tick box");
        }

        // standard mode: no ignore file, VEX documents nor CVSS version to choose; expert mode shows them
        for (String name : java.util.List.of("ignoreChoose", "vexChoose", "cvss"))
            assertEquals(null, w.find(Component.class, k -> name.equals(k.getName())), name + " hidden in standard mode");
        assertEquals(null, w.find(Component.class, k -> "reach".equals(k.getName())), "the reach behind Customise… in standard mode");
        w.named("envCustomise");
        w.menu("View", "Mode", "Expert");
        for (String name : java.util.List.of("ignoreChoose", "vexChoose", "cvss", "reach")) w.named(name);   // each waited for, shown
        assertEquals(null, w.find(Component.class, k -> "envCustomise".equals(k.getName())), "the reach on the row in expert mode");

        // ▴ collapses the settings to the folder's row, the room left to the tables; ▾ shows them again
        w.click(w.named("collapseSettings"));
        for (String name : java.util.List.of("databases", "scanMode", "vexChoose", "reach"))
            w.waitUntil(name + " hidden", () -> w.find(Component.class, k -> name.equals(k.getName())) == null);
        w.named("folder");
        w.click(w.named("collapseSettings"));
        for (String name : java.util.List.of("databases", "scanMode", "vexChoose", "reach")) w.named(name);

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
        assertTrue(w.tabTitle(MainWindow.IGNORED_TAB).contains("2"), w.tabTitle(MainWindow.IGNORED_TAB));
        w.clickTab(MainWindow.IGNORED_TAB);
        w.clickRow("lodash", 3);
        assertTrue(w.details().contains("stated in the VEX document"), w.details());
        // standard mode reads the folder's own VEX documents only: scanned again, the chosen one's statements left out
        w.menu("View", "Mode", "Standard");
        w.waitUntil("scanned without the chosen VEX document", () -> w.tabTitle(MainWindow.IGNORED_TAB).equals("Ignored (0)"));
        w.menu("View", "Mode", "Expert");
        w.waitUntil("scanned with it again", () -> w.tabTitle(MainWindow.IGNORED_TAB).equals("Ignored (2)"));

        // 6. the database age: a day; the sample's records carry no date, so none is said old
        w.menu("View", "Database age");
        var age = w.dialog("Database age");
        w.type(w.find(JTextField.class, f -> javax.swing.SwingUtilities.getWindowAncestor(f) == age), "1");
        w.tab();
        w.clickButton("OK");
        w.waitUntil("the age dialog closed", () -> !w.dialogShowing());
        w.scan();
        assertFalse(w.text("status").contains("days old"), w.text("status"));

        // 7. the dependency tree: a lockfile's packages under what brings them; those whose parents it does not record apart
        w.type(w.named("folder", JTextField.class), SAMPLES.resolve("python-projects").toString());
        w.scan();
        w.clickTab(MainWindow.DEPENDENCIES_TAB);
        var tree = w.treeRows();
        assertTrue(tree.contains("poetry/poetry.lock"), tree.toString());
        int jinja = tree.subList(tree.indexOf("poetry/poetry.lock"), tree.size()).indexOf("  jinja2 2.11.2") + tree.indexOf("poetry/poetry.lock");
        assertTrue(jinja >= 0 && tree.get(jinja + 1).equals("    markupsafe 1.1.1"), "markupsafe under jinja2: " + tree);
        assertTrue(tree.contains("  ?") && tree.contains("    asgiref 3.3.1"), "Pipfile.lock's indirect ones apart: " + tree);
        assertTrue(w.tabTitle(MainWindow.DEPENDENCIES_TAB).startsWith("Dependencies ("), w.tabTitle(MainWindow.DEPENDENCIES_TAB));
        w.click(w.named("hideTransitive"));
        w.waitUntil("the direct ones only", () -> w.treeRows().stream().noneMatch(r -> r.startsWith("    ")));
        assertTrue(w.tabTitle(MainWindow.DEPENDENCIES_TAB).contains(" of "), w.tabTitle(MainWindow.DEPENDENCIES_TAB));
        w.clickButton("Clear filters");

        // 8. Direct dependencies only: the next scan leaves out what the lockfiles add
        w.click(w.named("directOnly"));
        w.scan();
        assertTrue(w.treeRows().stream().noneMatch(r -> r.startsWith("    ")), w.treeRows().toString());
        assertTrue(w.treeRows().contains("  jinja2 2.11.2") && !w.treeRows().contains("  ?"), w.treeRows().toString());
        w.click(w.named("directOnly"));

        // 9. French: the window relabelled
        String scanInEnglish = w.text("scan");
        w.choose(w.named("language", JComboBox.class), I18nLanguage.FRENCH.toString());
        w.waitUntil("the window in French", () -> I18n.language() == I18nLanguage.FRENCH);
        assertNotEquals(scanInEnglish, w.text("scan"));
        assertEquals(I18n.text("toolbar.scan"), w.text("scan"));
        assertTrue(Files.isDirectory(SAMPLES));
    }
}
