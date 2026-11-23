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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.event.KeyEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The databases' list: the database folder's zips and those added, each listed once with a tick box; a scan reads the
 * ticked ones; what is unticked or added still so at the next start. Only with -Dcvescanner.windowTest=true, on a
 * virtual display (scripts/window-check.sh).
 */
class WindowDatabasesTest {

    private static final Path SAMPLES = Path.of("..").toAbsolutePath().normalize().resolve("samples");
    private static final String CVE_LIST = "2026-11-19_all_CVEs_at_midnight.zip.zip", NVD = "nvdcve-2.0-2024.json.zip",
            GHSA = "advisory-database-main.zip";

    @TempDir
    Path dir;
    private Path settings, database;
    private WindowDriver w;

    @BeforeEach
    void folder() throws Exception {
        Assumptions.assumeTrue(Boolean.getBoolean("cvescanner.windowTest"), "the window test runs with -Dcvescanner.windowTest=true");
        settings = Files.createDirectories(dir.resolve("settings"));
        database = Files.createDirectories(dir.resolve("database"));   // the database folder beside the program
        for (String zip : new String[]{CVE_LIST, NVD}) Files.copy(SAMPLES.resolve("db").resolve(zip), database.resolve(zip));
    }

    @AfterEach
    void stop() throws Exception {
        if (w != null) w.close();
        I18n.use(I18nLanguage.ENGLISH);
    }

    private void start() throws Exception {
        w = WindowDriver.start(settings, "--db-dir", database.toString());
    }

    private void openList() throws Exception {
        if (w.find(JCheckBox.class, b -> b.getName() != null && b.getName().startsWith("database:")) == null
                && w.find(java.awt.Component.class, k -> "databaseAdd".equals(k.getName())) == null)
            w.click(w.named("databaseChoose"));
        w.named("databaseAdd");
    }

    private JCheckBox box(Path zip) throws Exception {
        openList();
        return w.named("database:" + zip.toAbsolutePath().normalize(), JCheckBox.class);
    }

    private long countBoxes() throws Exception {
        openList();
        long n = 0;
        for (var zip : new Path[]{database.resolve(CVE_LIST), database.resolve(NVD), SAMPLES.resolve("db").resolve(GHSA)})
            if (w.find(JCheckBox.class, b -> ("database:" + zip.toAbsolutePath().normalize()).equals(b.getName())) != null) n++;
        return n;
    }

    private void add(Path zip) throws Exception {
        openList();
        w.click(w.named("databaseAdd"));
        w.dialog(I18n.text("database.chooser.title"));
        w.typeInFocus(zip.toString());
        w.key(KeyEvent.VK_ENTER);
        w.waitUntil("the chooser closed", () -> !w.dialogShowing());
    }

    private String field() throws Exception {
        return w.text("databases");
    }

    @Test
    void eachZipListedOnceTickedOrNotUntilTheNextStart() throws Exception {
        Path ghsa = SAMPLES.resolve("db").resolve(GHSA);
        start();
        assertTrue(field().contains(CVE_LIST) && field().contains(NVD), field());
        // unticked: left out of what a scan reads, kept in the list
        w.click(box(database.resolve(NVD)));
        w.waitUntil("the NVD feed unticked", () -> !field().contains(NVD));
        assertTrue(field().contains(CVE_LIST), field());
        // added: listed, ticked; added again: not listed twice
        add(ghsa);
        w.waitUntil("the advisories added", () -> field().contains(GHSA));
        add(ghsa);
        assertEquals(3, countBoxes(), "each zip listed once");
        assertEquals(1, field().split(java.util.regex.Pattern.quote(GHSA), -1).length - 1, field());
        assertFalse(WindowDriver.onEdt(box(database.resolve(NVD))::isSelected));
        // the folder's zips stay in the list (they come back at each start); one added here can be removed
        assertNull(w.find(java.awt.Component.class, k -> ("databaseRemove:" + database.resolve(NVD).toAbsolutePath().normalize()).equals(k.getName())));
        w.named("databaseRemove:" + ghsa.toAbsolutePath().normalize());
        w.close();

        start();
        assertTrue(field().contains(CVE_LIST) && field().contains(GHSA) && !field().contains(NVD), "as it was left: " + field());
        assertFalse(WindowDriver.onEdt(box(database.resolve(NVD))::isSelected));
        w.click(w.named("databaseRemove:" + ghsa.toAbsolutePath().normalize()));
        w.waitUntil("the advisories removed", () -> !field().contains(GHSA));
        assertNull(w.find(JCheckBox.class, b -> ("database:" + ghsa.toAbsolutePath().normalize()).equals(b.getName())));
        // untick all: nothing to scan with, the field outlined
        w.click(w.named("databaseNone"));
        w.waitUntil("none ticked", () -> field().equals(I18n.text("toolbar.database.noneTicked")));
        var databases = w.named("databases", JTextField.class);
        assertEquals("error", WindowDriver.onEdt(() -> databases.getClientProperty("JComponent.outline")));
        w.click(w.named("databaseAll"));
        w.waitUntil("all ticked", () -> field().contains(CVE_LIST) && field().contains(NVD));
    }

    @Test
    void aScanReadsTheTickedOnesOnly() throws Exception {
        Files.copy(SAMPLES.resolve("db").resolve(GHSA), database.resolve(GHSA));
        start();
        w.click(box(database.resolve(GHSA)));
        w.waitUntil("the advisories unticked", () -> !field().contains(GHSA));
        w.key(KeyEvent.VK_ESCAPE);
        w.type(w.named("folder", JTextField.class), SAMPLES.resolve("projects").toString());
        w.scan();
        String status = w.text("status");
        assertTrue(status.contains(CVE_LIST), status);
        assertFalse(status.contains(GHSA), "the unticked zip not read: " + status);
    }
}
