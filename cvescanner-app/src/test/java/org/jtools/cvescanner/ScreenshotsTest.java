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

import java.awt.Dimension;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The README's pictures, in English and in French: the welcome before a scan; the examples scanned with real databases
 * (the findings, three package versions ticked, the dependency tree, the components off-the-shelf in a dark look); a VEX
 * document's statements in the samples.
 * Only with -Dcvescanner.screenshots=DIR and the databases in -Dcvescanner.screenshotDbs (scripts/screenshots.sh).
 */
class ScreenshotsTest {

    private static final Path ROOT = Path.of("..").toAbsolutePath().normalize();
    private static final Path SAMPLES = ROOT.resolve("samples");
    private static final Dimension SIZE = new Dimension(1470, 1030);

    @TempDir
    Path settings;
    private WindowDriver w;

    @AfterEach
    void stop() throws Exception {
        if (w != null) w.close();
        I18n.use(I18nLanguage.ENGLISH);
    }

    @Test
    void theReadmesPictures() throws Exception {
        String out = System.getProperty("cvescanner.screenshots");
        Assumptions.assumeTrue(out != null, "the README's pictures are taken with -Dcvescanner.screenshots=DIR");
        var databases = new ArrayList<String>();
        for (String db : System.getProperty("cvescanner.screenshotDbs", "").split(File.pathSeparator))
            if (!db.isBlank()) databases.addAll(List.of("--db", db));
        for (I18nLanguage language : List.of(I18nLanguage.ENGLISH, I18nLanguage.FRENCH)) {
            Path dir = Files.createDirectories(language == I18nLanguage.ENGLISH ? Path.of(out) : Path.of(out, "fr"));
            welcome(language, databases, dir);
            examples(language, databases, dir);
            vex(language, dir);
        }
    }

    /** The paths a picture shows as a reader's would be: no build machine's folders. */
    private void show(String name, String text) throws Exception {
        var field = w.named(name, javax.swing.JTextField.class);
        SwingUtilities.invokeAndWait(() -> {
            field.setText(text);
            field.setCaretPosition(0);
        });
    }

    /**
     * The folder as a reader's would be, not this machine's: the window as it is with that folder there, neither
     * outlined in red nor Scan greyed (MainWindow.updateReady).
     */
    private void showFolder(String text) throws Exception {
        show("folder", text);
        var folder = w.named("folder", javax.swing.JTextField.class);
        var scan = w.named("scan");
        SwingUtilities.invokeAndWait(() -> {
            folder.putClientProperty("JComponent.outline", null);
            scan.setEnabled(true);
        });
    }

    private void open(I18nLanguage language, String folder, Path settingsFolder, List<String> more) throws Exception {
        var args = new ArrayList<>(List.of("-d", folder));
        args.addAll(more);
        w = WindowDriver.start(settingsFolder, args.toArray(String[]::new));
        SwingUtilities.invokeAndWait(() -> w.window.setSize(SIZE));
        // the window as a reader sees it after the scan: the settings collapsed, the folder's row alone
        w.waitUntil("the scan's findings", () -> w.find(java.awt.Component.class, k -> "tabs".equals(k.getName())) != null);
        if (language != I18nLanguage.ENGLISH) {
            w.choose(w.named("language", JComboBox.class), language.toString());
            w.waitUntil("the window in " + language, () -> I18n.language() == language);
        }
    }

    /** The window before its first scan, the examples beside the program (its settings' folder) to try. */
    private void welcome(I18nLanguage language, List<String> databases, Path dir) throws Exception {
        Path program = Files.createDirectories(settings.resolve("welcome-" + language));
        Files.createSymbolicLink(program.resolve("examples"), ROOT.resolve("examples"));
        w = WindowDriver.start(program, databases.toArray(String[]::new));
        SwingUtilities.invokeAndWait(() -> w.window.setSize(SIZE));
        if (language != I18nLanguage.ENGLISH) {
            w.choose(w.named("language", JComboBox.class), language.toString());
            w.waitUntil("the window in " + language, () -> I18n.language() == language);
        }
        showFolder("~/CVEScanner/examples");
        show("databases", "~/CVEScanner/database/  Maven-all.zip  ;  npm-all.zip  ;  PyPI-all.zip  ;  nvdcve-2.0-2002.json.zip … "
                + "nvdcve-2.0-2026.json.zip  ;  nvdcve-2.0-modified.json.zip");
        w.named("tryExamples");
        var welcomeScan = w.named("welcomeScan");
        SwingUtilities.invokeAndWait(() -> welcomeScan.setEnabled(true));
        w.screenshot(dir.resolve("welcome.png"));
        w.close();
        w = null;
    }

    /**
     * The examples for an internet-facing environment: Log4Shell selected, three packages ticked, lodash in the tree,
     * the COTS in the dark.
     */
    private void examples(I18nLanguage language, List<String> databases, Path dir) throws Exception {
        var more = new ArrayList<>(databases);
        more.addAll(List.of("--env", "internet"));
        open(language, ROOT.resolve("examples").toString(), Files.createDirectories(settings.resolve("examples-" + language)), more);
        showFolder("~/CVEScanner/examples");
        w.clickRow("log4j-core", FindingGroups.EXPAND);
        w.clickRow("CVE-2021-44228", FindingGroups.CVE);
        w.screenshot(dir.resolve("findings.png"));

        w.clickRow("log4j-core", FindingGroups.EXPAND);
        for (String pkg : List.of("jackson-databind", "axios", "netty-codec-http")) w.clickRow(pkg, FindingGroups.FIX);
        w.clickRow("jackson-databind", FindingGroups.PACKAGE);
        javax.swing.JTable list = w.table();   // the ticks clicked far right: the table shown from its first column again
        WindowDriver.onEdt(() -> { list.scrollRectToVisible(list.getCellRect(list.getSelectedRow(), 0, true)); return null; });
        w.screenshot(dir.resolve("packages.png"));

        w.clickTab(MainWindow.DEPENDENCIES_TAB);
        w.selectTreeRow("lodash");
        w.screenshot(dir.resolve("dependencies.png"));

        w.clickTab(0);
        w.choose(w.named("ecosystem", JComboBox.class), I18n.text("filter.cots"));
        w.menu(I18n.text("menu.view"), I18n.text("menu.look"), "FlatLaf Dark");
        w.waitUntil("the dark look", Looks::isDark);
        w.clickRow("COTS", FindingGroups.EXPAND);
        w.clickRow("CVE-", FindingGroups.CVE);
        w.screenshot(dir.resolve("cots-dark.png"));
        w.menu(I18n.text("menu.view"), I18n.text("menu.look"), "FlatLaf Light");
        w.waitUntil("the light look", () -> !Looks.isDark());
        w.close();
        w = null;
    }

    /** The samples with a VEX document of their own (named from the folder, as the details say it): the Ignored tab. */
    private void vex(I18nLanguage language, Path dir) throws Exception {
        Path projects = settings.resolve("projects-" + language);
        try (var files = Files.walk(SAMPLES.resolve("projects"))) {
            for (Path p : (Iterable<Path>) files::iterator) {
                Path to = projects.resolve(SAMPLES.resolve("projects").relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(to);
                else Files.copy(p, to);
            }
        }
        Files.copy(SAMPLES.resolve("vex/product.vex.json"), projects.resolve("product.vex.json"));
        open(language, projects.toString(), Files.createDirectories(settings.resolve("vex-" + language)),
                List.of("--db", SAMPLES.resolve("db/advisory-database-main.zip").toString()));
        showFolder("~/CVEScanner/samples/projects");
        w.clickTab(MainWindow.IGNORED_TAB);
        w.clickRow("lodash", 3);
        w.screenshot(dir.resolve("vex.png"));
        w.close();
        w = null;
    }
}
