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

import java.awt.Component;
import java.awt.Cursor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jtools.cvescanner.analysis.AnalysisFile;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanResult;

/**
 * An analysis carried to another computer: File ▸ Export analysis writes the scan shown to a .cvescan file; File ▸
 * Open analysis (or the file dropped, or picked among the recent ones) shows the one it holds as it was scanned; Scan,
 * with that file in the folder field, matches its dependencies again against the databases chosen here.
 */
final class AnalysisActions {

    /** What the window gives: the scan shown, its scan options and databases, where it says things. */
    interface Host {
        ScanResult result();

        boolean busy();

        void busy(boolean on);

        /** Shows the analysis opened or re-checked as a scan's result. */
        void show(ScanResult r);

        /** The databases chosen and the scan options set, for a re-check. */
        List<Path> databases();

        ScanOptions options();

        ScanListener listener();

        void say(Supplier<String> message);

        /** Where the reports go: the folder the export proposes. */
        Path reportsFolder();

        /** The ignore entries and VEX statements in force now, those added since the scan too: what an export keeps. */
        Ignores ignores();

        /** The environment and the CVSS version the findings are scored for now: what an export says they were. */
        Environment environment();

        boolean preferV4();
    }

    private final Component owner;
    private final Host host;
    private final JMenuItem exportItem = new JMenuItem(), openItem = new JMenuItem();
    /** The analysis last read, as its file holds it, and that file. */
    private ScanResult opened;
    private Path openedFile;

    AnalysisActions(Component owner, I18nLabels labels, Host host) {
        this.owner = owner;
        this.host = host;
        labels.menu(exportItem, "menu.file.exportAnalysis");
        labels.menu(openItem, "menu.file.openAnalysis");
        exportItem.setName("exportAnalysis");   // for the window test (WindowDriver)
        openItem.setName("openAnalysis");
        exportItem.addActionListener(_ -> export());
        openItem.addActionListener(_ -> choose());
        update();
    }

    JMenuItem exportItem() {
        return exportItem;
    }

    JMenuItem openItem() {
        return openItem;
    }

    /** Export analysis only once there is a scan to export, and not while one runs. */
    void update() {
        exportItem.setEnabled(host.result() != null && !host.busy());
        openItem.setEnabled(!host.busy());
    }

    private void choose() {
        var chooser = new JFileChooser(openedFile != null ? openedFile.getParent().toFile() : host.reportsFolder().toAbsolutePath().toFile());
        chooser.setDialogTitle(I18n.text("analysis.open.title"));
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("analysis.files"), AnalysisFile.EXTENSION.substring(1)));
        if (chooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION) open(chooser.getSelectedFile().toPath());
    }

    /** Shows the analysis this file holds, as it was scanned: no database read. */
    void open(Path file) {
        run(file, () -> read(file), "analysis.open.failed.title");
    }

    /** The dependencies of the analysis this file holds, matched against the databases chosen here. */
    void recheck(Path file) {
        var databases = host.databases();
        var options = host.options();
        var listener = host.listener();
        run(file, () -> Engine.recheck(read(file), databases, options, listener), "scan.failed.title");
    }

    private interface Work {
        ScanResult get() throws IOException;
    }

    private void run(Path file, Work work, String failedTitle) {
        if (host.busy()) return;
        host.busy(true);
        new SwingWorker<ScanResult, Void>() {
            @Override
            protected ScanResult doInBackground() throws Exception {
                return work.get();
            }

            @Override
            protected void done() {
                host.busy(false);
                try {
                    host.show(get());
                } catch (ExecutionException e) {
                    host.say(() -> I18n.text("scan.failed"));
                    JOptionPane.showMessageDialog(owner, SwingText.plain(e.getCause().getMessage()), I18n.text(failedTitle),
                            JOptionPane.ERROR_MESSAGE);
                } catch (InterruptedException _) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    /** The analysis in this file, read anew: the file may have been replaced since. */
    private synchronized ScanResult read(Path file) throws IOException {
        Path normal = file.toAbsolutePath().normalize();
        opened = AnalysisFile.read(normal);
        openedFile = normal;
        return opened;
    }

    /**
     * The ignore entries and VEX statements of the analysis last read, as its file holds them: those the window comes
     * back to when the folder's own ignore file is chosen again, the folder being on the other computer.
     */
    synchronized Ignores carried() {
        return opened == null ? Ignores.NONE : opened.ignores();
    }

    /** The scan shown as an export writes it: its findings set apart by the entries in force now, those added since the scan too. */
    static ScanResult forExport(ScanResult shown, Ignores now) {
        return now == null ? shown : shown.withIgnores(now);
    }

    /** The scan shown, written to a file the user picks; the scan's folder and the day proposed as its name. */
    private void export() {
        ScanResult r = host.result();
        if (r == null) return;
        Path folder = openedFile != null && r.imported() != null ? openedFile.getParent() : host.reportsFolder().toAbsolutePath();
        var chooser = new JFileChooser(folder.toFile());
        chooser.setDialogTitle(I18n.text("analysis.export.title"));
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("analysis.files"), AnalysisFile.EXTENSION.substring(1)));
        chooser.setSelectedFile(folder.resolve(AnalysisFile.defaultName(r, Clock.systemDefaultZone())).toFile());
        if (chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION) return;
        Path file = chooser.getSelectedFile().toPath();
        if (!AnalysisFile.named(file)) file = file.resolveSibling(file.getFileName() + AnalysisFile.EXTENSION);
        if (Files.exists(file) && JOptionPane.showConfirmDialog(owner, SwingText.plain(I18n.text("analysis.export.replace", file.getFileName())),
                I18n.text("analysis.export.title"), JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION)
            return;
        owner.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        try {
            AnalysisFile.write(forExport(r, host.ignores()), file, host.environment(), host.preferV4());
            Path written = file;
            host.say(() -> I18n.text("analysis.exported", written));
        } catch (IOException e) {
            JOptionPane.showMessageDialog(owner, SwingText.plain(e.getMessage()), I18n.text("analysis.export.failed.title"),
                    JOptionPane.ERROR_MESSAGE);
        } finally {
            owner.setCursor(Cursor.getDefaultCursor());
        }
    }
}
