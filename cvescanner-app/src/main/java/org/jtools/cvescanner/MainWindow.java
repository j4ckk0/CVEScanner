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

import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Scoring;

/**
 * The window: the folder and the databases to scan, the ignore file and VEX documents to read, the environment to
 * score for, the tabs of findings and dependencies with their filters, the details of the finding selected. It lays its
 * parts out and runs the scan; each part is its own class (the toolbar's rows, the filters, the summary, the tables, the
 * Dependencies tab, the details, the status line, the menus, the tables' actions). Every text is bound to its key
 * (I18nLabels) and set again when the language changes.
 */
final class MainWindow extends JFrame {

    private final Options opts;
    private final Settings settings;
    private final I18nLabels labels = new I18nLabels();
    private final FindingTables tables = new FindingTables(labels);
    private final I18nLanguageBox languageBox = new I18nLanguageBox(labels);
    private final JTextField dirField = new JTextField(40);
    private final JButton scanButton = new JButton();
    private final JButton exportButton = new JButton();
    /** What a scan reads: source projects, or an installed product from its binaries. */
    private final JComboBox<Choice<ScanMode>> scanModeCombo = new JComboBox<>(List.of(
            new Choice<>("toolbar.scanMode.sources", ScanMode.SOURCES), new Choice<>("toolbar.scanMode.installed", ScanMode.INSTALLED))
            .toArray(Choice[]::new));
    /** A scan of the declared dependencies only (--direct-only): for source projects; an installed product has none. */
    private final JCheckBox directOnlyBox = new JCheckBox();
    private final JTabbedPane tabs = new JTabbedPane();
    /** The tabs, in their order. */
    static final int FINDINGS_TAB = 0, PACKAGES_TAB = 1, DEPENDENCIES_TAB = 2, UNRESOLVED_TAB = 3, IGNORED_TAB = 4;
    private final DependencyTreeTab dependencyTab = new DependencyTreeTab(this::showSelected);

    private final DatabaseChoice databases;
    private final EnvironmentBar environmentBar;
    private final FixActions fixActions;
    private final IgnoreActions ignoreActions;
    private final VexDocuments vexDocuments;
    private final FilterBar filterBar;
    private final SummaryBar summaryBar;
    private final DetailsPane details;
    private final StatusLine status;
    private final ViewMenu viewMenu;

    private ScanResult result;
    /** The scan's findings scored for the environment, those the ignore file sets aside apart. */
    private Ignores.Split split = Ignores.Split.none(List.of());
    private boolean busy;   // progress messages arriving after a scan has finished are ignored

    MainWindow(Options opts, Settings settings) {
        this.opts = opts;
        this.settings = settings;
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        nameForTests();
        labels.bind(this::setTitle, "window.title");
        dirField.setText(opts.scanDir.toAbsolutePath().normalize().toString());
        status = new StatusLine(labels);
        databases = new DatabaseChoice(this, labels, settings, opts.dbFiles, opts.dbDir);
        ignoreActions = new IgnoreActions(this, labels, new IgnoreActions.Host() {
            public ScanResult result() { return result; }
            public Ignores.Split split() { return split; }
            public void reread(List<Phrase> warnings) {
                refreshFindings();
                updateStatusTipAfterReread(warnings);
            }
            public void say(Supplier<String> message) { status.say(message); }
        }, opts.ignoreChoice(), this::scanFolder);
        vexDocuments = new VexDocuments(this, labels, settings, opts.vexFiles, this::scanFolder);
        fixActions = new FixActions(this, labels, tables, new FixActions.Host() {
            public ScanResult result() { return result; }
            public List<Finding> reported() { return split.active(); }
            public void say(Supplier<String> message) { status.say(message); }
            public void rescan() { startScan(); }
            public void busy(boolean on) { setBusy(on); }
            public boolean scanning() { return busy; }
        });
        environmentBar = new EnvironmentBar(this, labels, settings, opts, () -> {
            updateSeverityHeader();
            rescore();
        });
        filterBar = new FilterBar(labels, opts.cveOnly, this::applyFilters);
        summaryBar = new SummaryBar(labels, filterBar::minSeverity);
        details = new DetailsPane(tables, new DetailsPane.Host() {
            public boolean scanned() { return result != null; }
            public Ignores.Split split() { return split; }
            public Ignores ignores() { return ignoreActions.ignores(); }
            public Environment environment() { return environmentBar.environment(); }
            public void copyLink(String url) { MainWindow.this.copyLink(url); }
        });
        viewMenu = new ViewMenu(this, labels, settings, startsExpert(opts, settings), this::setExpert, this::showSeverityColors);
        setJMenuBar(menuBar());

        var north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        // the rows of controls, each group apart: where to scan, how to score, what to show
        north.add(toolbar());
        north.add(separator());
        north.add(environmentBar.panel());
        north.add(separator());
        north.add(filterBar.panel());
        north.add(summaryBar.panel());
        add(north, BorderLayout.NORTH);
        addComponentListener(new ComponentAdapter() {       // let wrapped toolbar rows re-flow when the window is resized
            @Override public void componentResized(ComponentEvent e) { north.revalidate(); }
        });

        TableActions.wire(tables, labels, new TableActions.Host() {
            public void showSelected() { MainWindow.this.showSelected(); }
            public void copyLink(String url) { MainWindow.this.copyLink(url); }
            public void showFindingsOf(String text) {
                filterBar.search(text);
                tabs.setSelectedIndex(FINDINGS_TAB);
            }
            public void search(String text) { filterBar.search(text); }
            public void ignore(Finding f) { MainWindow.this.ignore(f); }
            public void stopIgnoring(IgnoredFinding i) { ignoreActions.stopIgnoring(i); }
        });
        tabs.addTab("", new JScrollPane(tables.findingsTable));
        tabs.addTab("", new JScrollPane(tables.packagesTable));
        tabs.addTab("", dependencyTab.component());
        tabs.addTab("", new JScrollPane(tables.unresolvedTable));
        tabs.addTab("", new JScrollPane(tables.ignoredTable));
        tabs.addChangeListener(_ -> showSelected());
        tabs.setPreferredSize(new Dimension(400, 420));
        var centre = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, details.component());
        centre.setResizeWeight(0.6);
        centre.setDividerSize(10);
        centre.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 16));
        add(centre, BorderLayout.CENTER);
        add(status.panel(), BorderLayout.SOUTH);

        int menuKey = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        getRootPane().registerKeyboardAction(_ -> filterBar.focusSearch(), KeyStroke.getKeyStroke(KeyEvent.VK_F, menuKey),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        getRootPane().setDefaultButton(scanButton);

        // what is shown from data rather than bound to one key: said again in the language chosen
        labels.on(this::updateChips);
        showSeverityColors();
        labels.on(this::updateCounts);
        labels.on(this::showSelected);
        labels.on(this::updateSeverityHeader);
        labels.on(scanModeCombo::repaint);
        labels.on(() -> List.of(tables.findingsTable, tables.packagesTable, dependencyTab.tree(), tables.unresolvedTable,
                tables.ignoredTable).forEach(JComponent::repaint));
        setSize(1480, 940);
        setMinimumSize(new Dimension(1000, 640));
        setLocationRelativeTo(null);
        applyMode(viewMenu.expert());
        if (opts.dirGiven) SwingUtilities.invokeLater(this::startScan);
    }

    // ------------------------------------------------------------------------------------ standard, expert
    /** Expert mode when the command line names what only it shows (an ignore file, VEX documents, a CVSS version), else as kept. */
    private static boolean startsExpert(Options opts, Settings settings) {
        return opts.ignoreFile != null || opts.noIgnore || !opts.vexFiles.isEmpty() || opts.cvssGiven
                || Boolean.parseBoolean(settings.get(Settings.EXPERT, "false"));
    }

    /** Standard mode hides the ignore file, the VEX documents and the CVSS version, and uses their defaults. */
    private void applyMode(boolean expert) {
        ignoreActions.standard(!expert);
        vexDocuments.standard(!expert);
        environmentBar.standard(!expert);
        getContentPane().revalidate();
        getContentPane().repaint();
    }

    /** View ▸ Mode: the findings shown as the mode's settings give them, scanned again when the files read change. */
    private void setExpert(boolean expert) {
        Path ignore = ignoreActions.choice();
        List<Path> vex = vexDocuments.files();
        boolean v4 = environmentBar.preferV4();
        applyMode(expert);
        if (result == null || busy) return;
        if (!Objects.equals(ignore, ignoreActions.choice()) || !vex.equals(vexDocuments.files())) startScan();
        else if (v4 != environmentBar.preferV4()) rescore();
    }

    /** The components the window test (WindowDriver) looks up, by a name no language changes. */
    private void nameForTests() {
        scanButton.setName("scan");
        dirField.setName("folder");
        tabs.setName("tabs");
        scanModeCombo.setName("scanMode");
        languageBox.setName("language");
    }

    private Path scanFolder() {
        return Path.of(dirField.getText().strip());
    }

    // ------------------------------------------------------------------------------------ menus, language
    private JMenuBar menuBar() {
        JMenu file = labels.menu(new JMenu(), "menu.file");
        JMenuItem export = labels.menu(new JMenuItem(), "menu.file.export");
        export.addActionListener(_ -> export());
        JMenuItem exit = labels.menu(new JMenuItem(), "menu.file.exit");
        exit.addActionListener(_ -> dispose());
        file.add(export);
        file.addSeparator();
        file.add(exit);
        JMenuBar bar = new JMenuBar();
        bar.add(file);
        bar.add(viewMenu.menu());
        bar.add(HelpMenu.of(this, labels));
        // the language on the right of the menus
        bar.add(Box.createHorizontalGlue());
        languageBox.onChoice(this::useLanguage);
        bar.add(languageBox);
        bar.add(Box.createHorizontalStrut(4));
        return bar;
    }

    /** Speaks this language from now on, and the next time (Settings). */
    private void useLanguage(I18nLanguage chosen) {
        I18n.use(chosen);
        settings.set(Settings.LANGUAGE, chosen.code());
        useSwingLocale();
        labels.relabel();
        languageBox.show(chosen);
        // a combo box keeps the width its texts had: measured again in the new language, as after a change of look
        SwingUtilities.updateComponentTreeUI(this);
        showSeverityColors();
    }

    /** Swing's own dialogs (the file chooser's buttons, a message's OK) in the language in use. */
    static void useSwingLocale() {
        Locale.setDefault(I18n.language().locale());
        JComponent.setDefaultLocale(I18n.language().locale());
    }

    // ------------------------------------------------------------------------------------ layout
    /** A line between two groups of controls, with room around it. */
    private static JComponent separator() {
        var line = new JPanel(new BorderLayout());
        line.setBorder(BorderFactory.createEmptyBorder(2, 16, 2, 16));
        line.add(new JSeparator(), BorderLayout.CENTER);
        line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 8));
        return line;
    }

    /** The rows of the toolbar: the folder, the databases, the ignore file, the VEX documents, with their buttons. */
    private JPanel toolbar() {
        var rows = new JPanel(new GridBagLayout());
        rows.setBorder(BorderFactory.createEmptyBorder(12, 14, 8, 14));
        var browse = labels.text(new JButton(), "toolbar.browse");
        browse.addActionListener(_ -> chooseFolder());
        labels.text(scanButton, "toolbar.scan");
        scanButton.addActionListener(_ -> startScan());
        scanButton.setFont(scanButton.getFont().deriveFont(Font.BOLD));
        labels.text(exportButton, "toolbar.export");
        exportButton.addActionListener(_ -> export());
        exportButton.setEnabled(false);

        var c = new GridBagConstraints();
        c.insets = new Insets(5, 6, 5, 6);
        c.anchor = GridBagConstraints.WEST;
        c.gridy = 0;
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.folder"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(dirField, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(browse, c);
        c.gridx = 3;
        rows.add(scanButton, c);
        c.gridx = 4;
        rows.add(exportButton, c);

        c.gridy = 1;
        databases.addRow(rows, c);
        c.gridx = 4;
        rows.add(fixActions.button(), c);

        c.gridy = 2;
        ignoreActions.addRow(rows, c);
        c.gridx = 4;
        rows.add(scanModeCombo, c);
        labels.tip(scanModeCombo, "toolbar.scanMode.tip");
        boolean installed = opts.installed || settings.get(Settings.SCAN_MODE, "SOURCES").equals(ScanMode.INSTALLED.name());
        scanModeCombo.setSelectedIndex(installed ? 1 : 0);
        scanModeCombo.addActionListener(_ -> {
            settings.set(Settings.SCAN_MODE, scanMode().name());
            directOnlyBox.setEnabled(scanMode() == ScanMode.SOURCES);
        });
        c.gridy++;
        vexDocuments.addRow(rows, c);
        c.gridx = 4;
        labels.text(directOnlyBox, "toolbar.directOnly");
        labels.tip(directOnlyBox, "toolbar.directOnly.tip");
        directOnlyBox.setName("directOnly");
        directOnlyBox.setSelected(opts.directOnly || settings.directOnly());
        directOnlyBox.setEnabled(scanMode() == ScanMode.SOURCES);
        directOnlyBox.addActionListener(_ -> settings.set(Settings.DIRECT_ONLY, String.valueOf(directOnlyBox.isSelected())));
        rows.add(directOnlyBox, c);
        return rows;
    }

    /** The severity column says it is the environmental severity when an environment applies. */
    private void updateSeverityHeader() {
        var header = tables.findingsTable.getColumnModel().getColumn(tables.findingsTable.convertColumnIndexToView(0));
        header.setHeaderValue(I18n.text(environmentBar.environment().active() ? "column.envSeverity" : "column.severity"));
        tables.findingsTable.getTableHeader().repaint();
    }

    /** Recomputes every finding's scores for the current environment (no rescan needed). */
    private void rescore() {
        if (result == null) return;
        var selected = tables.selectedFinding();
        refreshFindings();
        if (selected != null) {
            for (int i = 0; i < tables.findingsTable.getRowCount(); i++) {
                var f = tables.findingsModel.row(tables.findingsTable.convertRowIndexToModel(i));
                if (f.id().equals(selected.id()) && f.file().equals(selected.file()) && f.scope().equals(selected.scope())
                        && f.pkg().equals(selected.pkg())) {
                    tables.findingsTable.setRowSelectionInterval(i, i);
                    tables.findingsTable.scrollRectToVisible(tables.findingsTable.getCellRect(i, 0, true));
                    break;
                }
            }
        }
        showSelected();
    }

    // ----------------------------------------------------------------------------------- filtering
    /** The filters applied to every table, then the counts; the first finding selected when none is. */
    private void applyFilters() {
        tables.filter(filterBar.facets(), filterBar.searchTerms(), filterBar.ecosystem());
        dependencyTab.filter(filterBar.ecosystem(), filterBar.searchTerms(), filterBar.facets().hideTransitive());
        updateCounts();
        int shown = tables.findingsTable.getRowCount();
        if (tables.findingsTable.getSelectedRow() < 0 && shown > 0) tables.findingsTable.setRowSelectionInterval(0, 0);
        else if (shown == 0) details.show((Finding) null);
    }

    /** The tabs' titles and the line saying how many findings are shown. */
    private void updateCounts() {
        int shown = tables.findingsTable.getRowCount(), total = tables.findingsModel.getRowCount();
        tabs.setTitleAt(FINDINGS_TAB, shown == total ? I18n.text("tab.findings", total) : I18n.text("tab.findings.filtered", shown, total));
        tabs.setTitleAt(PACKAGES_TAB, I18n.text("tab.packages", tables.packagesTable.getRowCount()));
        tabs.setTitleAt(DEPENDENCIES_TAB, dependencyTab.title());
        tabs.setTitleAt(UNRESOLVED_TAB, I18n.text("tab.unresolved", tables.unresolvedTable.getRowCount()));
        tabs.setTitleAt(IGNORED_TAB, I18n.text("tab.ignored", tables.ignoredTable.getRowCount()));
        summaryBar.showing(result == null ? " " : shown == total ? I18n.text("showing.all", total) : I18n.text("showing.some", shown, total));
    }

    /** The severities' colours, those of the look in use, in the chips and the details. */
    private void showSeverityColors() {
        summaryBar.colours();
        showSelected();
    }

    private void updateChips() {
        summaryBar.count(tables.findingsModel.rows());
    }

    private void showSelected() {
        if (tabs.getSelectedIndex() == DEPENDENCIES_TAB) details.show(dependencyTab.selectedWorstFinding());
        else details.show(tabs.getSelectedIndex());
    }

    // --------------------------------------------------------------------------------- scanning
    private ScanMode scanMode() {
        return scanModeCombo.getSelectedItem() instanceof Choice<?> choice ? (ScanMode) choice.value() : ScanMode.SOURCES;
    }

    private void chooseFolder() {
        var chooser = new JFileChooser(dirField.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle(I18n.text("folder.chooser.title"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) dirField.setText(chooser.getSelectedFile().getAbsolutePath());
    }

    private void startScan() {
        Path dir = scanFolder();
        if (!Files.isDirectory(dir)) {
            JOptionPane.showMessageDialog(this, SwingText.plain(I18n.text("scan.notAFolder", dir)), I18n.text("scan.notAFolder.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        setBusy(true);
        var dbFiles = databases.files();
        // the Maven and Gradle caches the command line names, else the home folder's; none for a direct-only scan
        boolean direct = directOnlyBox.isSelected();
        var options = new ScanOptions(ignoreActions.choice(), scanMode(), viewMenu.dbMaxAge(), LocalDate.now(), vexDocuments.filesForScan(),
                direct ? null : opts.mavenRepositoryFound(), direct ? null : opts.gradleCacheFound(), opts.cacheDir(), direct);
        new SwingWorker<ScanResult, Void>() {
            @Override
            protected ScanResult doInBackground() throws Exception {
                return Engine.scan(dir, dbFiles, options, new ScanListener() {
                    public void status(String m) { SwingUtilities.invokeLater(() -> { if (busy) status.say(() -> m); }); }
                    public void progress(double f) { SwingUtilities.invokeLater(() -> { if (busy) status.progress(f); }); }
                });
            }

            @Override
            protected void done() {
                setBusy(false);
                try {
                    showResult(get());
                } catch (ExecutionException e) {
                    status.say(() -> I18n.text("scan.failed"));
                    JOptionPane.showMessageDialog(MainWindow.this, SwingText.plain(e.getCause().getMessage()), I18n.text("scan.failed.title"),
                            JOptionPane.ERROR_MESSAGE);
                    status.tip(List.of());
                } catch (InterruptedException _) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    private void setBusy(boolean busy) {
        this.busy = busy;
        scanButton.setEnabled(!busy);
        exportButton.setEnabled(!busy && result != null);
        status.busy(busy);
        setCursor(busy ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
        fixActions.update();
    }

    private void showResult(ScanResult r) {
        result = r;
        ignoreActions.scanned(r.ignores());
        tables.findingsTable.clearSelection();
        tables.ignoredTable.clearSelection();
        tables.unresolvedModel.setRows(r.unresolved());
        refreshFindings();
        exportButton.setEnabled(true);
        // a tick stays only on a package version this scan still reports: another folder's mean nothing here
        var reported = PackageSummary.of(split.active()).stream().map(FindingTables.PackageKey::of).collect(Collectors.toSet());
        tables.ticked.retainAll(reported);
        fixActions.update();
        int files = r.fileCounts().values().stream().mapToInt(Integer::intValue).sum();
        status.say(() -> {
            String scanned = I18n.text("scan.done", files, r.dependencies().size(), r.findings().size());
            if (!r.snapshots().isEmpty()) scanned += "  ·  " + I18n.text("scan.done.databases", String.join(", ", r.snapshots().keySet()));
            int warnings = r.warnings().size() + split.warnings().size();
            if (warnings > 0) scanned += "  ·  " + I18n.text("scan.done.warnings", warnings);
            // an old database said where it is seen: its findings lack the vulnerabilities published since
            var oldest = r.warnings().stream().filter(w -> w.key().equals("warning.dbOld"))
                    .mapToLong(w -> ((Number) w.arguments().get(2)).longValue()).max();
            if (oldest.isPresent()) scanned += "  ·  " + I18n.text("scan.done.dbOld", oldest.getAsLong());
            return scanned;
        });
        updateStatusTip(r.warnings());
        if (files == 0)
            JOptionPane.showMessageDialog(this, I18n.text("scan.nothing"), I18n.text("scan.nothing.title"),
                    JOptionPane.INFORMATION_MESSAGE);
    }

    /** Whether a scan's findings are shown. */
    boolean scanned() {
        return result != null;
    }

    // ------------------------------------------------------------------------------- ignore file
    /** The findings scored for the environment, then set apart by the ignore file: the tables, the tree, the chips, the counts. */
    private void refreshFindings() {
        if (result == null) return;
        split = ignoreActions.ignores().split(Scoring.applyAll(result.findings(), environmentBar.environment(), environmentBar.preferV4()), LocalDate.now());
        tables.findingsModel.setRows(split.active());
        tables.ignoredModel.setRows(split.ignored());
        dependencyTab.show(result.dependencies(), split.active());
        updateChips();
        applyFilters();
    }

    /** The status tooltip after the ignore file is read again: the scan's warnings, the file's own read anew. */
    private void updateStatusTipAfterReread(List<Phrase> reread) {
        var warnings = new ArrayList<Phrase>();
        if (result != null) result.warnings().stream().filter(w -> !w.key().startsWith("ignore.")).forEach(warnings::add);
        warnings.addAll(reread);
        updateStatusTip(warnings);
    }

    /** The status line's tooltip: the databases read, the scan's warnings, the ignore file's. */
    private void updateStatusTip(List<Phrase> warnings) {
        var tip = new ArrayList<String>();
        if (result != null) result.snapshots().forEach((k, v) -> tip.add("<b>" + SwingText.html(k) + "</b>: " + SwingText.html(v.text())));
        warnings.forEach(w -> tip.add(SwingText.html(I18n.text("status.warning", w))));
        split.warnings().forEach(w -> tip.add(SwingText.html(I18n.text("status.warning", w))));
        status.tip(tip);
    }

    /** Ignore… on a finding; once the entry is written, the row now in its place is selected. */
    private void ignore(Finding f) {
        int row = tables.findingsTable.getSelectedRow();
        if (!ignoreActions.ignore(f)) return;
        int rows = tables.findingsTable.getRowCount();
        if (rows > 0) {
            int next = Math.min(Math.max(row, 0), rows - 1);
            tables.findingsTable.setRowSelectionInterval(next, next);
            tables.findingsTable.scrollRectToVisible(tables.findingsTable.getCellRect(next, 0, true));
        }
    }

    // ----------------------------------------------------------------------------- export, misc
    private void export() {
        ExportAction.run(this, opts.outDir, result, split, tables, environmentBar, status);
    }

    /** A link is copied, never opened: the program starts no browser (README, "No network"). */
    private void copyLink(String url) {
        if (url == null || url.isBlank()) return;
        Clipboard.copy(url);
        status.say(() -> I18n.text("link.copied", url));
    }
}
