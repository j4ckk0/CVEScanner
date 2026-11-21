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
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.cvss.Cvss;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.cvss.Scoring;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.engine.ScanListener;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Severity;
import org.jtools.cvescanner.model.Unresolved;
import org.jtools.cvescanner.report.Reports;
import org.jtools.cvescanner.version.Versions;

final class MainWindow extends JFrame {
    private record SeverityOption(String label, Severity min) {
        @Override public String toString() { return label; }
    }

    private static final List<Column<Finding>> FINDING_COLUMNS = List.of(
            new Column<Finding>("Severity", Severity.class, 112, Finding::severity),
            new Column<Finding>("Base", Double.class, 50, Finding::cvss),
            new Column<Finding>("Env.", Double.class, 50, Finding::envScore),
            new Column<Finding>("CVSS", String.class, 45, f -> Objects.requireNonNullElse(f.score().version(), "")),
            new Column<Finding>("Ecosystem", String.class, 75, Finding::ecosystem),
            new Column<Finding>("Package", String.class, 260, Finding::pkg),
            new Column<Finding>("Version", String.class, 95, Finding::displayVersion),
            new Column<Finding>("Fixed in", String.class, 95, f -> f.fixedIn().isEmpty() ? "—" : f.fixedIn()),
            new Column<Finding>("CVE", String.class, 130, Finding::cveText),
            new Column<Finding>("Advisory", String.class, 150, Finding::id),
            new Column<Finding>("Match", String.class, 125, f -> f.basis().label),
            new Column<Finding>("Scope", String.class, 110, Finding::scope),
            new Column<Finding>("File", String.class, 220, Finding::file),
            new Column<Finding>("Published", String.class, 85, Finding::publishedDate),
            new Column<Finding>("Summary", String.class, 380, Finding::summary));
    private static final List<Column<PackageSummary>> PACKAGE_COLUMNS = List.of(
            new Column<PackageSummary>("Worst severity", Severity.class, 110, PackageSummary::worst),
            new Column<PackageSummary>("Ecosystem", String.class, 75, PackageSummary::ecosystem),
            new Column<PackageSummary>("Package", String.class, 300, PackageSummary::pkg),
            new Column<PackageSummary>("Current", String.class, 100, PackageSummary::displayVersion),
            new Column<PackageSummary>("Upgrade to", String.class, 160, PackageSummary::upgradeTo),
            new Column<PackageSummary>("Vulnerabilities", Integer.class, 95, PackageSummary::vulnerabilities),
            new Column<PackageSummary>("CVEs / advisories", String.class, 260, PackageSummary::advisories),
            new Column<PackageSummary>("Found in", String.class, 330, PackageSummary::files));
    private static final List<Column<Unresolved>> UNRESOLVED_COLUMNS = List.of(
            new Column<Unresolved>("Ecosystem", String.class, 75, Unresolved::ecosystem),
            new Column<Unresolved>("Package", String.class, 300, Unresolved::name),
            new Column<Unresolved>("Declared", String.class, 160, Unresolved::declared),
            new Column<Unresolved>("Reason", String.class, 330, Unresolved::reason),
            new Column<Unresolved>("File", String.class, 300, Unresolved::file));

    private static final java.util.prefs.Preferences PREFS = java.util.prefs.Preferences.userRoot().node("cve-scan");

    private final Options opts;
    private final JTextField dirField = new JTextField(40);
    private final JTextField dbField = new JTextField(40);
    private final JButton clearDbButton = new JButton("Clear");
    private final List<Path> dbFiles = new ArrayList<>();
    private final JCheckBox downloadBox = new JCheckBox("Download from OSV.dev (needs internet)");
    private final JCheckBox hideNameMatchBox = new JCheckBox("Hide CVE name matches ⚠");
    private final JComboBox<Environment> envCombo = new JComboBox<>();
    private final JComboBox<Reach> reachCombo = new JComboBox<>(Reach.values());
    private final JComboBox<Requirement> crCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> irCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> arCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<String> cvssCombo = new JComboBox<>(new String[]{"CVSS 4.0 first", "CVSS 3.x first"});
    private Environment environment = Environment.NONE;
    private boolean preferV4 = true;
    private boolean updatingEnvironment;
    private final JButton scanButton = new JButton("Scan");
    private final JButton exportButton = new JButton("Export…");
    private final HintField searchField = new HintField("Search package, CVE, file, summary…  (all words must match)", 32);
    private final JComboBox<SeverityOption> severityCombo = new JComboBox<>(new SeverityOption[]{
            new SeverityOption("All severities", null), new SeverityOption("Critical", Severity.CRITICAL),
            new SeverityOption("High and above", Severity.HIGH), new SeverityOption("Medium and above", Severity.MEDIUM),
            new SeverityOption("Low and above", Severity.LOW)});
    private final JComboBox<String> ecosystemCombo = new JComboBox<>(new String[]{"All ecosystems", "Maven", "npm"});
    private final JCheckBox cveOnlyBox = new JCheckBox("Only with CVE ID");
    private final JCheckBox hideApproxBox = new JCheckBox("Hide approximate (≈) versions");
    private final Map<Severity, JLabel> chips = new EnumMap<>(Severity.class);
    private final JLabel showingLabel = new JLabel(" ");

    private final ListTableModel<Finding> findingsModel = new ListTableModel<>(FINDING_COLUMNS);
    private final ListTableModel<PackageSummary> packagesModel = new ListTableModel<>(PACKAGE_COLUMNS);
    private final ListTableModel<Unresolved> unresolvedModel = new ListTableModel<>(UNRESOLVED_COLUMNS);
    private final JTable findingsTable = new JTable(findingsModel);
    private final JTable packagesTable = new JTable(packagesModel);
    private final JTable unresolvedTable = new JTable(unresolvedModel);
    private final TableRowSorter<ListTableModel<Finding>> findingsSorter = new TableRowSorter<>(findingsModel);
    private final TableRowSorter<ListTableModel<PackageSummary>> packagesSorter = new TableRowSorter<>(packagesModel);
    private final TableRowSorter<ListTableModel<Unresolved>> unresolvedSorter = new TableRowSorter<>(unresolvedModel);
    private final JTabbedPane tabs = new JTabbedPane();
    private final JEditorPane detailPane = new JEditorPane("text/html", "");
    private final JLabel statusLabel = new JLabel("Choose a folder and press Scan.");
    private final JProgressBar progressBar = new JProgressBar(0, 1000);
    private final Timer searchTimer = new Timer(200, _ -> applyFilters());

    private ScanResult result;
    private boolean busy;   // progress messages arriving after a scan has finished are ignored

    MainWindow(Options opts) {
        super("CVE Dependency Scanner");
        this.opts = opts;
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        dirField.setText(opts.scanDir.toAbsolutePath().normalize().toString());
        downloadBox.setSelected(!opts.skipDownload);
        downloadBox.addActionListener(_ -> updateDatabaseField());
        if (!opts.dbFiles.isEmpty()) dbFiles.addAll(opts.dbFiles);
        else restoreDatabaseChoice();
        restoreScoringChoice();
        updateDatabaseField();
        cveOnlyBox.setSelected(opts.cveOnly);
        searchTimer.setRepeats(false);

        var north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(toolbar());
        north.add(environmentBar());
        north.add(filterBar());
        north.add(summaryBar());
        add(north, BorderLayout.NORTH);
        addComponentListener(new ComponentAdapter() {       // let wrapped toolbar rows re-flow when the window is resized
            @Override public void componentResized(ComponentEvent e) { north.revalidate(); }
        });

        configureTables();
        tabs.addTab("Findings", new JScrollPane(findingsTable));
        tabs.addTab("Packages to upgrade", new JScrollPane(packagesTable));
        tabs.addTab("Unchecked dependencies", new JScrollPane(unresolvedTable));

        detailPane.setEditable(false);
        detailPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        detailPane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) openBrowser(e.getDescription());
        });
        showDetails(null);
        var detailScroll = new JScrollPane(detailPane);
        detailScroll.setPreferredSize(new Dimension(400, 300));
        tabs.setPreferredSize(new Dimension(400, 420));
        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, detailScroll);
        split.setResizeWeight(0.6);
        split.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        add(split, BorderLayout.CENTER);

        var status = new JPanel(new BorderLayout(10, 0));
        status.setBorder(BorderFactory.createEmptyBorder(4, 10, 6, 10));
        progressBar.setPreferredSize(new Dimension(220, 14));
        progressBar.setVisible(false);
        status.add(statusLabel, BorderLayout.CENTER);
        status.add(progressBar, BorderLayout.EAST);
        add(status, BorderLayout.SOUTH);

        int menuKey = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        getRootPane().registerKeyboardAction(_ -> { searchField.requestFocusInWindow(); searchField.selectAll(); },
                KeyStroke.getKeyStroke(KeyEvent.VK_F, menuKey), JComponent.WHEN_IN_FOCUSED_WINDOW);
        searchField.registerKeyboardAction(_ -> searchField.setText(""), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_FOCUSED);
        getRootPane().setDefaultButton(scanButton);

        updateChips();
        setSize(1360, 860);
        setMinimumSize(new Dimension(900, 560));
        setLocationRelativeTo(null);
        if (opts.dirGiven) SwingUtilities.invokeLater(this::startScan);
    }

    // ------------------------------------------------------------------------------------ layout
    private JPanel toolbar() {
        var rows = new JPanel(new GridBagLayout());
        rows.setBorder(BorderFactory.createEmptyBorder(6, 8, 2, 8));
        var browse = new JButton("Browse…");
        browse.addActionListener(_ -> chooseFolder());
        scanButton.addActionListener(_ -> startScan());
        scanButton.setFont(scanButton.getFont().deriveFont(Font.BOLD));
        exportButton.addActionListener(_ -> export());
        exportButton.setEnabled(false);
        var chooseDb = new JButton("Choose database zip…");
        chooseDb.addActionListener(_ -> chooseDatabase());
        clearDbButton.addActionListener(_ -> setDatabase(List.of()));
        dbField.setEditable(false);
        downloadBox.setToolTipText("Used only when no database zip is chosen: fetches the newest OSV.dev database before scanning");

        var c = new GridBagConstraints();
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        c.gridy = 0;
        c.gridx = 0;
        rows.add(new JLabel("Project folder:"), c);
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
        c.gridx = 0;
        rows.add(new JLabel("Vulnerability database:"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(dbField, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(chooseDb, c);
        c.gridx = 3;
        rows.add(clearDbButton, c);
        c.gridx = 4;
        rows.add(downloadBox, c);
        return rows;
    }

    private JPanel filterBar() {
        var p = new JPanel(new WrapLayout(FlowLayout.LEFT, 8, 4));
        p.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4));
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void removeUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void changedUpdate(DocumentEvent e) { searchTimer.restart(); }
        });
        severityCombo.addActionListener(_ -> applyFilters());
        ecosystemCombo.addActionListener(_ -> applyFilters());
        cveOnlyBox.addActionListener(_ -> applyFilters());
        hideApproxBox.addActionListener(_ -> applyFilters());
        hideNameMatchBox.addActionListener(_ -> applyFilters());
        hideNameMatchBox.setToolTipText("Hide CVE List findings matched only by product name");
        var clear = new JButton("Clear filters");
        clear.addActionListener(_ -> {
            searchField.setText("");
            severityCombo.setSelectedIndex(0);
            ecosystemCombo.setSelectedIndex(0);
            cveOnlyBox.setSelected(false);
            hideApproxBox.setSelected(false);
            hideNameMatchBox.setSelected(false);
            applyFilters();
        });
        p.add(new JLabel("Search:"));
        p.add(searchField);
        p.add(severityCombo);
        p.add(ecosystemCombo);
        p.add(cveOnlyBox);
        p.add(hideApproxBox);
        p.add(hideNameMatchBox);
        p.add(clear);
        return p;
    }

    private JPanel environmentBar() {
        var p = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 2));
        p.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 4));
        Environment.PRESETS.forEach(envCombo::addItem);
        envCombo.setToolTipText("Environment used for the CVSS environmental score of every finding");
        reachCombo.setToolTipText("<html>How the affected software can be reached in your environment.<br>"
                + "Caps the CVSS attack vector: <i>Internal network only</i> → at most Adjacent, <i>Local access only</i> → at most Local.</html>");
        for (var c : List.of(crCombo, irCombo, arCombo))
            c.setToolTipText("<html>CVSS security requirement: how much this property matters for the system.<br>"
                    + "Low / Medium / High; <i>Not defined</i> = CVSS default (neutral in 3.x, High in 4.0).</html>");
        cvssCombo.setToolTipText("CVSS version used when an advisory provides both a 3.x and a 4.0 vector");
        var help = new JButton("?");
        help.setMargin(new Insets(1, 6, 1, 6));
        help.addActionListener(_ -> JOptionPane.showMessageDialog(this, new JLabel(ENVIRONMENT_HELP), "Environmental score",
                JOptionPane.INFORMATION_MESSAGE));
        envCombo.addActionListener(_ -> {
            if (updatingEnvironment || !(envCombo.getSelectedItem() instanceof Environment e) || e.key().equals("custom")) return;
            setEnvironment(e);
        });
        for (var c : List.<JComboBox<?>>of(reachCombo, crCombo, irCombo, arCombo))
            c.addActionListener(_ -> {
                if (!updatingEnvironment)
                    setEnvironment(Environment.of((Reach) reachCombo.getSelectedItem(), (Requirement) crCombo.getSelectedItem(),
                            (Requirement) irCombo.getSelectedItem(), (Requirement) arCombo.getSelectedItem()));
            });
        cvssCombo.addActionListener(_ -> {
            if (!updatingEnvironment) { preferV4 = cvssCombo.getSelectedIndex() == 0; rescore(); }
        });
        p.add(new JLabel("Environment:"));
        p.add(envCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(new JLabel("Reachable:"));
        p.add(reachCombo);
        p.add(new JLabel("Confidentiality:"));
        p.add(crCombo);
        p.add(new JLabel("Integrity:"));
        p.add(irCombo);
        p.add(new JLabel("Availability:"));
        p.add(arCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(cvssCombo);
        p.add(help);
        syncEnvironmentControls();
        return p;
    }

    private static final String ENVIRONMENT_HELP = """
            <html><body style='width:460px'>
            <b>Base score</b> - the CVSS score published with the advisory's vector: how severe the vulnerability is in general.<br><br>
            <b>Environmental score</b> - the same vector adjusted to <i>your</i> environment with CVSS environmental metrics.
            CVSS defines no list of environment types, so the presets below simply fill in those metrics; adjust them freely:<br><br>
            <b>Reachable</b> caps the attack vector (Modified Attack Vector):<br>
            &nbsp;• Internet / unrestricted - no change<br>
            &nbsp;• Internal network only - network attacks count as Adjacent<br>
            &nbsp;• Local access only (air-gapped) - network/adjacent attacks count as Local<br><br>
            <b>Confidentiality / Integrity / Availability</b> are the security requirements (CR / IR / AR):
            how much a breach of each would hurt this system (Low / Medium / High).<br><br>
            <b>Presets</b><br>
            &nbsp;• Internet-facing production: unrestricted, High / High / High<br>
            &nbsp;• Internal network service: internal, Medium / Medium / Medium<br>
            &nbsp;• Air-gapped / offline system: local, Medium / Medium / Medium<br>
            &nbsp;• Developer workstation / CI only: internal, Medium / High / Low<br><br>
            When an environment is applied, the <b>Severity</b> column, filters, counters and reports use the environmental
            severity (findings without a CVSS vector keep their advisory rating). Scores are computed for CVSS 3.0, 3.1 and 4.0;
            when an advisory has both versions, the selected preference decides which one is used.
            </body></html>""";

    private void setEnvironment(Environment e) {
        environment = e;
        syncEnvironmentControls();
        rescore();
    }

    private void syncEnvironmentControls() {
        updatingEnvironment = true;
        try {
            if (environment.key().equals("custom")) {
                boolean present = false;
                for (int i = 0; i < envCombo.getItemCount(); i++) present |= envCombo.getItemAt(i).key().equals("custom");
                if (!present) envCombo.addItem(new Environment("custom", "Custom", Reach.UNRESTRICTED,
                        Requirement.NOT_DEFINED, Requirement.NOT_DEFINED, Requirement.NOT_DEFINED));
                for (int i = 0; i < envCombo.getItemCount(); i++) if (envCombo.getItemAt(i).key().equals("custom")) envCombo.setSelectedIndex(i);
            } else {
                envCombo.setSelectedItem(environment);
            }
            reachCombo.setSelectedItem(environment.reach());
            crCombo.setSelectedItem(environment.confidentiality());
            irCombo.setSelectedItem(environment.integrity());
            arCombo.setSelectedItem(environment.availability());
            cvssCombo.setSelectedIndex(preferV4 ? 0 : 1);
            var header = findingsTable.getColumnModel().getColumn(findingsTable.convertColumnIndexToView(0));
            header.setHeaderValue(environment.active() ? "Env. severity" : "Severity");
            findingsTable.getTableHeader().repaint();
        } finally {
            updatingEnvironment = false;
        }
    }

    /** Recomputes every finding's scores for the current environment (no rescan needed). */
    private void rescore() {
        saveScoringChoice();
        if (result == null) return;
        var selected = selectedFinding();
        findingsModel.setRows(Scoring.applyAll(result.findings(), environment, preferV4));
        updateChips();
        applyFilters();
        if (selected != null) {
            for (int i = 0; i < findingsTable.getRowCount(); i++) {
                var f = findingsModel.row(findingsTable.convertRowIndexToModel(i));
                if (f.id().equals(selected.id()) && f.file().equals(selected.file()) && f.scope().equals(selected.scope())
                        && f.pkg().equals(selected.pkg())) {
                    findingsTable.setRowSelectionInterval(i, i);
                    findingsTable.scrollRectToVisible(findingsTable.getCellRect(i, 0, true));
                    break;
                }
            }
        }
        showDetails(selectedFinding());
    }

    private void restoreScoringChoice() {
        if (opts.environmentGiven) environment = opts.environment;
        else {
            try {
                String key = PREFS.get("env.key", "none");
                if (key.equals("custom")) {
                    environment = Environment.of(Reach.valueOf(PREFS.get("env.reach", "UNRESTRICTED")),
                            Requirement.valueOf(PREFS.get("env.cr", "NOT_DEFINED")), Requirement.valueOf(PREFS.get("env.ir", "NOT_DEFINED")),
                            Requirement.valueOf(PREFS.get("env.ar", "NOT_DEFINED")));
                } else {
                    environment = Environment.preset(key);
                }
            } catch (RuntimeException _) { environment = Environment.NONE; }
        }
        preferV4 = opts.cvssGiven ? opts.preferV4 : PREFS.getBoolean("cvss.preferV4", true);
    }

    private void saveScoringChoice() {
        try {
            PREFS.put("env.key", environment.key());
            PREFS.put("env.reach", environment.reach().name());
            PREFS.put("env.cr", environment.confidentiality().name());
            PREFS.put("env.ir", environment.integrity().name());
            PREFS.put("env.ar", environment.availability().name());
            PREFS.putBoolean("cvss.preferV4", preferV4);
        } catch (RuntimeException _) { /* preferences unavailable */ }
    }

    private JPanel summaryBar() {
        var p = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 4));
        p.setBorder(BorderFactory.createEmptyBorder(0, 6, 4, 4));
        int index = 1;
        for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN)) {
            var chip = new JLabel();
            chip.setIcon(new DotIcon(SeverityColors.of(s), 12));
            chip.setFont(chip.getFont().deriveFont(Font.BOLD, chip.getFont().getSize2D() + 1f));
            chip.setForeground(SeverityColors.of(s));
            if (s != Severity.UNKNOWN) {
                int comboIndex = index++;
                chip.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                chip.setToolTipText("Show " + s.label().toLowerCase(Locale.ROOT) + (s == Severity.CRITICAL ? "" : " and above"));
                chip.addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent e) { severityCombo.setSelectedIndex(comboIndex); }
                });
            }
            chips.put(s, chip);
            p.add(chip);
        }
        p.add(Box.createHorizontalStrut(20));
        showingLabel.setForeground(Color.GRAY);
        p.add(showingLabel);
        return p;
    }

    private void configureTables() {
        Comparator<String> version = (a, b) -> Versions.compareMaven(a.replace(" ≈", "").replace("—", ""),
                b.replace(" ≈", "").replace("—", ""));
        setup(findingsTable, findingsSorter, FINDING_COLUMNS);
        findingsSorter.setComparator(column(FINDING_COLUMNS, "Version"), version);
        findingsSorter.setComparator(column(FINDING_COLUMNS, "Fixed in"), version);
        findingsSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "Env."), SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "Base"), SortOrder.DESCENDING)));
        setup(packagesTable, packagesSorter, PACKAGE_COLUMNS);
        packagesSorter.setComparator(3, version);
        packagesSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING), new RowSorter.SortKey(5, SortOrder.DESCENDING)));
        setup(unresolvedTable, unresolvedSorter, UNRESOLVED_COLUMNS);

        var cvss = new DefaultTableCellRenderer() {
            @Override
            protected void setValue(Object v) { setText(v instanceof Double d ? "%.1f".formatted(d) : ""); }
        };
        cvss.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "Base")).setCellRenderer(cvss);
        var envRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, focus, row, col);
                setText(v instanceof Double d ? "%.1f".formatted(d) : "");
                setFont(getFont().deriveFont(Font.BOLD));
                if (!sel && v instanceof Double d) setForeground(SeverityColors.of(Severity.fromScore(d)));
                return this;
            }
        };
        envRenderer.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "Env.")).setCellRenderer(envRenderer);
        var header = findingsTable.getTableHeader();
        header.setToolTipText("<html>Severity: environmental when an environment is applied, else base.<br>"
                + "Base / Env.: CVSS base and environmental scores. CVSS: version used.</html>");

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetails(selectedFinding());
        });
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int row = findingsTable.rowAtPoint(e.getPoint());
                if (SwingUtilities.isRightMouseButton(e) && row >= 0) findingsTable.setRowSelectionInterval(row, row);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                var f = selectedFinding();
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && f != null) openBrowser(f.url());
            }
        });
        findingsTable.setComponentPopupMenu(findingsMenu());

        packagesTable.addMouseListener(new MouseAdapter() {     // double-click a package: show its findings
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = packagesTable.getSelectedRow();
                if (e.getClickCount() == 2 && row >= 0) {
                    searchField.setText(packagesModel.row(packagesTable.convertRowIndexToModel(row)).pkg());
                    tabs.setSelectedIndex(0);
                }
            }
        });
        packagesTable.setToolTipText("Double-click a package to see its individual findings");
    }

    private static <T> int column(List<Column<T>> columns, String name) {
        for (int i = 0; i < columns.size(); i++) if (columns.get(i).name().equals(name)) return i;
        throw new IllegalArgumentException(name);
    }

    private <T> void setup(JTable table, TableRowSorter<ListTableModel<T>> sorter, List<Column<T>> columns) {
        table.setRowSorter(sorter);
        table.setRowHeight(24);
        table.setAutoCreateRowSorter(false);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setDefaultRenderer(Severity.class, new SeverityRenderer());
        table.setDefaultRenderer(String.class, new TextRenderer());
        table.getTableHeader().setReorderingAllowed(true);
        for (int c = 0; c < columns.size(); c++) {
            var col = table.getColumnModel().getColumn(c);
            col.setPreferredWidth(columns.get(c).width());
            if (columns.get(c).width() <= 112) col.setMinWidth(columns.get(c).width());   // keep short columns readable
        }
        sorter.setSortsOnUpdates(true);
    }

    private JPopupMenu findingsMenu() {
        var menu = new JPopupMenu();
        menu.add(item("Open advisory in browser", f -> openBrowser(f.url())));
        menu.add(item("Open CVE on NVD", f -> f.cves().forEach(c -> openBrowser("https://nvd.nist.gov/vuln/detail/" + c))));
        menu.addSeparator();
        menu.add(item("Copy CVE IDs", f -> copy(f.cves().isEmpty() ? f.id() : f.cveText())));
        menu.add(item("Copy package coordinate", f -> copy(f.pkg() + (f.ecosystem().equals("npm") ? "@" : ":") + f.version())));
        menu.add(item("Copy row", f -> copy(String.join("\t", f.severity().name(), f.pkg(), f.version(), f.id(), f.cveText(),
                f.fixedIn(), f.file(), f.summary()))));
        menu.addSeparator();
        menu.add(item("Show only this package", f -> searchField.setText(f.pkg())));
        return menu;
    }

    private JMenuItem item(String label, Consumer<Finding> action) {
        var item = new JMenuItem(label);
        item.addActionListener(_ -> {
            var f = selectedFinding();
            if (f != null) action.accept(f);
        });
        return item;
    }

    // ----------------------------------------------------------------------------------- filtering
    private List<String> searchTerms() {
        return Arrays.stream(searchField.getText().toLowerCase(Locale.ROOT).split("\\s+")).filter(s -> !s.isBlank()).toList();
    }

    private boolean passesFacets(Finding f) {
        var sev = (SeverityOption) severityCombo.getSelectedItem();
        if (sev != null && sev.min() != null && f.severity().compareTo(sev.min()) < 0) return false;
        if (ecosystemCombo.getSelectedIndex() > 0 && !f.ecosystem().equals(ecosystemCombo.getSelectedItem())) return false;
        if (cveOnlyBox.isSelected() && f.cves().isEmpty()) return false;
        if (hideNameMatchBox.isSelected() && f.basis() == MatchBasis.CVE_NAME) return false;
        return !(hideApproxBox.isSelected() && f.approximate());
    }

    private static <M extends ListTableModel<?>> boolean matchesSearch(RowFilter.Entry<? extends M, ? extends Integer> e,
                                                                       List<String> terms, String extra) {
        if (terms.isEmpty()) return true;
        var sb = new StringBuilder(extra);
        for (int c = 0; c < e.getValueCount(); c++) sb.append('\u0001').append(e.getStringValue(c));
        String hay = sb.toString().toLowerCase(Locale.ROOT);
        return terms.stream().allMatch(hay::contains);
    }

    private void applyFilters() {
        var terms = searchTerms();
        findingsSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<Finding>, ? extends Integer> e) {
                var f = e.getModel().row(e.getIdentifier());
                return passesFacets(f) && matchesSearch(e, terms, String.join(" ", f.aliases()));
            }
        });
        // the package view is rebuilt from the findings that pass the facet filters, then searched
        packagesModel.setRows(Reports.packages(findingsModel.rows().stream().filter(this::passesFacets).toList()));
        packagesSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<PackageSummary>, ? extends Integer> e) {
                return matchesSearch(e, terms, "");
            }
        });
        unresolvedSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<Unresolved>, ? extends Integer> e) {
                var u = e.getModel().row(e.getIdentifier());
                if (ecosystemCombo.getSelectedIndex() > 0 && !u.ecosystem().equals(ecosystemCombo.getSelectedItem())) return false;
                return matchesSearch(e, terms, "");
            }
        });
        int shown = findingsTable.getRowCount(), total = findingsModel.getRowCount();
        tabs.setTitleAt(0, shown == total ? "Findings (" + total + ")" : "Findings (" + shown + " of " + total + ")");
        tabs.setTitleAt(1, "Packages to upgrade (" + packagesTable.getRowCount() + ")");
        tabs.setTitleAt(2, "Unchecked dependencies (" + unresolvedTable.getRowCount() + ")");
        showingLabel.setText(result == null ? " " : shown == total ? "Showing all " + total + " findings"
                : "Showing " + shown + " of " + total + " findings");
        if (findingsTable.getSelectedRow() < 0 && shown > 0) findingsTable.setRowSelectionInterval(0, 0);
        else if (shown == 0) showDetails(null);
    }

    private void updateChips() {
        var counts = Reports.counts(findingsModel.rows());
        chips.forEach((s, chip) -> chip.setText(s.label() + "  " + counts.get(s)));
    }

    // --------------------------------------------------------------------------------- scanning
    private void chooseDatabase() {
        File start = !dbFiles.isEmpty() ? dbFiles.getFirst().toFile().getParentFile()
                : opts.dbDir != null && Files.isDirectory(opts.dbDir) ? opts.dbDir.toFile() : new File(System.getProperty("user.home"));
        var chooser = new JFileChooser(start);
        chooser.setDialogTitle("Choose vulnerability database zip file(s)");
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Zip archives (*.zip)", "zip"));
        chooser.setAccessory(databaseHelp());
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            setDatabase(Arrays.stream(chooser.getSelectedFiles()).map(File::toPath).toList());
    }

    private static JComponent databaseHelp() {
        var help = new JLabel("""
                <html><body style='width:230px;padding-left:10px'>
                <b>Supported files</b><br><br>
                <b>GitHub Advisory Database</b> (recommended)<br>github.com/github/advisory-database<br>
                → Code → Download ZIP<br><i>Exact Maven/npm package matches, with CVE IDs.</i><br><br>
                <b>CVE List</b><br>github.com/CVEProject/cvelistV5<br>→ Releases → "all_CVEs" zip<br>
                <i>Matched by package or product name; name matches are flagged ⚠.</i><br><br>
                <b>OSV.dev</b> ecosystem exports<br>Maven/all.zip, npm/all.zip<br><br>
                You can select several files. Zips placed in the<br><b>database</b> folder next to the program are<br>
                loaded automatically at start-up.</body></html>""");
        help.setVerticalAlignment(SwingConstants.TOP);
        return help;
    }

    private void setDatabase(List<Path> files) {
        dbFiles.clear();
        dbFiles.addAll(files);
        try {
            PREFS.put("dbFiles", files.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        } catch (RuntimeException _) { /* preferences unavailable: the choice just isn't remembered */ }
        updateDatabaseField();
    }

    private void restoreDatabaseChoice() {
        try {
            String saved = PREFS.get("dbFiles", "");
            if (!saved.isBlank())
                Arrays.stream(saved.split(java.util.regex.Pattern.quote(File.pathSeparator))).map(Path::of)
                        .filter(Files::isRegularFile).forEach(dbFiles::add);
        } catch (RuntimeException _) { /* ignore */ }
    }

    private void updateDatabaseField() {
        boolean none = dbFiles.isEmpty();
        dbField.setText(none ? (downloadBox.isSelected() ? "(none chosen: OSV.dev database will be downloaded / cached copy used)"
                : "(none chosen: cached OSV.dev copy will be used)") : dbFiles.stream().map(Path::toString).collect(Collectors.joining("  ;  ")));
        dbField.setForeground(none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        dbField.setCaretPosition(0);
        downloadBox.setEnabled(none);
        clearDbButton.setEnabled(!none);
    }

    private void chooseFolder() {
        var chooser = new JFileChooser(dirField.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Folder to scan");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) dirField.setText(chooser.getSelectedFile().getAbsolutePath());
    }

    private void startScan() {
        Path dir = Path.of(dirField.getText().strip());
        if (!Files.isDirectory(dir)) {
            JOptionPane.showMessageDialog(this, "'" + dir + "' is not a folder.", "Cannot scan", JOptionPane.WARNING_MESSAGE);
            return;
        }
        setBusy(true);
        boolean download = downloadBox.isSelected() && dbFiles.isEmpty();
        var databases = List.copyOf(dbFiles);
        new SwingWorker<ScanResult, Void>() {
            @Override
            protected ScanResult doInBackground() throws Exception {
                return Engine.scan(dir, opts.cacheDir, download, databases, new ScanListener() {
                    public void status(String m) { SwingUtilities.invokeLater(() -> { if (busy) statusLabel.setText(m); }); }
                    public void progress(double f) { SwingUtilities.invokeLater(() -> { if (busy) updateProgress(f); }); }
                });
            }

            @Override
            protected void done() {
                setBusy(false);
                try {
                    show(get());
                } catch (ExecutionException e) {
                    statusLabel.setText("Scan failed.");
                    JOptionPane.showMessageDialog(MainWindow.this, e.getCause().getMessage(), "Scan failed", JOptionPane.ERROR_MESSAGE);
                    statusLabel.setToolTipText(null);
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
        progressBar.setVisible(busy);
        updateProgress(-1);
        setCursor(busy ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
    }

    private void updateProgress(double fraction) {
        progressBar.setIndeterminate(fraction < 0);
        if (fraction >= 0) progressBar.setValue((int) (fraction * 1000));
    }

    private void show(ScanResult r) {
        result = r;
        findingsTable.clearSelection();
        findingsModel.setRows(Scoring.applyAll(r.findings(), environment, preferV4));
        unresolvedModel.setRows(r.unresolved());
        updateChips();
        applyFilters();
        exportButton.setEnabled(true);
        int files = r.fileCounts().values().stream().mapToInt(Integer::intValue).sum();
        String db = r.snapshots().isEmpty() ? "" : "Database: " + String.join(", ", r.snapshots().keySet());
        statusLabel.setText("Scanned " + files + " files, " + r.dependencies().size() + " dependencies → " + r.findings().size()
                + " findings" + (db.isEmpty() ? "" : "  ·  " + db) + (r.warnings().isEmpty() ? "" : "  ·  " + r.warnings().size() + " warning(s)"));
        var tip = new ArrayList<String>();
        r.snapshots().forEach((k, v) -> tip.add("<b>" + Gui.html(k) + "</b>: " + Gui.html(v)));
        r.warnings().forEach(w -> tip.add("Warning: " + Gui.html(w)));
        statusLabel.setToolTipText(tip.isEmpty() ? null : "<html>" + String.join("<br>", tip) + "</html>");
        if (files == 0)
            JOptionPane.showMessageDialog(this, "No pom.xml, Gradle or package.json files were found in this folder.",
                    "Nothing to scan", JOptionPane.INFORMATION_MESSAGE);
    }

    // ---------------------------------------------------------------------------------- details
    private Finding selectedFinding() {
        int row = findingsTable.getSelectedRow();
        return row < 0 ? null : findingsModel.row(findingsTable.convertRowIndexToModel(row));
    }

    private void showDetails(Finding f) {
        if (f == null) {
            detailPane.setText("<html><body style='font-family:sans-serif;color:gray;padding:12px'>"
                    + (result == null ? "Scan a folder to see vulnerable dependencies." : "Select a finding to see its details.")
                    + "</body></html>");
            return;
        }
        var sb = new StringBuilder("<html><body style='font-family:sans-serif;padding:6px 10px'>");
        sb.append("<div style='font-size:15pt'><b>").append(Gui.html(f.id())).append("</b> &nbsp;<font color='")
                .append(Gui.hex(SeverityColors.of(f.severity()))).append("'><b>").append(f.severity().label());
        if (f.envScore() != null) sb.append(" · environmental ").append("%.1f".formatted(f.envScore()));
        else if (f.cvss() != null) sb.append(" · CVSS ").append("%.1f".formatted(f.cvss()));
        sb.append("</b></font></div><p><b>").append(Gui.html(f.summary())).append("</b></p><table cellpadding='2'>");
        row(sb, "Package", "<b>" + Gui.html(f.pkg()) + "</b> (" + f.ecosystem() + ")");
        row(sb, "Version in use", Gui.html(f.version()) + (f.approximate()
                ? " <font color='gray'>≈ lowest version allowed by the declared range; add a lockfile for an exact check</font>" : ""));
        var sc = f.score();
        if (sc.base() != null) {
            row(sb, "Base score", "<b>" + "%.1f".formatted(sc.base()) + "</b> " + sc.baseSeverity().label()
                    + (sc.version() != null ? " · CVSS " + sc.version() + " <font color='gray'>" + Gui.html(sc.baseVector()) + "</font>"
                                            : " <font color='gray'>(reported by the advisory, no vector)</font>"));
        } else {
            row(sb, "Base score", "<font color='gray'>no CVSS score; severity from the advisory rating ("
                    + sc.baseSeverity().label() + ")</font>");
        }
        if (environment.active()) {
            if (sc.env() != null) {
                double delta = sc.env() - sc.base();
                row(sb, "Environmental", "<b><font color='" + Gui.hex(SeverityColors.of(Severity.fromScore(sc.env()))) + "'>" + "%.1f".formatted(sc.env())
                        + " " + Severity.fromScore(sc.env()).label() + "</font></b>"
                        + (delta == 0 ? " (unchanged)" : " (%+.1f)".formatted(delta)) + " · " + Gui.html(environment.describe())
                        + "<br><font color='gray'>" + Gui.html(sc.envVector()) + "</font>");
            } else {
                row(sb, "Environmental", "<font color='gray'>not computed: the advisory has no CVSS vector</font>");
            }
        }
        if (f.rating().cvss3() != null && f.rating().cvss4() != null) {
            String other = Objects.equals(sc.baseVector(), f.rating().cvss4()) ? f.rating().cvss3() : f.rating().cvss4();
            Double otherScore = Cvss.baseScore(other);
            row(sb, "Other version", "CVSS " + Cvss.version(other) + " base " + (otherScore == null ? "—" : "%.1f".formatted(otherScore))
                    + " <font color='gray'>" + Gui.html(other) + "</font>");
        }
        row(sb, "Fixed in", f.fixedIn().isEmpty() ? "<font color='#b00020'>no fixed version published</font>" : "<b>" + Gui.html(f.fixedIn()) + "</b>");
        row(sb, "CVE", f.cves().isEmpty() ? "—" : f.cves().stream()
                .map(c -> "<a href='https://nvd.nist.gov/vuln/detail/" + c + "'>" + c + "</a>").collect(Collectors.joining(", ")));
        if (!f.aliases().isEmpty()) row(sb, "Aliases", Gui.html(String.join(", ", f.aliases())));
        row(sb, "Found in", Gui.html(f.file()) + " · " + Gui.html(f.scope()));
        row(sb, "Match", (f.basis() == MatchBasis.CVE_NAME ? "<font color='#b7791f'><b>⚠ " : "<b>") + Gui.html(f.basis().label.replace(" ⚠", ""))
                + "</b>" + (f.basis() == MatchBasis.CVE_NAME ? "</font>" : "") + " — " + Gui.html(f.basisNote()));
        if (!f.published().isEmpty()) row(sb, "Published", f.publishedDate());
        row(sb, f.basis() == MatchBasis.ADVISORY ? "Advisory" : "CVE record", "<a href='" + f.url() + "'>" + f.url() + "</a>");
        sb.append("</table>");
        if (!f.details().isBlank()) {
            String d = f.details().length() > 8000 ? f.details().substring(0, 8000) + "…" : f.details();
            sb.append("<hr><div>").append(Gui.html(d).replace("\n\n", "<p>").replace("\n", "<br>")).append("</div>");
        }
        detailPane.setText(sb.append("</body></html>").toString());
        detailPane.setCaretPosition(0);
    }

    private static void row(StringBuilder sb, String label, String valueHtml) {
        sb.append("<tr><td valign='top'><font color='gray'>").append(label).append("</font></td><td>").append(valueHtml).append("</td></tr>");
    }

    // ----------------------------------------------------------------------------- export, misc
    private void export() {
        if (result == null) return;
        var chooser = new JFileChooser(opts.outDir.toAbsolutePath().toFile());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Export the " + findingsTable.getRowCount() + " visible findings to folder");
        chooser.setApproveButtonText("Export here");
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        var visible = IntStream.range(0, findingsTable.getRowCount())
                .mapToObj(i -> findingsModel.row(findingsTable.convertRowIndexToModel(i))).toList();
        boolean filtered = visible.size() != findingsModel.getRowCount();
        try {
            var written = Reports.writeAll(result, visible, chooser.getSelectedFile().toPath(),
                    filtered ? "filtered view in the GUI (" + visible.size() + " of " + findingsModel.getRowCount() + " findings)" : null,
                    environment, preferV4);
            int choice = JOptionPane.showOptionDialog(this, "Wrote:\n" + written.stream().map(Path::toString).collect(Collectors.joining("\n")),
                    "Export complete", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null,
                    new Object[]{"Open folder", "OK"}, "OK");
            if (choice == 0 && Desktop.isDesktopSupported()) Desktop.getDesktop().open(chooser.getSelectedFile());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (IOException | IllegalArgumentException _) { /* fall through to copying the link */ }
        copy(url);
        statusLabel.setText("Link copied to clipboard: " + url);
    }

    private static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
}
