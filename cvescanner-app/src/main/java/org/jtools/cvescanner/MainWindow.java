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
import java.time.LocalDate;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
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
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreFile;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanListener;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Scoring;
import org.jtools.cvescanner.model.Unresolved;
import org.jtools.cvescanner.report.Reports;
import org.jtools.cvescanner.version.Versions;

/**
 * The window: the folder and the databases to scan, the ignore file to read, the environment to score for, the
 * findings' table with its filters, the details of the finding selected. Every text is bound to its key (I18nLabels)
 * and set again when the language changes; a column or a choice is known by its key, never by the text it shows.
 */
final class MainWindow extends JFrame {

    /** A choice of a drop list, shown in the language in use. */
    private record Choice<T>(String key, T value) {
        @Override public String toString() { return I18n.text(key); }
    }

    private static final List<Column<Finding>> FINDING_COLUMNS = List.of(
            new Column<Finding>("column.severity", Severity.class, 175, Finding::severity),
            new Column<Finding>("column.base", Double.class, 95, Finding::cvss),
            new Column<Finding>("column.env", Double.class, 140, Finding::envScore),
            new Column<Finding>("column.cvss", String.class, 95, f -> Objects.requireNonNullElse(f.score().version(), "")),
            new Column<Finding>("column.ecosystem", String.class, 100, Finding::ecosystem),
            new Column<Finding>("column.package", String.class, 320, Finding::pkg),
            new Column<Finding>("column.version", String.class, 95, Finding::displayVersion),
            new Column<Finding>("column.fixedIn", String.class, 95, f -> f.fixedIn().isEmpty() ? "—" : f.fixedIn()),
            new Column<Finding>("column.cve", String.class, 130, Finding::cveText),
            new Column<Finding>("column.advisory", String.class, 150, Finding::id),
            new Column<Finding>("column.match", String.class, 125, f -> f.basis().label()),
            new Column<Finding>("column.scope", String.class, 160, Finding::scope),
            new Column<Finding>("column.file", String.class, 220, Finding::file),
            new Column<Finding>("column.published", String.class, 85, Finding::publishedDate),
            new Column<Finding>("column.summary", String.class, 380, Finding::summary));
    private static final List<Column<PackageSummary>> PACKAGE_COLUMNS = List.of(
            new Column<PackageSummary>("column.worst", Severity.class, 110, PackageSummary::worst),
            new Column<PackageSummary>("column.ecosystem", String.class, 75, PackageSummary::ecosystem),
            new Column<PackageSummary>("column.package", String.class, 300, PackageSummary::pkg),
            new Column<PackageSummary>("column.current", String.class, 100, PackageSummary::displayVersion),
            new Column<PackageSummary>("column.upgradeTo", String.class, 160, p -> p.upgradeTo()),
            new Column<PackageSummary>("column.vulnerabilities", Integer.class, 95, PackageSummary::vulnerabilities),
            new Column<PackageSummary>("column.advisories", String.class, 260, PackageSummary::advisories),
            new Column<PackageSummary>("column.foundIn", String.class, 330, PackageSummary::files));
    private static final List<Column<IgnoredFinding>> IGNORED_COLUMNS = List.of(
            new Column<IgnoredFinding>("column.severity", Severity.class, 175, i -> i.finding().severity()),
            new Column<IgnoredFinding>("column.env", Double.class, 140, i -> i.finding().envScore()),
            new Column<IgnoredFinding>("column.ecosystem", String.class, 100, i -> i.finding().ecosystem()),
            new Column<IgnoredFinding>("column.package", String.class, 300, i -> i.finding().pkg()),
            new Column<IgnoredFinding>("column.version", String.class, 95, i -> i.finding().displayVersion()),
            new Column<IgnoredFinding>("column.cve", String.class, 130, i -> i.finding().cveText()),
            new Column<IgnoredFinding>("column.advisory", String.class, 150, i -> i.finding().id()),
            new Column<IgnoredFinding>("column.until", String.class, 110, i -> i.rule().until() == null ? "—" : i.rule().until().toString()),
            new Column<IgnoredFinding>("column.reason", String.class, 330, i -> i.rule().reason()),
            new Column<IgnoredFinding>("column.file", String.class, 220, i -> i.finding().file()));
    private static final List<Column<Unresolved>> UNRESOLVED_COLUMNS = List.of(
            new Column<Unresolved>("column.ecosystem", String.class, 75, Unresolved::ecosystem),
            new Column<Unresolved>("column.package", String.class, 300, Unresolved::name),
            new Column<Unresolved>("column.declared", String.class, 160, Unresolved::declared),
            new Column<Unresolved>("column.reason", String.class, 330, u -> u.reason().text()),
            new Column<Unresolved>("column.file", String.class, 300, Unresolved::file));

    private final Options opts;
    private final Settings settings;
    private final I18nLabels labels = new I18nLabels();
    private final I18nLanguageBox languageBox = new I18nLanguageBox(labels);
    /** The look items of View ▸ Look, each holding its look's class under LOOK_CLASS. */
    private final List<JRadioButtonMenuItem> lookItems = new ArrayList<>();
    private static final String LOOK_CLASS = "lookClass";
    private final JTextField dirField = new JTextField(40);
    private final JTextField dbField = new JTextField(40);
    private final JButton clearDbButton = new JButton();
    private final List<Path> dbFiles = new ArrayList<>();
    private final JTextField ignoreField = new JTextField(40);
    private final JButton ownIgnoreButton = new JButton();
    /** The ignore file to read: null for the folder's own, Ignores.DISABLED for none (Engine.scan). */
    private Path ignoreChoice;
    private final JCheckBox hideNameMatchBox = new JCheckBox();
    private final JComboBox<Environment> envCombo = new JComboBox<>();
    private final JComboBox<Reach> reachCombo = new JComboBox<>(Reach.values());
    private final JComboBox<Requirement> crCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> irCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> arCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Choice<Boolean>> cvssCombo = new JComboBox<>(List.of(
            new Choice<>("environment.cvss4First", true), new Choice<>("environment.cvss3First", false)).toArray(Choice[]::new));
    private Environment environment = Environment.NONE;
    private boolean preferV4 = true;
    private boolean updatingEnvironment;
    private final JButton scanButton = new JButton();
    private final JButton exportButton = new JButton();
    private final HintField searchField = new HintField("", 32);
    private final JComboBox<Choice<Severity>> severityCombo = new JComboBox<>(List.of(
            new Choice<Severity>("filter.allSeverities", null), new Choice<>("filter.critical", Severity.CRITICAL),
            new Choice<>("filter.highUp", Severity.HIGH), new Choice<>("filter.mediumUp", Severity.MEDIUM),
            new Choice<>("filter.lowUp", Severity.LOW)).toArray(Choice[]::new));
    private final JComboBox<Choice<String>> ecosystemCombo = new JComboBox<>(List.of(
            new Choice<String>("filter.allEcosystems", null), new Choice<>("filter.maven", "Maven"),
            new Choice<>("filter.npm", "npm"), new Choice<>("filter.cots", "COTS")).toArray(Choice[]::new));
    private final JCheckBox cveOnlyBox = new JCheckBox();
    private final JCheckBox hideApproxBox = new JCheckBox();
    private final Map<Severity, JLabel> chips = new EnumMap<>(Severity.class);
    private final JLabel showingLabel = new JLabel(" ");

    private final ListTableModel<Finding> findingsModel = new ListTableModel<>(FINDING_COLUMNS);
    private final ListTableModel<PackageSummary> packagesModel = new ListTableModel<>(PACKAGE_COLUMNS);
    private final ListTableModel<Unresolved> unresolvedModel = new ListTableModel<>(UNRESOLVED_COLUMNS);
    private final ListTableModel<IgnoredFinding> ignoredModel = new ListTableModel<>(IGNORED_COLUMNS);
    private final JTable findingsTable = new ScrollingTable(findingsModel);
    private final JTable packagesTable = new ScrollingTable(packagesModel);
    private final JTable unresolvedTable = new ScrollingTable(unresolvedModel);
    private final JTable ignoredTable = new ScrollingTable(ignoredModel);
    private final TableRowSorter<ListTableModel<Finding>> findingsSorter = new TableRowSorter<>(findingsModel);
    private final TableRowSorter<ListTableModel<PackageSummary>> packagesSorter = new TableRowSorter<>(packagesModel);
    private final TableRowSorter<ListTableModel<Unresolved>> unresolvedSorter = new TableRowSorter<>(unresolvedModel);
    private final TableRowSorter<ListTableModel<IgnoredFinding>> ignoredSorter = new TableRowSorter<>(ignoredModel);
    private final JTabbedPane tabs = new JTabbedPane();
    private final JEditorPane detailPane = new JEditorPane("text/html", "");
    private final JLabel statusLabel = Gui.noHtml(new JLabel(" "));
    private final JProgressBar progressBar = new JProgressBar(0, 1000);
    private final Timer searchTimer = new Timer(200, _ -> applyFilters());

    private ScanResult result;
    /** The ignore file in use, the scan's or the one chosen since; read again after the window writes it. */
    private Ignores ignores = Ignores.NONE;
    /** The scan's findings scored for the environment, those the ignore file sets aside apart. */
    private Ignores.Split split = Ignores.Split.none(List.of());
    private boolean busy;   // progress messages arriving after a scan has finished are ignored
    /** What the status line says, said again in the language chosen. */
    private Supplier<String> statusMessage = () -> I18n.text("status.ready");

    MainWindow(Options opts, Settings settings) {
        this.opts = opts;
        this.settings = settings;
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        labels.bind(this::setTitle, "window.title");
        dirField.setText(opts.scanDir.toAbsolutePath().normalize().toString());
        if (!opts.dbFiles.isEmpty()) dbFiles.addAll(opts.dbFiles);
        else restoreDatabaseChoice();
        ignoreChoice = opts.ignoreChoice();
        restoreScoringChoice();
        cveOnlyBox.setSelected(opts.cveOnly);
        searchTimer.setRepeats(false);
        setJMenuBar(menuBar());

        var north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        // the rows of controls, each group apart: where to scan, how to score, what to show
        north.add(toolbar());
        north.add(separator());
        north.add(environmentBar());
        north.add(separator());
        north.add(filterBar());
        north.add(summaryBar());
        add(north, BorderLayout.NORTH);
        addComponentListener(new ComponentAdapter() {       // let wrapped toolbar rows re-flow when the window is resized
            @Override public void componentResized(ComponentEvent e) { north.revalidate(); }
        });

        configureTables();
        tabs.addTab("", new JScrollPane(findingsTable));
        tabs.addTab("", new JScrollPane(packagesTable));
        tabs.addTab("", new JScrollPane(unresolvedTable));
        tabs.addTab("", new JScrollPane(ignoredTable));
        tabs.addChangeListener(_ -> showSelected());

        detailPane.setEditable(false);
        detailPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        detailPane.addHyperlinkListener(e -> {
            // the address as the page wrote it (getDescription), never resolved into a URL
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) copyLink(e.getDescription());
        });
        var detailScroll = new JScrollPane(detailPane);
        detailScroll.setPreferredSize(new Dimension(400, 300));
        tabs.setPreferredSize(new Dimension(400, 420));
        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, detailScroll);
        split.setResizeWeight(0.6);
        split.setDividerSize(10);
        split.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 16));
        add(split, BorderLayout.CENTER);

        var status = new JPanel(new BorderLayout(16, 0));
        status.setBorder(BorderFactory.createEmptyBorder(8, 18, 10, 18));
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

        // what is shown from data rather than bound to one key: said again in the language chosen
        labels.on(() -> statusLabel.setText(statusMessage.get()));
        labels.on(this::updateDatabaseField);
        labels.on(this::updateIgnoreField);
        labels.on(this::updateChips);
        showSeverityColors();
        labels.on(this::updateCounts);
        labels.on(() -> showSelected());
        labels.on(this::syncEnvironmentControls);
        labels.on(() -> List.of(severityCombo, ecosystemCombo, cvssCombo, envCombo, reachCombo, crCombo, irCombo, arCombo)
                .forEach(Component::repaint));
        labels.on(() -> List.of(findingsTable, packagesTable, unresolvedTable, ignoredTable).forEach(Component::repaint));
        setSize(1480, 940);
        setMinimumSize(new Dimension(1000, 640));
        setLocationRelativeTo(null);
        if (opts.dirGiven) SwingUtilities.invokeLater(this::startScan);
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
        JMenu view = labels.menu(new JMenu(), "menu.view");
        view.add(lookMenu());
        JMenuBar bar = new JMenuBar();
        bar.add(file);
        bar.add(view);
        bar.add(HelpMenu.of(this, labels));
        // the language on the right of the menus
        bar.add(Box.createHorizontalGlue());
        languageBox.onChoice(this::useLanguage);
        bar.add(languageBox);
        bar.add(Box.createHorizontalStrut(4));
        return bar;
    }

    /**
     * View ▸ Look: FlatLaf's looks, light and dark, and those Java has here — the system's, Nimbus, Metal… —, the one
     * chosen kept for the next time (Settings), the window shown in it at once.
     */
    private JMenu lookMenu() {
        JMenu menu = labels.menu(new JMenu(), "menu.look");
        String current = currentLook();
        String system = UIManager.getSystemLookAndFeelClassName();
        List<UIManager.LookAndFeelInfo> installed = new ArrayList<>(List.of(UIManager.getInstalledLookAndFeels()));
        // FlatLaf's first, then the system's, then the others as Java lists them
        installed.sort(Comparator.comparingInt((UIManager.LookAndFeelInfo look) ->
                look.getClassName().startsWith("com.formdev.flatlaf") ? 0
                        : look.getClassName().equals(system) ? 1 : 2));
        ButtonGroup looks = new ButtonGroup();
        for (UIManager.LookAndFeelInfo look : installed) {
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(look.getName(), look.getClassName().equals(current));
            if (look.getClassName().equals(system)) {
                labels.on(() -> item.setText(I18n.text("menu.look.system", look.getName())));
            }
            item.putClientProperty(LOOK_CLASS, look.getClassName());
            item.addActionListener(_ -> applyLook(look.getClassName()));
            looks.add(item);
            lookItems.add(item);
            menu.add(item);
        }
        return menu;
    }

    private static String currentLook() {
        return UIManager.getLookAndFeel().getClass().getName();
    }

    /** Shows the window in this look, keeps it for the next time, and says so in the menu. */
    private void applyLook(String className) {
        Looks.use(className);
        SwingUtilities.updateComponentTreeUI(this);
        showSeverityColors();
        settings.set(Settings.LOOK, currentLook());
        for (JRadioButtonMenuItem item : lookItems) {
            item.setSelected(currentLook().equals(item.getClientProperty(LOOK_CLASS)));
        }
    }

    /** Speaks this language from now on, and the next time (Settings). */
    private void useLanguage(I18nLanguage chosen) {
        I18n.use(chosen);
        settings.set(Settings.LANGUAGE, chosen.code());
        useSwingLocale();
        labels.relabel();
        languageBox.show(chosen);
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
        var chooseDb = labels.text(new JButton(), "toolbar.chooseDatabase");
        chooseDb.addActionListener(_ -> chooseDatabase());
        labels.text(clearDbButton, "toolbar.clearDatabase");
        clearDbButton.addActionListener(_ -> setDatabase(List.of()));
        dbField.setEditable(false);

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
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.database"), c);
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

        var chooseIgnore = labels.text(new JButton(), "toolbar.chooseIgnoreFile");
        chooseIgnore.addActionListener(_ -> chooseIgnoreFile());
        labels.text(ownIgnoreButton, "toolbar.ownIgnoreFile");
        ownIgnoreButton.addActionListener(_ -> setIgnoreChoice(null));
        ignoreField.setEditable(false);
        c.gridy = 2;
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.ignoreFile"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(ignoreField, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(chooseIgnore, c);
        c.gridx = 3;
        rows.add(ownIgnoreButton, c);
        return rows;
    }

    private JPanel filterBar() {
        var p = new JPanel(new WrapLayout(FlowLayout.LEFT, 12, 8));
        p.setBorder(BorderFactory.createEmptyBorder(6, 8, 2, 8));
        labels.bind(searchField::setHint, "filter.searchHint");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void removeUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void changedUpdate(DocumentEvent e) { searchTimer.restart(); }
        });
        severityCombo.addActionListener(_ -> applyFilters());
        ecosystemCombo.addActionListener(_ -> applyFilters());
        labels.text(cveOnlyBox, "filter.onlyWithCve").addActionListener(_ -> applyFilters());
        labels.text(hideApproxBox, "filter.hideApproximate").addActionListener(_ -> applyFilters());
        labels.text(hideNameMatchBox, "filter.hideNameMatches").addActionListener(_ -> applyFilters());
        labels.tip(hideNameMatchBox, "filter.hideNameMatches.tip");
        var clear = labels.text(new JButton(), "filter.clear");
        clear.addActionListener(_ -> {
            searchField.setText("");
            severityCombo.setSelectedIndex(0);
            ecosystemCombo.setSelectedIndex(0);
            cveOnlyBox.setSelected(false);
            hideApproxBox.setSelected(false);
            hideNameMatchBox.setSelected(false);
            applyFilters();
        });
        p.add(labels.text(new JLabel(), "filter.search"));
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
        var p = new JPanel(new WrapLayout(FlowLayout.LEFT, 10, 8));
        p.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 8));
        Environment.PRESETS.forEach(envCombo::addItem);
        labels.tip(envCombo, "environment.preset.tip");
        labels.tip(reachCombo, "environment.reach.tip");
        for (var c : List.of(crCombo, irCombo, arCombo)) labels.tip(c, "environment.requirement.tip");
        labels.tip(cvssCombo, "environment.cvss.tip");
        var help = new JButton("?");
        help.setMargin(new Insets(1, 6, 1, 6));
        help.addActionListener(_ -> JOptionPane.showMessageDialog(this, new JLabel(I18n.text("environment.help")),
                I18n.text("environment.help.title"), JOptionPane.INFORMATION_MESSAGE));
        envCombo.addActionListener(_ -> {
            if (updatingEnvironment || !(envCombo.getSelectedItem() instanceof Environment e) || e.key().equals(Environment.CUSTOM)) return;
            setEnvironment(e);
        });
        for (var c : List.<JComboBox<?>>of(reachCombo, crCombo, irCombo, arCombo))
            c.addActionListener(_ -> {
                if (!updatingEnvironment)
                    setEnvironment(Environment.of((Reach) reachCombo.getSelectedItem(), (Requirement) crCombo.getSelectedItem(),
                            (Requirement) irCombo.getSelectedItem(), (Requirement) arCombo.getSelectedItem()));
            });
        cvssCombo.addActionListener(_ -> {
            if (!updatingEnvironment && cvssCombo.getSelectedItem() instanceof Choice<?> choice) {
                preferV4 = (Boolean) choice.value();
                rescore();
            }
        });
        p.add(labels.text(new JLabel(), "environment.label"));
        p.add(envCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(labels.text(new JLabel(), "environment.reachable"));
        p.add(reachCombo);
        p.add(labels.text(new JLabel(), "environment.confidentiality"));
        p.add(crCombo);
        p.add(labels.text(new JLabel(), "environment.integrity"));
        p.add(irCombo);
        p.add(labels.text(new JLabel(), "environment.availability"));
        p.add(arCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(cvssCombo);
        p.add(help);
        return p;
    }

    private void setEnvironment(Environment e) {
        environment = e;
        syncEnvironmentControls();
        rescore();
    }

    private void syncEnvironmentControls() {
        updatingEnvironment = true;
        try {
            if (environment.key().equals(Environment.CUSTOM)) {
                boolean present = false;
                for (int i = 0; i < envCombo.getItemCount(); i++) present |= envCombo.getItemAt(i).key().equals(Environment.CUSTOM);
                if (!present) envCombo.addItem(new Environment(Environment.CUSTOM, Reach.UNRESTRICTED,
                        Requirement.NOT_DEFINED, Requirement.NOT_DEFINED, Requirement.NOT_DEFINED));
                for (int i = 0; i < envCombo.getItemCount(); i++) if (envCombo.getItemAt(i).key().equals(Environment.CUSTOM)) envCombo.setSelectedIndex(i);
            } else {
                envCombo.setSelectedItem(environment);
            }
            reachCombo.setSelectedItem(environment.reach());
            crCombo.setSelectedItem(environment.confidentiality());
            irCombo.setSelectedItem(environment.integrity());
            arCombo.setSelectedItem(environment.availability());
            cvssCombo.setSelectedIndex(preferV4 ? 0 : 1);
            var header = findingsTable.getColumnModel().getColumn(findingsTable.convertColumnIndexToView(0));
            header.setHeaderValue(I18n.text(environment.active() ? "column.envSeverity" : "column.severity"));
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
        refreshFindings();
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
        showSelected();
    }

    private void restoreScoringChoice() {
        if (opts.environmentGiven) environment = opts.environment;
        else {
            try {
                String key = settings.get(Settings.ENVIRONMENT, "none");
                if (key.equals(Environment.CUSTOM)) {
                    environment = Environment.of(Reach.valueOf(settings.get(Settings.REACH, "UNRESTRICTED")),
                            Requirement.valueOf(settings.get(Settings.CONFIDENTIALITY, "NOT_DEFINED")),
                            Requirement.valueOf(settings.get(Settings.INTEGRITY, "NOT_DEFINED")),
                            Requirement.valueOf(settings.get(Settings.AVAILABILITY, "NOT_DEFINED")));
                } else {
                    environment = Environment.preset(key);
                }
            } catch (RuntimeException _) { environment = Environment.NONE; }   // a value of another version: the default
        }
        preferV4 = opts.cvssGiven ? opts.preferV4 : Boolean.parseBoolean(settings.get(Settings.PREFER_CVSS4, "true"));
    }

    private void saveScoringChoice() {
        settings.set(Settings.ENVIRONMENT, environment.key());
        settings.set(Settings.REACH, environment.reach().name());
        settings.set(Settings.CONFIDENTIALITY, environment.confidentiality().name());
        settings.set(Settings.INTEGRITY, environment.integrity().name());
        settings.set(Settings.AVAILABILITY, environment.availability().name());
        settings.set(Settings.PREFER_CVSS4, Boolean.toString(preferV4));
    }

    private JPanel summaryBar() {
        var p = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 6));
        p.setBorder(BorderFactory.createEmptyBorder(2, 10, 10, 8));
        int index = 1;
        for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN)) {
            var chip = new JLabel();
            chip.setFont(chip.getFont().deriveFont(Font.BOLD, chip.getFont().getSize2D() + 1f));
            if (s != Severity.UNKNOWN) {
                int comboIndex = index++;
                chip.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                labels.on(() -> chip.setToolTipText(I18n.text(s == Severity.CRITICAL ? "chip.tip.only" : "chip.tip.andAbove",
                        s.label().toLowerCase(I18n.language().locale()))));
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
        findingsSorter.setComparator(column(FINDING_COLUMNS, "column.version"), version);
        findingsSorter.setComparator(column(FINDING_COLUMNS, "column.fixedIn"), version);
        findingsSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "column.env"), SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "column.base"), SortOrder.DESCENDING)));
        setup(packagesTable, packagesSorter, PACKAGE_COLUMNS);
        packagesSorter.setComparator(column(PACKAGE_COLUMNS, "column.current"), version);
        packagesSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(PACKAGE_COLUMNS, "column.vulnerabilities"), SortOrder.DESCENDING)));
        setup(unresolvedTable, unresolvedSorter, UNRESOLVED_COLUMNS);
        setup(ignoredTable, ignoredSorter, IGNORED_COLUMNS);
        ignoredSorter.setComparator(column(IGNORED_COLUMNS, "column.version"), version);
        ignoredSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(IGNORED_COLUMNS, "column.env"), SortOrder.DESCENDING)));

        var cvss = new DefaultTableCellRenderer() {
            @Override
            protected void setValue(Object v) { setText(v instanceof Double d ? Gui.score(d) : ""); }
        };
        cvss.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "column.base")).setCellRenderer(cvss);
        var envRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, focus, row, col);
                setText(v instanceof Double d ? Gui.score(d) : "");
                setFont(getFont().deriveFont(Font.BOLD));
                if (!sel && v instanceof Double d) setForeground(SeverityColors.of(Severity.fromScore(d)));
                return this;
            }
        };
        envRenderer.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "column.env")).setCellRenderer(envRenderer);
        ignoredTable.getColumnModel().getColumn(column(IGNORED_COLUMNS, "column.env")).setCellRenderer(envRenderer);
        labels.tip(findingsTable.getTableHeader(), "column.header.tip");

        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelected();
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
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && f != null) copyLink(f.url());
            }
        });
        findingsTable.setComponentPopupMenu(findingsMenu());

        ignoredTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelected();
        });
        ignoredTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int row = ignoredTable.rowAtPoint(e.getPoint());
                if (SwingUtilities.isRightMouseButton(e) && row >= 0) ignoredTable.setRowSelectionInterval(row, row);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                var i = selectedIgnored();
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && i != null) copyLink(i.finding().url());
            }
        });
        ignoredTable.setComponentPopupMenu(ignoredMenu());

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
        labels.tip(packagesTable, "packages.tip");
    }

    private static <T> int column(List<Column<T>> columns, String key) {
        for (int i = 0; i < columns.size(); i++) if (columns.get(i).key().equals(key)) return i;
        throw new IllegalArgumentException(key);
    }

    private <T> void setup(JTable table, TableRowSorter<ListTableModel<T>> sorter, List<Column<T>> columns) {
        table.setRowSorter(sorter);
        table.setRowHeight(30);
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
            if (columns.get(c).width() <= 175) col.setMinWidth(columns.get(c).width());   // keep short columns readable
        }
        // the headers in the language in use: each column by its model index, wherever it was dragged
        labels.on(() -> {
            for (int c = 0; c < table.getColumnCount(); c++) {
                var col = table.getColumnModel().getColumn(c);
                col.setHeaderValue(I18n.text(columns.get(col.getModelIndex()).key()));
            }
            table.getTableHeader().repaint();
        });
        sorter.setSortsOnUpdates(true);
    }

    private JPopupMenu findingsMenu() {
        var menu = new JPopupMenu();
        menu.add(item("menu.finding.copyAdvisoryLink", f -> copyLink(f.url())));
        menu.add(item("menu.finding.copyNvdLink", f -> copyLink(f.cves().stream().map(FindingDetails::nvdUrl).collect(Collectors.joining(" ")))));
        menu.addSeparator();
        menu.add(item("menu.finding.copyCves", f -> copy(f.cves().isEmpty() ? f.id() : f.cveText())));
        menu.add(item("menu.finding.copyCoordinate", f -> copy(f.pkg() + (f.ecosystem().equals("npm") ? "@" : ":") + f.version())));
        menu.add(item("menu.finding.copyRow", f -> copy(String.join("\t", f.severity().name(), f.pkg(), f.version(), f.id(), f.cveText(),
                f.fixedIn(), f.file(), f.summary()))));
        menu.addSeparator();
        menu.add(item("menu.finding.onlyThisPackage", f -> searchField.setText(f.pkg())));
        menu.addSeparator();
        menu.add(item("menu.finding.ignore", this::ignore));
        return menu;
    }

    private JPopupMenu ignoredMenu() {
        var menu = new JPopupMenu();
        var stop = labels.text(new JMenuItem(), "menu.ignored.stop");
        stop.addActionListener(_ -> {
            var i = selectedIgnored();
            if (i != null) stopIgnoring(i);
        });
        menu.add(stop);
        menu.addSeparator();
        var link = labels.text(new JMenuItem(), "menu.finding.copyAdvisoryLink");
        link.addActionListener(_ -> {
            var i = selectedIgnored();
            if (i != null) copyLink(i.finding().url());
        });
        menu.add(link);
        return menu;
    }

    private JMenuItem item(String key, Consumer<Finding> action) {
        var item = labels.text(new JMenuItem(), key);
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

    private String ecosystemShown() {
        return ecosystemCombo.getSelectedItem() instanceof Choice<?> choice ? (String) choice.value() : null;
    }

    private boolean passesFacets(Finding f) {
        var min = severityCombo.getSelectedItem() instanceof Choice<?> choice ? (Severity) choice.value() : null;
        if (min != null && f.severity().compareTo(min) < 0) return false;
        String ecosystem = ecosystemShown();
        if (ecosystem != null && !f.ecosystem().equals(ecosystem)) return false;
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
        packagesModel.setRows(PackageSummary.of(findingsModel.rows().stream().filter(this::passesFacets).toList()));
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
                String ecosystem = ecosystemShown();
                if (ecosystem != null && !u.ecosystem().equals(ecosystem)) return false;
                return matchesSearch(e, terms, "");
            }
        });
        ignoredSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<IgnoredFinding>, ? extends Integer> e) {
                var i = e.getModel().row(e.getIdentifier());
                String ecosystem = ecosystemShown();
                if (ecosystem != null && !i.finding().ecosystem().equals(ecosystem)) return false;
                return matchesSearch(e, terms, i.rule().reason());
            }
        });
        updateCounts();
        int shown = findingsTable.getRowCount();
        if (findingsTable.getSelectedRow() < 0 && shown > 0) findingsTable.setRowSelectionInterval(0, 0);
        else if (shown == 0) showDetails(null);
    }

    /** The tabs' titles and the line saying how many findings are shown. */
    private void updateCounts() {
        int shown = findingsTable.getRowCount(), total = findingsModel.getRowCount();
        tabs.setTitleAt(0, shown == total ? I18n.text("tab.findings", total) : I18n.text("tab.findings.filtered", shown, total));
        tabs.setTitleAt(1, I18n.text("tab.packages", packagesTable.getRowCount()));
        tabs.setTitleAt(2, I18n.text("tab.unresolved", unresolvedTable.getRowCount()));
        tabs.setTitleAt(3, I18n.text("tab.ignored", ignoredTable.getRowCount()));
        showingLabel.setText(result == null ? " " : shown == total ? I18n.text("showing.all", total)
                : I18n.text("showing.some", shown, total));
    }

    /** The severities' colours, those of the look in use: light or dark (SeverityColors). */
    private void showSeverityColors() {
        chips.forEach((s, chip) -> {
            chip.setIcon(new DotIcon(SeverityColors.of(s), 12));
            chip.setForeground(SeverityColors.of(s));
        });
        showSelected();
    }

    private void updateChips() {
        var counts = Finding.countBySeverity(findingsModel.rows());
        chips.forEach((s, chip) -> chip.setText(s.label() + "  " + counts.get(s)));
    }

    // --------------------------------------------------------------------------------- scanning
    private void chooseDatabase() {
        File start = !dbFiles.isEmpty() ? dbFiles.getFirst().toFile().getParentFile()
                : opts.dbDir != null && Files.isDirectory(opts.dbDir) ? opts.dbDir.toFile() : new File(System.getProperty("user.home"));
        var chooser = new JFileChooser(start);
        chooser.setDialogTitle(I18n.text("database.chooser.title"));
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("database.chooser.filter"), "zip"));
        var help = new JLabel(I18n.text("database.chooser.help"));
        help.setVerticalAlignment(SwingConstants.TOP);
        chooser.setAccessory(help);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            setDatabase(Arrays.stream(chooser.getSelectedFiles()).map(File::toPath).toList());
    }

    private void setDatabase(List<Path> files) {
        dbFiles.clear();
        dbFiles.addAll(files);
        settings.set(Settings.DATABASES, files.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        updateDatabaseField();
    }

    private void restoreDatabaseChoice() {
        String saved = settings.get(Settings.DATABASES, "");
        if (!saved.isBlank())
            Arrays.stream(saved.split(Pattern.quote(File.pathSeparator))).map(Path::of)
                    .filter(Files::isRegularFile).forEach(dbFiles::add);
    }

    private void updateDatabaseField() {
        boolean none = dbFiles.isEmpty();
        dbField.setText(none ? I18n.text("toolbar.database.none")
                : dbFiles.stream().map(Path::toString).collect(Collectors.joining("  ;  ")));
        dbField.setForeground(none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        dbField.setCaretPosition(0);
        clearDbButton.setEnabled(!none);
    }

    private void chooseFolder() {
        var chooser = new JFileChooser(dirField.getText());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle(I18n.text("folder.chooser.title"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) dirField.setText(chooser.getSelectedFile().getAbsolutePath());
    }

    private void startScan() {
        Path dir = Path.of(dirField.getText().strip());
        if (!Files.isDirectory(dir)) {
            JOptionPane.showMessageDialog(this, Gui.plain(I18n.text("scan.notAFolder", dir)), I18n.text("scan.notAFolder.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        setBusy(true);
        var databases = List.copyOf(dbFiles);
        Path ignoreFile = ignoreChoice;
        new SwingWorker<ScanResult, Void>() {
            @Override
            protected ScanResult doInBackground() throws Exception {
                return Engine.scan(dir, databases, ignoreFile, new ScanListener() {
                    public void status(String m) { SwingUtilities.invokeLater(() -> { if (busy) say(() -> m); }); }
                    public void progress(double f) { SwingUtilities.invokeLater(() -> { if (busy) updateProgress(f); }); }
                });
            }

            @Override
            protected void done() {
                setBusy(false);
                try {
                    showResult(get());
                } catch (ExecutionException e) {
                    say(() -> I18n.text("scan.failed"));
                    JOptionPane.showMessageDialog(MainWindow.this, Gui.plain(e.getCause().getMessage()), I18n.text("scan.failed.title"),
                            JOptionPane.ERROR_MESSAGE);
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

    private void showResult(ScanResult r) {
        result = r;
        ignores = r.ignores();
        findingsTable.clearSelection();
        ignoredTable.clearSelection();
        unresolvedModel.setRows(r.unresolved());
        refreshFindings();
        exportButton.setEnabled(true);
        int files = r.fileCounts().values().stream().mapToInt(Integer::intValue).sum();
        say(() -> {
            String scanned = I18n.text("scan.done", files, r.dependencies().size(), r.findings().size());
            if (!r.snapshots().isEmpty()) scanned += "  ·  " + I18n.text("scan.done.databases", String.join(", ", r.snapshots().keySet()));
            int warnings = r.warnings().size() + split.warnings().size();
            if (warnings > 0) scanned += "  ·  " + I18n.text("scan.done.warnings", warnings);
            return scanned;
        });
        updateStatusTip(r.warnings());
        if (files == 0)
            JOptionPane.showMessageDialog(this, I18n.text("scan.nothing"), I18n.text("scan.nothing.title"),
                    JOptionPane.INFORMATION_MESSAGE);
    }

    // ---------------------------------------------------------------------------------- details
    /** Whether a scan's findings are shown. */
    boolean scanned() {
        return result != null;
    }

    private Finding selectedFinding() {
        int row = findingsTable.getSelectedRow();
        return row < 0 ? null : findingsModel.row(findingsTable.convertRowIndexToModel(row));
    }

    private IgnoredFinding selectedIgnored() {
        int row = ignoredTable.getSelectedRow();
        return row < 0 ? null : ignoredModel.row(ignoredTable.convertRowIndexToModel(row));
    }

    /** The details of the finding selected in the findings' table; in the Ignored tab, of the one set aside there. */
    private void showSelected() {
        if (tabs.getSelectedIndex() != 3) {
            showDetails(selectedFinding());
            return;
        }
        var i = selectedIgnored();
        detailPane.setText(i == null ? FindingDetails.placeholder(result != null)
                : FindingDetails.page(i.finding(), environment, i.rule(), ignores.shown()));
        detailPane.setCaretPosition(0);
    }

    private void showDetails(Finding f) {
        detailPane.setText(f == null ? FindingDetails.placeholder(result != null) : FindingDetails.page(f, environment));
        detailPane.setCaretPosition(0);
    }

    // ------------------------------------------------------------------------------- ignore file
    /** The findings scored for the environment, then set apart by the ignore file: the tables, the chips, the counts. */
    private void refreshFindings() {
        if (result == null) return;
        split = ignores.split(Scoring.applyAll(result.findings(), environment, preferV4), LocalDate.now());
        findingsModel.setRows(split.active());
        ignoredModel.setRows(split.ignored());
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
        if (result != null) result.snapshots().forEach((k, v) -> tip.add("<b>" + Gui.html(k) + "</b>: " + Gui.html(v.text())));
        warnings.forEach(w -> tip.add(Gui.html(I18n.text("status.warning", w))));
        split.warnings().forEach(w -> tip.add(Gui.html(I18n.text("status.warning", w))));
        statusLabel.setToolTipText(tip.isEmpty() ? null : "<html>" + String.join("<br>", tip) + "</html>");
    }

    private void chooseIgnoreFile() {
        Path start = ignoreChoice != null && ignoreChoice.getParent() != null ? ignoreChoice.getParent() : Path.of(dirField.getText().strip());
        var chooser = new JFileChooser(start.toFile());
        chooser.setDialogTitle(I18n.text("ignore.chooser.title"));
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("ignore.chooser.filter"), "csv"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) setIgnoreChoice(chooser.getSelectedFile().toPath());
    }

    /** Reads this ignore file from now on: the findings shown are set apart again at once, without a new scan. */
    private void setIgnoreChoice(Path file) {
        ignoreChoice = file;
        updateIgnoreField();
        if (result == null) return;
        var warnings = new ArrayList<Phrase>();
        try {
            ignores = Ignores.load(result.root(), file, warnings::add);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, Gui.plain(e.getMessage()), I18n.text("ignore.failed.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        refreshFindings();
        updateStatusTipAfterReread(warnings);
        say(() -> I18n.text("ignore.applied", split.ignored().size()));
    }

    private void updateIgnoreField() {
        boolean own = ignoreChoice == null, none = Ignores.DISABLED.equals(ignoreChoice);
        ignoreField.setText(own ? I18n.text("toolbar.ignoreFile.own", IgnoreFile.NAME)
                : none ? I18n.text("toolbar.ignoreFile.disabled") : ignoreChoice.toString());
        ignoreField.setForeground(own || none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        ignoreField.setCaretPosition(0);
        ownIgnoreButton.setEnabled(!own);
    }

    /** Asks how to set this finding aside, writes the entry, sets the findings apart again; the next row is selected. */
    private void ignore(Finding f) {
        if (ignores.file() == null) {
            JOptionPane.showMessageDialog(this, I18n.text("ignore.disabled"), I18n.text("ignore.dialog.title"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        var rule = IgnoreDialog.ask(this, f, ignores.file().toString(),
                r -> (int) split.active().stream().filter(r::matches).count());
        if (rule.isEmpty()) return;
        int row = findingsTable.getSelectedRow();
        try {
            IgnoreFile.append(ignores.file(), rule.get());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, Gui.plain(e.getMessage()), I18n.text("ignore.failed.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        int before = split.ignored().size();
        rereadIgnores();
        int rows = findingsTable.getRowCount();
        if (rows > 0) {
            int next = Math.min(Math.max(row, 0), rows - 1);
            findingsTable.setRowSelectionInterval(next, next);
            findingsTable.scrollRectToVisible(findingsTable.getCellRect(next, 0, true));
        }
        int added = split.ignored().size() - before;
        say(() -> I18n.text("ignore.done", added, ignores.shown()));
    }

    /** Takes the entry setting this finding aside out of the file, after asking when it sets others aside too. */
    private void stopIgnoring(IgnoredFinding i) {
        long others = split.ignored().stream().filter(x -> x.rule().equals(i.rule())).count() - 1;
        if (others > 0 && JOptionPane.showConfirmDialog(this, Gui.plain(I18n.text("ignore.stop.others", others, i.rule().line())),
                I18n.text("ignore.stop.title"), JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION)
            return;
        boolean removed;
        try {
            removed = IgnoreFile.remove(ignores.file(), i.rule());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, Gui.plain(e.getMessage()), I18n.text("ignore.failed.title"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!removed)
            JOptionPane.showMessageDialog(this, Gui.plain(I18n.text("ignore.stop.notFound", ignores.shown())), I18n.text("ignore.stop.title"),
                    JOptionPane.WARNING_MESSAGE);
        rereadIgnores();
        if (removed) say(() -> I18n.text("ignore.stopped", others + 1));
    }

    /** The ignore file read again, once the window wrote it (or someone edited it), and the findings set apart again. */
    private void rereadIgnores() {
        var warnings = new ArrayList<Phrase>();
        try {
            ignores = ignores.reload(warnings::add);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, Gui.plain(e.getMessage()), I18n.text("ignore.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
        refreshFindings();
        updateStatusTipAfterReread(warnings);
    }

    // ----------------------------------------------------------------------------- export, misc
    private void export() {
        if (result == null) return;
        var chooser = new JFileChooser(opts.outDir.toAbsolutePath().toFile());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle(I18n.text("export.chooser.title", findingsTable.getRowCount()));
        chooser.setApproveButtonText(I18n.text("export.chooser.approve"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        var visible = IntStream.range(0, findingsTable.getRowCount())
                .mapToObj(i -> findingsModel.row(findingsTable.convertRowIndexToModel(i))).toList();
        boolean filtered = visible.size() != findingsModel.getRowCount();
        try {
            var written = Reports.writeAll(result, split.withActive(visible), chooser.getSelectedFile().toPath(),
                    filtered ? Phrase.of("export.filter", visible.size(), findingsModel.getRowCount()) : null,
                    environment, preferV4, I18n.language());
            // the folder is shown, to copy: the program starts no other one, a file manager no more than a browser
            String folder = chooser.getSelectedFile().getAbsolutePath();
            int choice = JOptionPane.showOptionDialog(this,
                    Gui.plain(I18n.text("export.done", written.stream().map(Path::toString).collect(Collectors.joining("\n")))),
                    I18n.text("export.done.title"), JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null,
                    new Object[]{I18n.text("export.copyFolder"), I18n.text("export.ok")}, I18n.text("export.ok"));
            if (choice == 0) {
                copy(folder);
                say(() -> I18n.text("export.folderCopied", folder));
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, Gui.plain(e.getMessage()), I18n.text("export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /** A link is copied, never opened: the program starts no browser (README, "No network"). */
    private void copyLink(String url) {
        if (url == null || url.isBlank()) return;
        copy(url);
        say(() -> I18n.text("link.copied", url));
    }

    /** Shows this on the status line, and again whenever the language changes. */
    private void say(Supplier<String> message) {
        statusMessage = message;
        statusLabel.setText(message.get());
    }

    private static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
}
