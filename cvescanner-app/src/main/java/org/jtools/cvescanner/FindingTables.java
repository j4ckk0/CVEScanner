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
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.FindingFilter;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.Unresolved;
import org.jtools.cvescanner.version.Versions;

/**
 * The window's three tables (the findings grouped by package version, the dependencies not checked, the findings set
 * aside) as they look: their columns, known by their key and titled in the language in use, their sorting, their
 * renderers, the filters they show through. What a click or a menu does with them is TableActions'.
 */
final class FindingTables {

    private static final List<Column<IgnoredFinding>> IGNORED_COLUMNS = List.of(
            new Column<IgnoredFinding>("column.severity", Severity.class, 175, i -> i.finding().severity()),
            new Column<IgnoredFinding>("column.env", Double.class, 140, i -> i.finding().envScore()),
            new Column<IgnoredFinding>("column.ecosystem", String.class, 100, i -> i.finding().ecosystem().id()),
            new Column<IgnoredFinding>("column.package", String.class, 300, i -> i.finding().pkg()),
            new Column<IgnoredFinding>("column.version", String.class, 95, i -> i.finding().displayVersion()),
            new Column<IgnoredFinding>("column.cve", String.class, 130, i -> i.finding().cveText()),
            new Column<IgnoredFinding>("column.advisory", String.class, 150, i -> i.finding().id()),
            new Column<IgnoredFinding>("column.until", String.class, 110, i -> i.rule().until() == null ? "—" : i.rule().until().toString()),
            new Column<IgnoredFinding>("column.reason", String.class, 330, i -> i.rule().reason()),
            new Column<IgnoredFinding>("column.ignoredBy", String.class, 160, i -> i.rule().fromVex() ? "VEX " + i.rule().source()
                    : I18n.text("column.ignoredBy.line", i.rule().line())),
            new Column<IgnoredFinding>("column.file", String.class, 220, i -> i.finding().file()));
    private static final List<Column<Unresolved>> UNRESOLVED_COLUMNS = List.of(
            new Column<Unresolved>("column.ecosystem", String.class, 75, u -> u.ecosystem().id()),
            new Column<Unresolved>("column.package", String.class, 300, Unresolved::name),
            new Column<Unresolved>("column.declared", String.class, 160, Unresolved::declared),
            new Column<Unresolved>("column.reason", String.class, 330, u -> u.reason().text()),
            new Column<Unresolved>("column.file", String.class, 300, Unresolved::file));

    /** A package version, as the findings' table groups and ticks it: its rows are rebuilt by the filters, its ticks stay. */
    record PackageKey(Ecosystem ecosystem, String pkg, String version) {
        static PackageKey of(PackageSummary p) {
            return new PackageKey(p.ecosystem(), p.pkg(), p.version());
        }

        static PackageKey of(Finding f) {
            return new PackageKey(f.ecosystem(), f.pkg(), f.version());
        }
    }

    /** The narrowest a column can be dragged to. */
    private static final int MIN_WIDTH = 40;

    private final I18nLabels labels;
    /** The package versions ticked for Apply fixes. */
    final Set<PackageKey> ticked = new LinkedHashSet<>();
    /** Told whenever a tick changes. */
    Runnable onTicked = () -> { };
    /** The findings of the scan, the ignore file's set aside: those the table shows from. */
    private List<Finding> all = List.of();
    final FindingGroups findingGroups = new FindingGroups(ticked, () -> onTicked.run());
    final ScrollingTable findingsTable = new ScrollingTable(findingGroups);
    final ListTableModel<Unresolved> unresolvedModel = new ListTableModel<>(UNRESOLVED_COLUMNS);
    final ListTableModel<IgnoredFinding> ignoredModel = new ListTableModel<>(IGNORED_COLUMNS);
    final JTable unresolvedTable = new ScrollingTable(unresolvedModel);
    final JTable ignoredTable = new ScrollingTable(ignoredModel);
    final TableRowSorter<ListTableModel<Unresolved>> unresolvedSorter = new TableRowSorter<>(unresolvedModel);
    final TableRowSorter<ListTableModel<IgnoredFinding>> ignoredSorter = new TableRowSorter<>(ignoredModel);
    /** The findings' ▾ in each header: the values to show, column by column; a click elsewhere on a header sorts. */
    final HeaderFilters headerFilters;
    /** Told whenever the values ticked in a header change. */
    Runnable onHeaderFilter = () -> { };

    FindingTables(I18nLabels labels) {
        this.labels = labels;
        Comparator<String> version = (a, b) -> Versions.compareMaven(a.replace(" ≈", "").replace("—", ""),
                b.replace(" ≈", "").replace("—", ""));
        setupFindings();
        setup(unresolvedTable, unresolvedSorter, UNRESOLVED_COLUMNS);
        setup(ignoredTable, ignoredSorter, IGNORED_COLUMNS);
        ignoredSorter.setComparator(column(IGNORED_COLUMNS, "column.version"), version);
        ignoredSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(IGNORED_COLUMNS, "column.env"), SortOrder.DESCENDING)));

        var cvss = new DefaultTableCellRenderer() {
            @Override
            protected void setValue(Object v) { setText(v instanceof Double d ? SwingText.score(d) : ""); }
        };
        cvss.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(FindingGroups.BASE).setCellRenderer(cvss);
        var envRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, focus, row, col);
                setText(v instanceof Double d ? SwingText.score(d) : "");
                setFont(getFont().deriveFont(Font.BOLD));
                if (!sel && v instanceof Double d) setForeground(SeverityColors.of(Severity.fromScore(d)));
                return this;
            }
        };
        envRenderer.setHorizontalAlignment(SwingConstants.RIGHT);
        findingsTable.getColumnModel().getColumn(FindingGroups.ENV).setCellRenderer(envRenderer);
        ignoredTable.getColumnModel().getColumn(column(IGNORED_COLUMNS, "column.env")).setCellRenderer(envRenderer);
        var expand = new DefaultTableCellRenderer();
        expand.setHorizontalAlignment(SwingConstants.CENTER);
        findingsTable.getColumnModel().getColumn(FindingGroups.EXPAND).setCellRenderer(expand);
        labels.tip(findingsTable.getTableHeader(), "column.header.tip");
        headerFilters = new HeaderFilters(findingsTable, c -> findingGroups.columns().get(c).filter(), () -> all, HeaderFilters::text,
                () -> onHeaderFilter.run(), new HeaderFilters.Sorting() {
                    public int column() { return findingGroups.sortColumn(); }
                    public boolean ascending() { return findingGroups.ascending(); }
                    public void sortBy(int column) { keepingSelection(() -> findingGroups.sortBy(column)); }
                });
    }

    /** The findings' table: a package version's row in bold, its ▸ opening its findings below it (a click, →, ←). */
    private void setupFindings() {
        var t = findingsTable;
        t.setRowHeight(30);
        t.setFillsViewportHeight(true);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        t.setDefaultRenderer(Severity.class, new SeverityRenderer());
        t.setDefaultRenderer(String.class, new TextRenderer());
        t.setDefaultRenderer(Boolean.class, new TickRenderer(t.getDefaultRenderer(Boolean.class)));
        t.strongRow(row -> findingGroups.row(row) instanceof FindingGroups.Group);
        t.getTableHeader().setReorderingAllowed(true);
        var columns = findingGroups.columns();
        for (int c = 0; c < columns.size(); c++) {
            var col = t.getColumnModel().getColumn(c);
            col.setPreferredWidth(columns.get(c).width());
            col.setMinWidth(c == FindingGroups.EXPAND ? 28 : MIN_WIDTH);
        }
        labels.on(() -> {
            for (int c = 0; c < t.getColumnCount(); c++) {
                var col = t.getColumnModel().getColumn(c);
                col.setHeaderValue(c == FindingGroups.EXPAND ? "" : I18n.text(columns.get(col.getModelIndex()).key()));
            }
            t.getTableHeader().repaint();
        });
        t.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1 && SwingUtilities.isLeftMouseButton(e)
                        && t.convertColumnIndexToModel(t.columnAtPoint(e.getPoint())) == FindingGroups.EXPAND) toggle(t.rowAtPoint(e.getPoint()), null);
            }
        });
        bind(KeyEvent.VK_RIGHT, "open", true);
        bind(KeyEvent.VK_LEFT, "close", false);
    }

    private void bind(int key, String name, boolean open) {
        findingsTable.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key, 0), name);
        findingsTable.getActionMap().put(name, new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                int row = findingsTable.getSelectedRow();
                if (row < 0) return;
                if (findingGroups.row(row) instanceof FindingGroups.Child c && !open) selectRow(findingGroups.rowOf(c.group().key()));
                else toggle(row, open);
            }
        });
    }

    /** The package version of this row opened or closed (null: the other way), its row then selected. */
    void toggle(int row, Boolean open) {
        if (row < 0 || !(findingGroups.row(row) instanceof FindingGroups.Group g)) return;
        findingGroups.toggle(g, open == null ? !findingGroups.expanded(g) : open);
        selectRow(findingGroups.rowOf(g.key()));
    }

    /** Whether the row selected is a package version's: a double-click on it opens or closes it rather than copying a link. */
    boolean packageSelected() {
        int row = findingsTable.getSelectedRow();
        return row >= 0 && findingGroups.row(row) instanceof FindingGroups.Group;
    }

    /** Whether this column of the findings' table is the ticks', wherever it was dragged. */
    boolean isTickColumn(int viewColumn) {
        return viewColumn >= 0 && findingsTable.convertColumnIndexToModel(viewColumn) == FindingGroups.FIX;
    }

    /**
     * The folder of the file a finding comes from, as the scan names it ("maven-webapp/service"); for a jar inside a
     * jar, the outer one's ("opt/shop/lib"); "." for the folder scanned itself.
     */
    static String folderOf(String file) {
        int nested = file.indexOf("!/");
        String outer = nested < 0 ? file : file.substring(0, nested);
        int slash = Math.max(outer.lastIndexOf('/'), outer.lastIndexOf('\\'));
        return slash < 0 ? "." : outer.substring(0, slash);
    }

    static <T> int column(List<Column<T>> columns, String key) {
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
            col.setMinWidth(MIN_WIDTH);   // any column narrowed by hand, down to its first letters
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

    /**
     * A package version the Apply fixes button can act on: a Maven or npm package a project declares, with a version
     * that fixes it; not a component off-the-shelf, a Python package, nor what an installed product ships.
     */
    static boolean fixable(PackageSummary p) {
        return (p.ecosystem() == Ecosystem.MAVEN || p.ecosystem() == Ecosystem.NPM) && !p.installed() && !p.fixedIn().isEmpty();
    }

    /** A tick where it can be set, nothing where it cannot (a package not fixable, a finding's row). */
    private static final class TickRenderer implements TableCellRenderer {
        private final TableCellRenderer box;
        private final JLabel none = new JLabel();

        TickRenderer(TableCellRenderer box) {
            this.box = box;
            none.setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
            if (v != null) return box.getTableCellRendererComponent(t, v, sel, focus, row, col);
            none.setBackground(sel ? t.getSelectionBackground() : t.getBackground());
            return none;
        }
    }

    /** The findings of a scan the table shows from, the ignore file's set aside; the packages opened that it still has stay so. */
    void setFindings(List<Finding> findings) {
        all = List.copyOf(findings);
        findingGroups.retainOpened(findings.stream().map(PackageKey::of).collect(Collectors.toSet()));
    }

    List<Finding> allFindings() {
        return all;
    }

    /** The findings the filters, the headers' ▾ and the search let through, package by package: opened or not. */
    List<Finding> shownFindings() {
        return findingGroups.findings();
    }

    /** How many package versions the filters let through. */
    int shownPackages() {
        return findingGroups.packages();
    }

    /** Selects this finding's row, its package opened for it, scrolled to; false when it is not let through. */
    boolean select(Finding f) {
        int row = findingGroups.rowOf(f);
        if (row >= 0) selectRow(row);
        return row >= 0;
    }

    /** The row selected in the findings' table, -1 for none. */
    int selectedRow() {
        return findingsTable.getSelectedRow();
    }

    /** Selects the row at this place, the last when there are fewer; none when the table is empty. */
    void selectRow(int row) {
        int rows = findingsTable.getRowCount();
        if (rows == 0 || row < 0) return;
        int r = Math.min(row, rows - 1);
        findingsTable.setRowSelectionInterval(r, r);
        findingsTable.scrollRectToVisible(findingsTable.getCellRect(r, 0, true));
    }

    /** The finding of the row selected; for a package version's row, its most severe finding. */
    Finding selectedFinding() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return null;
        return switch (findingGroups.row(row)) {
            case FindingGroups.Child c -> c.finding();
            case FindingGroups.Group g -> g.worst();
        };
    }

    /** The package version of the row selected, or of its finding. */
    PackageSummary selectedPackage() {
        int row = findingsTable.getSelectedRow();
        if (row < 0) return null;
        return switch (findingGroups.row(row)) {
            case FindingGroups.Child c -> c.group().summary();
            case FindingGroups.Group g -> g.summary();
        };
    }

    /** The filters last applied: the export leaves out what they leave out. */
    FindingFilter facets() {
        return facets;
    }

    private FindingFilter facets = FindingFilter.NONE;

    /** Something done to the findings' rows, the row selected before selected again: the same finding or package version. */
    private void keepingSelection(Runnable change) {
        int row = findingsTable.getSelectedRow();
        FindingGroups.Row before = row < 0 ? null : findingGroups.row(row);
        change.run();
        switch (before) {
            case FindingGroups.Child c -> {
                int r = rowOfShown(c.finding());
                selectRow(r >= 0 ? r : findingGroups.rowOf(c.group().key()));   // its package closed: the package's row
            }
            case FindingGroups.Group g -> selectRow(findingGroups.rowOf(g.key()));
            case null, default -> { }
        }
    }

    /** The row of this finding if it is shown, its package left closed or open as it is; -1 otherwise. */
    private int rowOfShown(Finding f) {
        for (int i = 0; i < findingGroups.getRowCount(); i++)
            if (findingGroups.row(i) instanceof FindingGroups.Child c && FindingGroups.same(c.finding(), f)) return i;
        return -1;
    }

    /**
     * The filters applied to every table: the findings by the facets, the values ticked in their headers and the search,
     * then grouped by package version (every one opened while searching); the others by the ecosystem and the search.
     */
    void filter(FindingFilter facets, List<String> terms, Ecosystem ecosystem) {
        this.facets = facets;
        var shown = all.stream().filter(f -> facets.test(f) && headerFilters.test(f) && matchesSearch(f, terms)).toList();
        keepingSelection(() -> findingGroups.show(shown, !terms.isEmpty()));
        unresolvedSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<Unresolved>, ? extends Integer> e) {
                var u = e.getModel().row(e.getIdentifier());
                return (ecosystem == null || u.ecosystem() == ecosystem) && matchesSearch(e, terms, "");
            }
        });
        ignoredSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<IgnoredFinding>, ? extends Integer> e) {
                var i = e.getModel().row(e.getIdentifier());
                return (ecosystem == null || i.finding().ecosystem() == ecosystem) && matchesSearch(e, terms, i.rule().reason());
            }
        });
    }

    /** Every word searched is in one of the finding's columns, its package's, or its aliases. */
    private boolean matchesSearch(Finding f, List<String> terms) {
        if (terms.isEmpty()) return true;
        var sb = new StringBuilder(String.join(" ", f.aliases()));
        for (var c : findingGroups.columns()) {
            Object v = c.filter() != null ? c.filter().apply(f) : null;
            if (v != null) sb.append('\u0001').append(HeaderFilters.text(v));
        }
        String hay = sb.toString().toLowerCase(Locale.ROOT);
        return terms.stream().allMatch(hay::contains);
    }

    /** Every word searched is in a column of the row, or in the extra text given (aliases, the reason set aside). */
    private static <M extends ListTableModel<?>> boolean matchesSearch(RowFilter.Entry<? extends M, ? extends Integer> e,
                                                                       List<String> terms, String extra) {
        if (terms.isEmpty()) return true;
        var sb = new StringBuilder(extra);
        for (int c = 0; c < e.getValueCount(); c++) sb.append('\u0001').append(e.getStringValue(c));
        String hay = sb.toString().toLowerCase(Locale.ROOT);
        return terms.stream().allMatch(hay::contains);
    }

    IgnoredFinding selectedIgnored() {
        int row = ignoredTable.getSelectedRow();
        return row < 0 ? null : ignoredModel.row(ignoredTable.convertRowIndexToModel(row));
    }
}
