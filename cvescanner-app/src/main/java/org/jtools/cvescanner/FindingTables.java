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
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
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
 * The window's four tables (the findings, the packages to upgrade, the dependencies not checked, the findings set aside)
 * as they look: their columns, known by their key and titled in the language in use, their sorting, their renderers,
 * the filters they show through. What a click or a menu does with them is TableActions'.
 */
final class FindingTables {

    private static final List<Column<Finding>> FINDING_COLUMNS = List.of(
            new Column<Finding>("column.severity", Severity.class, 175, Finding::severity),
            new Column<Finding>("column.base", Double.class, 95, Finding::cvss),
            new Column<Finding>("column.env", Double.class, 140, Finding::envScore),
            new Column<Finding>("column.cvss", String.class, 95, f -> Objects.requireNonNullElse(f.score().version(), "")),
            new Column<Finding>("column.ecosystem", String.class, 100, f -> f.ecosystem().id()),
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

    /** A package version, as the Packages tab ticks it: its rows are rebuilt by the filters, its ticks stay. */
    record PackageKey(Ecosystem ecosystem, String pkg, String version) {
        static PackageKey of(PackageSummary p) {
            return new PackageKey(p.ecosystem(), p.pkg(), p.version());
        }
    }

    private final I18nLabels labels;
    /** The package versions ticked for Apply fixes. */
    final Set<PackageKey> ticked = new LinkedHashSet<>();
    /** Told whenever a tick changes. */
    Runnable onTicked = () -> { };
    private final List<Column<PackageSummary>> packageColumns = List.of(
            new Column<PackageSummary>("column.apply", Boolean.class, 70, p -> fixable(p) ? ticked.contains(PackageKey.of(p)) : null,
                    FindingTables::fixable, (p, v) -> tick(p, Boolean.TRUE.equals(v))),
            new Column<PackageSummary>("column.worst", Severity.class, 110, PackageSummary::worst),
            new Column<PackageSummary>("column.ecosystem", String.class, 75, p -> p.ecosystem().id()),
            new Column<PackageSummary>("column.package", String.class, 300, PackageSummary::pkg),
            new Column<PackageSummary>("column.current", String.class, 100, PackageSummary::displayVersion),
            new Column<PackageSummary>("column.upgradeTo", String.class, 160, p -> p.upgradeTo()),
            new Column<PackageSummary>("column.vulnerabilities", Integer.class, 95, PackageSummary::vulnerabilities),
            new Column<PackageSummary>("column.advisories", String.class, 260, PackageSummary::advisories),
            new Column<PackageSummary>("column.foundIn", String.class, 330, PackageSummary::files));
    final ListTableModel<Finding> findingsModel = new ListTableModel<>(FINDING_COLUMNS);
    final ListTableModel<PackageSummary> packagesModel = new ListTableModel<>(packageColumns);
    final ListTableModel<Unresolved> unresolvedModel = new ListTableModel<>(UNRESOLVED_COLUMNS);
    final ListTableModel<IgnoredFinding> ignoredModel = new ListTableModel<>(IGNORED_COLUMNS);
    final JTable findingsTable = new ScrollingTable(findingsModel);
    final JTable packagesTable = new ScrollingTable(packagesModel);
    final JTable unresolvedTable = new ScrollingTable(unresolvedModel);
    final JTable ignoredTable = new ScrollingTable(ignoredModel);
    final TableRowSorter<ListTableModel<Finding>> findingsSorter = new TableRowSorter<>(findingsModel);
    final TableRowSorter<ListTableModel<PackageSummary>> packagesSorter = new TableRowSorter<>(packagesModel);
    final TableRowSorter<ListTableModel<Unresolved>> unresolvedSorter = new TableRowSorter<>(unresolvedModel);
    final TableRowSorter<ListTableModel<IgnoredFinding>> ignoredSorter = new TableRowSorter<>(ignoredModel);

    FindingTables(I18nLabels labels) {
        this.labels = labels;
        Comparator<String> version = (a, b) -> Versions.compareMaven(a.replace(" ≈", "").replace("—", ""),
                b.replace(" ≈", "").replace("—", ""));
        setup(findingsTable, findingsSorter, FINDING_COLUMNS);
        findingsSorter.setComparator(column(FINDING_COLUMNS, "column.version"), version);
        findingsSorter.setComparator(column(FINDING_COLUMNS, "column.fixedIn"), version);
        findingsSorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "column.env"), SortOrder.DESCENDING),
                new RowSorter.SortKey(column(FINDING_COLUMNS, "column.base"), SortOrder.DESCENDING)));
        setup(packagesTable, packagesSorter, packageColumns);
        packagesSorter.setComparator(column(packageColumns, "column.current"), version);
        packagesSorter.setSortKeys(List.of(new RowSorter.SortKey(column(packageColumns, "column.worst"), SortOrder.DESCENDING),
                new RowSorter.SortKey(column(packageColumns, "column.vulnerabilities"), SortOrder.DESCENDING)));
        packagesTable.setDefaultRenderer(Boolean.class, new TickRenderer(packagesTable.getDefaultRenderer(Boolean.class)));
        labels.tip(packagesTable.getTableHeader(), "column.apply.tip");
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
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "column.base")).setCellRenderer(cvss);
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
        findingsTable.getColumnModel().getColumn(column(FINDING_COLUMNS, "column.env")).setCellRenderer(envRenderer);
        ignoredTable.getColumnModel().getColumn(column(IGNORED_COLUMNS, "column.env")).setCellRenderer(envRenderer);
        labels.tip(findingsTable.getTableHeader(), "column.header.tip");
        labels.tip(packagesTable, "packages.tip");
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

    /**
     * A package version the Apply fixes button can act on: a Maven or npm package a project declares, with a version
     * that fixes it; not a component off-the-shelf, a Python package, nor what an installed product ships.
     */
    static boolean fixable(PackageSummary p) {
        return (p.ecosystem() == Ecosystem.MAVEN || p.ecosystem() == Ecosystem.NPM) && !p.installed() && !p.fixedIn().isEmpty();
    }

    private void tick(PackageSummary p, boolean on) {
        if (on) ticked.add(PackageKey.of(p));
        else ticked.remove(PackageKey.of(p));
        onTicked.run();
    }

    /** Whether this column of the packages' table is the ticks' one, wherever it was dragged. */
    boolean isTickColumn(int viewColumn) {
        return viewColumn >= 0 && packagesTable.convertColumnIndexToModel(viewColumn) == column(packageColumns, "column.apply");
    }

    /** A tick where it can be set, nothing where it cannot (a COTS component, a package without a fix). */
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

    Finding selectedFinding() {
        int row = findingsTable.getSelectedRow();
        return row < 0 ? null : findingsModel.row(findingsTable.convertRowIndexToModel(row));
    }

    PackageSummary selectedPackage() {
        int row = packagesTable.getSelectedRow();
        return row < 0 ? null : packagesModel.row(packagesTable.convertRowIndexToModel(row));
    }

    /**
     * The filters applied to every table: the findings by the facets and the search; the package view rebuilt from the
     * findings that pass the facets, then searched; the others by the ecosystem and the search.
     */
    void filter(FindingFilter facets, List<String> terms, Ecosystem ecosystem) {
        findingsSorter.setRowFilter(new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends ListTableModel<Finding>, ? extends Integer> e) {
                var f = e.getModel().row(e.getIdentifier());
                return facets.test(f) && matchesSearch(e, terms, String.join(" ", f.aliases()));
            }
        });
        packagesModel.setRows(PackageSummary.of(findingsModel.rows().stream().filter(facets::test).toList()));
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
