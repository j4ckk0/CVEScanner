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
import java.util.List;
import java.util.Objects;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.Unresolved;
import org.jtools.cvescanner.version.Versions;

/**
 * The window's four tables (the findings, the packages to upgrade, the dependencies not checked, the findings set aside)
 * as they look: their columns, known by their key and titled in the language in use, their sorting, their renderers.
 * What a click or a menu does with them is the window's.
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
    private static final List<Column<PackageSummary>> PACKAGE_COLUMNS = List.of(
            new Column<PackageSummary>("column.worst", Severity.class, 110, PackageSummary::worst),
            new Column<PackageSummary>("column.ecosystem", String.class, 75, p -> p.ecosystem().id()),
            new Column<PackageSummary>("column.package", String.class, 300, PackageSummary::pkg),
            new Column<PackageSummary>("column.current", String.class, 100, PackageSummary::displayVersion),
            new Column<PackageSummary>("column.upgradeTo", String.class, 160, p -> p.upgradeTo()),
            new Column<PackageSummary>("column.vulnerabilities", Integer.class, 95, PackageSummary::vulnerabilities),
            new Column<PackageSummary>("column.advisories", String.class, 260, PackageSummary::advisories),
            new Column<PackageSummary>("column.foundIn", String.class, 330, PackageSummary::files));
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
            new Column<IgnoredFinding>("column.file", String.class, 220, i -> i.finding().file()));
    private static final List<Column<Unresolved>> UNRESOLVED_COLUMNS = List.of(
            new Column<Unresolved>("column.ecosystem", String.class, 75, u -> u.ecosystem().id()),
            new Column<Unresolved>("column.package", String.class, 300, Unresolved::name),
            new Column<Unresolved>("column.declared", String.class, 160, Unresolved::declared),
            new Column<Unresolved>("column.reason", String.class, 330, u -> u.reason().text()),
            new Column<Unresolved>("column.file", String.class, 300, Unresolved::file));

    private final I18nLabels labels;
    final ListTableModel<Finding> findingsModel = new ListTableModel<>(FINDING_COLUMNS);
    final ListTableModel<PackageSummary> packagesModel = new ListTableModel<>(PACKAGE_COLUMNS);
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

    Finding selectedFinding() {
        int row = findingsTable.getSelectedRow();
        return row < 0 ? null : findingsModel.row(findingsTable.convertRowIndexToModel(row));
    }

    IgnoredFinding selectedIgnored() {
        int row = ignoredTable.getSelectedRow();
        return row < 0 ? null : ignoredModel.row(ignoredTable.convertRowIndexToModel(row));
    }
}
