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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.model.Finding;

/**
 * What a click, a double-click, a right-click does in the tables: a selection shows its details, a double-click on a
 * finding copies its link, on a package searches its findings; the right-click menus copy, ignore, stop ignoring.
 */
final class TableActions {

    /** What the tables' actions need of the window. */
    interface Host {
        void showSelected();

        void copyLink(String url);

        /** The findings' tab shown, searched for this text. */
        void showFindingsOf(String text);

        /** The findings' search set to this text, the tab left as it is. */
        void search(String text);

        void ignore(Finding f);

        void stopIgnoring(IgnoredFinding i);
    }

    private final FindingTables tables;
    private final I18nLabels labels;
    private final Host host;

    private TableActions(FindingTables tables, I18nLabels labels, Host host) {
        this.tables = tables;
        this.labels = labels;
        this.host = host;
    }

    static void wire(FindingTables tables, I18nLabels labels, Host host) {
        new TableActions(tables, labels, host).wire();
    }

    private void wire() {
        for (JTable t : new JTable[]{tables.findingsTable, tables.packagesTable, tables.ignoredTable})
            t.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) host.showSelected();
            });
        selectOnRightClick(tables.findingsTable);
        tables.findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                var f = tables.selectedFinding();
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && f != null) host.copyLink(f.url());
            }
        });
        tables.findingsTable.setComponentPopupMenu(findingsMenu());

        selectOnRightClick(tables.ignoredTable);
        tables.ignoredTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                var i = tables.selectedIgnored();
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e) && i != null) host.copyLink(i.finding().url());
            }
        });
        tables.ignoredTable.setComponentPopupMenu(ignoredMenu());

        tables.packagesTable.addMouseListener(new MouseAdapter() {     // double-click a package: show its findings
            @Override
            public void mouseClicked(MouseEvent e) {
                if (tables.isTickColumn(tables.packagesTable.columnAtPoint(e.getPoint()))) return;   // a tick, not a look
                var p = tables.selectedPackage();
                if (e.getClickCount() == 2 && p != null) host.showFindingsOf(p.pkg());
            }
        });
    }

    /** A right-click selects the row it is on, so that its menu acts on that row. */
    private static void selectOnRightClick(JTable table) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (SwingUtilities.isRightMouseButton(e) && row >= 0) table.setRowSelectionInterval(row, row);
            }
        });
    }

    private JPopupMenu findingsMenu() {
        var menu = new JPopupMenu();
        menu.add(findingItem("menu.finding.copyAdvisoryLink", f -> host.copyLink(f.url())));
        menu.add(findingItem("menu.finding.copyNvdLink", f -> host.copyLink(f.cves().stream().map(FindingDetails::nvdUrl).collect(Collectors.joining(" ")))));
        menu.addSeparator();
        menu.add(findingItem("menu.finding.copyCves", f -> Clipboard.copy(f.cves().isEmpty() ? f.id() : f.cveText())));
        menu.add(findingItem("menu.finding.copyCoordinate", f -> Clipboard.copy(f.ecosystem().coordinate(f.pkg(), f.version()))));
        menu.add(findingItem("menu.finding.copyRow", f -> Clipboard.copy(String.join("\t", f.severity().name(), f.pkg(), f.version(), f.id(),
                f.cveText(), f.fixedIn(), f.file(), f.summary()))));
        menu.addSeparator();
        menu.add(findingItem("menu.finding.onlyThisPackage", f -> host.search(f.pkg())));
        menu.addSeparator();
        menu.add(findingItem("menu.finding.ignore", host::ignore));
        return menu;
    }

    private JPopupMenu ignoredMenu() {
        var menu = new JPopupMenu();
        var stop = labels.text(new JMenuItem(), "menu.ignored.stop");
        stop.addActionListener(_ -> {
            var i = tables.selectedIgnored();
            if (i != null) host.stopIgnoring(i);
        });
        menu.add(stop);
        menu.addSeparator();
        var link = labels.text(new JMenuItem(), "menu.finding.copyAdvisoryLink");
        link.addActionListener(_ -> {
            var i = tables.selectedIgnored();
            if (i != null) host.copyLink(i.finding().url());
        });
        menu.add(link);
        return menu;
    }

    private JMenuItem findingItem(String key, Consumer<Finding> action) {
        var item = labels.text(new JMenuItem(), key);
        item.addActionListener(_ -> {
            var f = tables.selectedFinding();
            if (f != null) action.accept(f);
        });
        return item;
    }
}
