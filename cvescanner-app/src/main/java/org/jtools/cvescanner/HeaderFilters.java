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
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.List;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JComponent;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Finding;

/**
 * A ▾ at the right of each header of the findings' table: a click on it lists the column's values, each to tick, as a
 * spreadsheet filters; a finding is shown when each filtered column's value of it is one ticked. The ▾ of a filtered
 * column is drawn in the accent colour. A click elsewhere on a header sorts by its column (Sorting), the arrow of the
 * look drawn beside its title.
 */
final class HeaderFilters {

    /** The table's own order, which a header click changes: the table sorts itself, without a RowSorter. */
    interface Sorting {
        int column();

        boolean ascending();

        void sortBy(int column);
    }

    /** The width of the ▾ zone at a header's right, the last pixels left to resizing the column. */
    private static final int ZONE = 20, RESIZE = 4;

    private final JTable table;
    /** Each model column's value of a finding, which its list names and filters by; null for a column not filtered. */
    private final IntFunction<Function<Finding, ?>> value;
    /** Every finding the table can show, whose values the lists offer. */
    private final Supplier<List<Finding>> all;
    private final Function<Object, String> text;
    private final Runnable changed;
    private final Sorting sorting;
    /** Each filtered column's values shown, by its model index; a column not in it is not filtered. */
    private final Map<Integer, Set<String>> shown = new HashMap<>();
    /** Set when a press opens a list or grabs a column's edge: the click it ends in does not sort. */
    private boolean pressedOnArrow;
    /** The look's own header renderer, which the ▾ is put beside, and the look it is of: made anew in another look. */
    private TableCellRenderer plain;
    private Object plainLook;
    /** The look's header border, taken from its renderer, which sets it on each cell or once. */
    private Border border;

    /**
     * @param value   a model column's value of a finding; null for a column without a list
     * @param all     every finding the table can show
     * @param text    a value as the list names it
     * @param changed run when the values ticked change
     * @param sorting the table's order, which a click on a header changes
     */
    HeaderFilters(JTable table, IntFunction<Function<Finding, ?>> value, Supplier<List<Finding>> all, Function<Object, String> text,
                  Runnable changed, Sorting sorting) {
        this.table = table;
        this.value = value;
        this.all = all;
        this.text = text;
        this.changed = changed;
        this.sorting = sorting;
        var header = table.getTableHeader();
        header.setDefaultRenderer((t, heading, selected, focus, row, column) -> {
            Component c = plain().getTableCellRendererComponent(t, heading, selected, focus, row, column);
            int model = t.convertColumnIndexToModel(column);
            if (c instanceof JLabel title) {   // the column sorted by: the look's arrow beside its title
                title.setIcon(model == sorting.column()
                        ? UIManager.getIcon(sorting.ascending() ? "Table.ascendingSortIcon" : "Table.descendingSortIcon") : null);
                title.setHorizontalTextPosition(JLabel.LEADING);
            }
            var arrow = new JLabel(value.apply(model) == null ? "" : shown.containsKey(model) ? "▼" : "▾");
            arrow.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, RESIZE));
            if (shown.containsKey(t.convertColumnIndexToModel(column))) {
                arrow.setForeground(UIManager.getColor("Component.accentColor"));
                c.setFont(c.getFont().deriveFont(Font.BOLD));
            } else {
                arrow.setForeground(UIManager.getColor("Label.disabledForeground"));
            }
            var cell = new JPanel(new BorderLayout());
            cell.setOpaque(false);
            // the look's border (its padding, the line between two headers) around the title and its ▾ both: on the
            // title alone, the line would fall between them, the ▾ seeming the next column's
            if (c instanceof JComponent title) {
                if (title.getBorder() != null) border = title.getBorder();
                title.setBorder(null);
                cell.setBorder(border);
            }
            cell.add(c, BorderLayout.CENTER);
            cell.add(arrow, BorderLayout.EAST);
            return cell;
        });
        header.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int column = header.columnAtPoint(e.getPoint());
                Rectangle r = column < 0 ? null : header.getHeaderRect(column);
                boolean onArrow = r != null && value.apply(table.convertColumnIndexToModel(column)) != null
                        && e.getX() >= r.x + r.width - ZONE && e.getX() < r.x + r.width - RESIZE;
                boolean onEdge = r != null && (e.getX() < r.x + RESIZE || e.getX() >= r.x + r.width - RESIZE);
                pressedOnArrow = onArrow || onEdge;
                if (onArrow) list(column, r);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                int column = header.columnAtPoint(e.getPoint());
                if (column < 0 || pressedOnArrow || e.getClickCount() != 1 || !javax.swing.SwingUtilities.isLeftMouseButton(e)) return;
                sorting.sortBy(table.convertColumnIndexToModel(column));
                header.repaint();
            }
        });
    }

    private TableCellRenderer plain() {
        if (plain == null || plainLook != UIManager.getLookAndFeel()) {
            plainLook = UIManager.getLookAndFeel();
            plain = new JTableHeader().getDefaultRenderer();
            border = null;
        }
        return plain;
    }

    /** Whether a finding shows: each filtered column's value of it is one ticked. */
    boolean test(Finding f) {
        for (var e : shown.entrySet())
            if (!e.getValue().contains(text.apply(value.apply(e.getKey()).apply(f)))) return false;
        return true;
    }

    boolean active() {
        return !shown.isEmpty();
    }

    /** Every column shown whole again (Clear filters). */
    void clear() {
        if (shown.isEmpty()) return;
        shown.clear();
        table.getTableHeader().repaint();
    }

    /** The list of a column's values, below its header: All, then each value, ticked when shown. */
    private void list(int viewColumn, Rectangle header) {
        int column = table.convertColumnIndexToModel(viewColumn);
        Function<Finding, ?> of = value.apply(column);
        if (of == null) return;
        var values = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (Finding f : all.get()) values.add(text.apply(of.apply(f)));
        Set<String> current = shown.getOrDefault(column, values);
        var boxes = new JPanel();
        boxes.setLayout(new BoxLayout(boxes, BoxLayout.Y_AXIS));
        var all = new JCheckBox(I18n.text("headerFilter.all"), current.containsAll(values));
        all.setFont(all.getFont().deriveFont(Font.BOLD));
        boxes.add(all);
        var each = new java.util.ArrayList<JCheckBox>();
        for (String v : values) {
            var box = new JCheckBox(v.isEmpty() ? I18n.text("headerFilter.empty") : v, current.contains(v));
            box.putClientProperty("value", v);
            each.add(box);
            boxes.add(box);
        }
        Runnable apply = () -> {
            var ticked = new LinkedHashSet<String>();
            for (var b : each) if (b.isSelected()) ticked.add((String) b.getClientProperty("value"));
            if (ticked.size() == values.size()) shown.remove(column);
            else shown.put(column, ticked);
            all.setSelected(ticked.size() == values.size());
            table.getTableHeader().repaint();
            changed.run();
        };
        all.addActionListener(_ -> {
            each.forEach(b -> b.setSelected(all.isSelected()));
            apply.run();
        });
        each.forEach(b -> b.addActionListener(_ -> apply.run()));
        var scroll = new JScrollPane(boxes);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        int height = Math.min(boxes.getPreferredSize().height + 4, 320);
        scroll.setPreferredSize(new Dimension(Math.max(header.width, Math.min(boxes.getPreferredSize().width + 24, 420)), height));
        var close = new JButton(I18n.text("headerFilter.close"));
        var panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        panel.add(scroll, BorderLayout.CENTER);
        panel.add(close, BorderLayout.SOUTH);
        var popup = new JPopupMenu();
        popup.setName("headerFilter");   // for the window test (WindowDriver)
        popup.add(panel);
        close.addActionListener(_ -> popup.setVisible(false));
        popup.show(table.getTableHeader(), header.x, header.y + header.height);
    }

    /** The texts a list shows for a column's values: a severity by its label, a score as the language writes it. */
    static String text(Object value) {
        return switch (value) {
            case null -> "";
            case org.jtools.cvescanner.cvss.Severity s -> s.label();
            case Double d -> SwingText.score(d);
            default -> value.toString();
        };
    }
}
