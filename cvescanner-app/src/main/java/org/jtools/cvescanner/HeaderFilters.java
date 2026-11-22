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
import java.util.function.Function;
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
import javax.swing.table.TableRowSorter;
import org.jtools.cvescanner.i18n.I18n;

/**
 * A ▾ at the right of each header of a table: a click on it lists the column's values, each to tick, as a spreadsheet
 * filters; a row is shown when each filtered column's value is one ticked. The ▾ of a filtered column is drawn in the
 * accent colour. A click elsewhere on the header still sorts.
 */
final class HeaderFilters<T> {

    /** The width of the ▾ zone at a header's right, the last pixels left to resizing the column. */
    private static final int ZONE = 20, RESIZE = 4;

    private final JTable table;
    private final ListTableModel<T> model;
    private final Function<Object, String> text;
    private final Runnable changed;
    /** Each filtered column's values shown, by its model index; a column not in it is not filtered. */
    private final Map<Integer, Set<String>> shown = new HashMap<>();
    /** Set when a press opens the list: the click it ends in does not sort. */
    private boolean pressedOnArrow;
    /** The look's own header renderer, which the ▾ is put beside, and the look it is of: made anew in another look. */
    private TableCellRenderer plain;
    private Object plainLook;
    /** The look's header border, taken from its renderer, which sets it on each cell or once. */
    private Border border;

    /**
     * @param text    a cell's value as the list names it
     * @param changed run when the values ticked change
     */
    HeaderFilters(JTable table, ListTableModel<T> model, Function<Object, String> text, Runnable changed) {
        this.table = table;
        this.model = model;
        this.text = text;
        this.changed = changed;
        var header = table.getTableHeader();
        header.setDefaultRenderer((t, value, selected, focus, row, column) -> {
            Component c = plain().getTableCellRendererComponent(t, value, selected, focus, row, column);
            var arrow = new JLabel(shown.containsKey(t.convertColumnIndexToModel(column)) ? "▼" : "▾");
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
                pressedOnArrow = r != null && e.getX() >= r.x + r.width - ZONE && e.getX() < r.x + r.width - RESIZE;
                if (pressedOnArrow) list(column, r);
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

    /** Whether the press that ends in this click opened a list: then the click does not sort (FilteringSorter). */
    boolean pressedOnArrow() {
        boolean was = pressedOnArrow;
        pressedOnArrow = false;
        return was;
    }

    /** Whether a row shows: each filtered column's value is one ticked. */
    boolean test(int modelRow) {
        for (var e : shown.entrySet())
            if (!e.getValue().contains(text.apply(model.getValueAt(modelRow, e.getKey())))) return false;
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
        var values = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        for (int r = 0; r < model.getRowCount(); r++) values.add(text.apply(model.getValueAt(r, column)));
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

    /** A sorter that does not sort on the click that opened a header's list. */
    static final class FilteringSorter<M extends ListTableModel<?>> extends TableRowSorter<M> {
        private HeaderFilters<?> filters;

        FilteringSorter(M model) {
            super(model);
        }

        void filters(HeaderFilters<?> filters) {
            this.filters = filters;
        }

        @Override
        public void toggleSortOrder(int column) {
            if (filters != null && filters.pressedOnArrow()) return;
            super.toggleSortOrder(column);
        }
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
