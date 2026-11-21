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


import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.jtools.cvescanner.i18n.I18n;

final class ListTableModel<T> extends AbstractTableModel {
    private final List<Column<T>> columns;
    private List<T> rows = List.of();

    ListTableModel(List<Column<T>> columns) { this.columns = columns; }

    void setRows(List<T> rows) {
        this.rows = List.copyOf(rows);
        fireTableDataChanged();
    }

    T row(int modelIndex) { return rows.get(modelIndex); }

    List<T> rows() { return rows; }

    List<Column<T>> columns() { return columns; }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return columns.size(); }
    @Override public String getColumnName(int c) { return I18n.text(columns.get(c).key()); }
    @Override public Class<?> getColumnClass(int c) { return columns.get(c).type(); }
    @Override public Object getValueAt(int r, int c) { return columns.get(c).value().apply(rows.get(r)); }
}
