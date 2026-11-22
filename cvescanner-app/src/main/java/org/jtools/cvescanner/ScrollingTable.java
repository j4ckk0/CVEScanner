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
import java.util.function.IntPredicate;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;

/**
 * A table that fills the width it is given when its columns fit in it, and otherwise keeps their widths and scrolls
 * sideways: a plain JTable squeezes every column into the window, cutting each text short.
 */
final class ScrollingTable extends JTable {

    /** The rows drawn in bold: a package version's among its findings. */
    private IntPredicate strong = _ -> false;

    ScrollingTable(TableModel model) {
        super(model);
    }

    void strongRow(IntPredicate rows) {
        strong = rows;
    }

    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        Component c = super.prepareRenderer(renderer, row, column);
        if (strong.test(convertRowIndexToModel(row)) && !c.getFont().isBold()) c.setFont(c.getFont().deriveFont(Font.BOLD));
        return c;
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return getParent() == null || getPreferredSize().width < getParent().getWidth();
    }
}
