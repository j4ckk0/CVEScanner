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
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import org.jtools.cvescanner.cvss.Severity;

/** A severity as a pill in its colour (Pill), on the row's own background: striped, or selected. */
final class SeverityRenderer extends DefaultTableCellRenderer {

    private Severity severity;

    @Override
    public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
        super.getTableCellRendererComponent(t, v, sel, focus, row, col);
        severity = v instanceof Severity s ? s : null;
        setText(severity == null ? "" : severity.label());   // what a screen reader says; painted as a pill below
        setIcon(null);
        setFont(getFont().deriveFont(Font.BOLD, getFont().getSize2D() - 1f));
        return this;
    }

    @Override
    protected void paintComponent(Graphics g) {
        if (severity == null) {
            super.paintComponent(g);
            return;
        }
        g.setColor(getBackground());
        g.fillRect(0, 0, getWidth(), getHeight());
        Pill.paint(g, getInsets().left, getHeight(), severity.label(), getFont(), SeverityColors.of(severity), true);
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        if (severity == null) return d;
        Dimension pill = Pill.size(getFontMetrics(getFont()), severity.label());
        return new Dimension(Math.max(d.width, pill.width + getInsets().left + getInsets().right), Math.max(d.height, pill.height));
    }
}
