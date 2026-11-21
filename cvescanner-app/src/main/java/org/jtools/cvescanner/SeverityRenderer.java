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
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import org.jtools.cvescanner.model.Severity;

final class SeverityRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
        super.getTableCellRendererComponent(t, v, sel, focus, row, col);
        if (v instanceof Severity s) {
            setText(s.label());
            setIcon(new DotIcon(SeverityColors.of(s), 10));
            setFont(getFont().deriveFont(Font.BOLD));
            if (!sel) setForeground(SeverityColors.of(s));
        } else {
            setText("");
            setIcon(null);
        }
        return this;
    }
}
