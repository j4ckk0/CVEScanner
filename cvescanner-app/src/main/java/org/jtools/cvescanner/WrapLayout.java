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
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;

/** FlowLayout that wraps onto extra rows (and reports the height for them) when the container is too narrow. */
final class WrapLayout extends FlowLayout {
    WrapLayout(int align, int hgap, int vgap) { super(align, hgap, vgap); }

    @Override public Dimension preferredLayoutSize(Container target) { return size(target, true); }

    /** The width at which a new layout was last asked for (layoutContainer): asked once for each width, never in a loop. */
    private int askedAt = -1;

    /**
     * Laid out, then once more when its rows need another height than the one given at this width: a height the panels
     * around worked out before it had a width (it is shown at last, after the window's first scan) would leave rows of
     * empty space.
     */
    @Override public void layoutContainer(Container target) {
        super.layoutContainer(target);
        int width = target.getWidth();
        if (width > 0 && width != askedAt && size(target, true).height != target.getHeight()) {
            askedAt = width;
            SwingUtilities.invokeLater(((JComponent) target)::revalidate);
        }
    }

    @Override public Dimension minimumLayoutSize(Container target) {
        var d = size(target, false);
        d.width -= getHgap() + 1;
        return d;
    }

    private Dimension size(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            Container sized = target;
            while (sized.getSize().width == 0 && sized.getParent() != null) sized = sized.getParent();
            int available = sized.getSize().width == 0 ? Integer.MAX_VALUE : sized.getSize().width;
            Insets in = target.getInsets();
            int maxWidth = available - (in.left + in.right + getHgap() * 2);
            int width = 0, height = 0, rowWidth = 0, rowHeight = 0;
            for (Component c : target.getComponents()) {
                if (!c.isVisible()) continue;
                Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                if (rowWidth > 0 && rowWidth + getHgap() + d.width > maxWidth) {
                    width = Math.max(width, rowWidth);
                    height += rowHeight + getVgap();
                    rowWidth = 0;
                    rowHeight = 0;
                }
                rowWidth += (rowWidth > 0 ? getHgap() : 0) + d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }
            width = Math.max(width, rowWidth) + in.left + in.right + getHgap() * 2;
            height += rowHeight + in.top + in.bottom + getVgap() * 2;
            return new Dimension(width, height);
        }
    }
}
