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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * A severity drawn as a rounded label in its colour: filled, its text white or black, whichever reads better on it;
 * or outlined, its text in the colour. The tables' severities and the counters above them.
 */
final class Pill {

    static final int PAD_X = 9, PAD_Y = 2;

    private Pill() {
    }

    /** The size of a pill holding this text in this font. */
    static Dimension size(FontMetrics fm, String text) {
        return new Dimension(fm.stringWidth(text) + 2 * PAD_X, fm.getHeight() + 2 * PAD_Y);
    }

    /** Paints the pill with its left edge at x, centred in a height of h. */
    static void paint(Graphics g, int x, int h, String text, Font font, Color colour, boolean filled) {
        var g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setFont(font);
            FontMetrics fm = g2.getFontMetrics();
            Dimension d = size(fm, text);
            int y = Math.max(0, (h - d.height) / 2);
            g2.setColor(colour);
            if (filled) g2.fillRoundRect(x, y, d.width, d.height, d.height, d.height);
            else g2.drawRoundRect(x, y, d.width - 1, d.height - 1, d.height, d.height);
            g2.setColor(filled ? textOn(colour) : colour);
            g2.drawString(text, x + PAD_X, y + PAD_Y + fm.getAscent());
        } finally {
            g2.dispose();
        }
    }

    /** White on a dark colour, near-black on a light one (the dark looks' lighter severity colours). */
    static Color textOn(Color c) {
        double luminance = (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255;
        return luminance > 0.6 ? new Color(0x1E1E1E) : Color.WHITE;
    }
}
