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
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntConsumer;
import java.util.function.IntSupplier;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Finding;

/**
 * The findings counted by severity, a pill each in its colour: a click shows that severity and above, the pills shown
 * filled; a click on the lowest filled one shows them all again. Then how many findings the filters let through.
 */
final class SummaryBar {

    private static final List<Severity> ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN);

    private final Map<Severity, Chip> chips = new EnumMap<>(Severity.class);
    private final JLabel showingLabel = new JLabel(" ");
    private final JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 6));
    private final IntSupplier current;

    /**
     * @param minSeverity given the index of the severity choice a chip stands for (1: critical…, 0: all)
     * @param current     the index of the severity chosen now
     */
    SummaryBar(I18nLabels labels, IntConsumer minSeverity, IntSupplier current) {
        this.current = current;
        panel.setBorder(BorderFactory.createEmptyBorder(2, 10, 10, 8));
        for (var s : ORDER) {
            var chip = new Chip();
            chip.setFont(chip.getFont().deriveFont(Font.BOLD));
            if (s != Severity.UNKNOWN) {
                int comboIndex = ORDER.indexOf(s) + 1;
                chip.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                chip.addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent e) { minSeverity.accept(current.getAsInt() == comboIndex ? 0 : comboIndex); }
                });
            }
            chips.put(s, chip);
            panel.add(chip);
        }
        labels.on(this::active);
        panel.add(Box.createHorizontalStrut(12));
        showingLabel.setForeground(Color.GRAY);
        panel.add(showingLabel);
    }

    JPanel panel() {
        return panel;
    }

    /** Each chip's count, of these findings. */
    void count(List<Finding> findings) {
        var counts = Finding.countBySeverity(findings);
        chips.forEach((s, chip) -> chip.setText(s.label() + "  " + counts.get(s)));
    }

    /** How many findings are shown: the text, or " " before a scan. */
    void showing(String text) {
        showingLabel.setText(text);
    }

    /** The severities' colours, those of the look in use: light or dark (SeverityColors). */
    void colours() {
        chips.forEach((s, chip) -> chip.colour = SeverityColors.of(s));
        panel.repaint();
    }

    /** The chips of the severities shown filled, the others outlined; their tooltips say what a click does. */
    void active() {
        int min = current.getAsInt();
        chips.forEach((s, chip) -> {
            int index = ORDER.indexOf(s) + 1;
            chip.filled = min > 0 && index <= min;
            if (s != Severity.UNKNOWN) {
                String name = s.label().toLowerCase(I18n.language().locale());
                chip.setToolTipText(index == min ? I18n.text("chip.tip.all")
                        : I18n.text(s == Severity.CRITICAL ? "chip.tip.only" : "chip.tip.andAbove", name));
            }
            chip.repaint();
        });
    }

    /** A count as a pill: its text the label's, painted by Pill. */
    private static final class Chip extends JLabel {
        Color colour = Color.GRAY;
        boolean filled;

        @Override
        protected void paintComponent(Graphics g) {
            Pill.paint(g, 0, getHeight(), getText(), getFont(), colour, filled);
        }

        @Override
        public Dimension getPreferredSize() {
            return Pill.size(getFontMetrics(getFont()), getText() == null ? "" : getText());
        }
    }
}
