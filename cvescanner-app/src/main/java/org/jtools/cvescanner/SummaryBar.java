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
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntConsumer;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Finding;

/**
 * The findings counted by severity, one chip each in its colour (a click shows that severity and above), and how
 * many findings the filters let through.
 */
final class SummaryBar {

    private final Map<Severity, JLabel> chips = new EnumMap<>(Severity.class);
    private final JLabel showingLabel = new JLabel(" ");
    private final JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 6));

    /** @param minSeverity given the index of the severity choice a chip stands for (1: critical…) */
    SummaryBar(I18nLabels labels, IntConsumer minSeverity) {
        panel.setBorder(BorderFactory.createEmptyBorder(2, 10, 10, 8));
        int index = 1;
        for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN)) {
            var chip = new JLabel();
            chip.setFont(chip.getFont().deriveFont(Font.BOLD, chip.getFont().getSize2D() + 1f));
            if (s != Severity.UNKNOWN) {
                int comboIndex = index++;
                chip.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                labels.on(() -> chip.setToolTipText(I18n.text(s == Severity.CRITICAL ? "chip.tip.only" : "chip.tip.andAbove",
                        s.label().toLowerCase(I18n.language().locale()))));
                chip.addMouseListener(new MouseAdapter() {
                    @Override public void mouseClicked(MouseEvent e) { minSeverity.accept(comboIndex); }
                });
            }
            chips.put(s, chip);
            panel.add(chip);
        }
        panel.add(Box.createHorizontalStrut(20));
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
        chips.forEach((s, chip) -> {
            chip.setIcon(new DotIcon(SeverityColors.of(s), 12));
            chip.setForeground(SeverityColors.of(s));
        });
    }
}
