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
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * What the window shows before its first scan, where the tables will be: the three steps, Scan, and Try the examples
 * when the examples are beside the program.
 */
final class WelcomePanel {

    /** A button in the accent colour, as Scan is in the toolbar (Looks): in every FlatLaf look, light or dark. */
    static final String ACCENT = "background: $Component.accentColor; foreground: #fff; borderColor: $Component.accentColor;"
            + " hoverBackground: darken($Component.accentColor,6%); pressedBackground: darken($Component.accentColor,12%);"
            + " disabledBackground: $Button.disabledBackground; disabledBorderColor: $Button.disabledBorderColor";

    private final JPanel panel = new JPanel(new GridBagLayout());
    private final JButton scanButton = new JButton();

    /** @param tryExamples run by Try the examples; null when there are none beside the program */
    WelcomePanel(I18nLabels labels, Runnable scan, Runnable tryExamples) {
        panel.setName("welcome");   // for the window test (WindowDriver)
        var box = new JPanel();
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));
        var title = labels.text(new JLabel(), "welcome.title");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 8f));
        add(box, title);
        box.add(Box.createVerticalStrut(18));
        for (String step : new String[] {"welcome.step1", "welcome.step2", "welcome.step3"}) {
            var line = labels.text(new JLabel(), step);
            line.setFont(line.getFont().deriveFont(line.getFont().getSize2D() + 2f));
            line.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
            add(box, line);
        }
        box.add(Box.createVerticalStrut(18));
        var buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        labels.text(scanButton, "toolbar.scan");
        scanButton.putClientProperty("FlatLaf.style", ACCENT);
        scanButton.setFont(scanButton.getFont().deriveFont(Font.BOLD, scanButton.getFont().getSize2D() + 2f));
        scanButton.setName("welcomeScan");
        scanButton.addActionListener(_ -> scan.run());
        buttons.add(scanButton);
        if (tryExamples != null) {
            var examples = labels.text(new JButton(), "welcome.examples");
            examples.setName("tryExamples");
            examples.setFont(examples.getFont().deriveFont(examples.getFont().getSize2D() + 2f));
            examples.addActionListener(_ -> tryExamples.run());
            buttons.add(Box.createHorizontalStrut(12));
            buttons.add(examples);
        }
        add(box, buttons);
        panel.add(box);
    }

    private static void add(JPanel box, JComponent c) {
        c.setAlignmentX(Component.LEFT_ALIGNMENT);
        box.add(c);
    }

    /** Scan, once the folder and the database are given: greyed, its tooltip saying what a scan needs, before. */
    void ready(boolean on) {
        scanButton.setEnabled(on);
        scanButton.setToolTipText(on ? null : org.jtools.cvescanner.i18n.I18n.text("toolbar.scan.needs"));
    }

    JPanel component() {
        return panel;
    }
}
