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
import java.awt.Dimension;
import java.util.List;
import java.util.function.Supplier;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The line at the bottom: what was last said (a scan's counts, a link copied), said again in the language chosen; a
 * progress bar while something runs; a tooltip with the databases read and the warnings.
 */
final class StatusLine {

    private final JLabel label = SwingText.noHtml(new JLabel(" "));
    private final JProgressBar progressBar = new JProgressBar(0, 1000);
    private final JPanel panel = new JPanel(new BorderLayout(16, 0));
    private Supplier<String> message = () -> I18n.text("status.ready");

    StatusLine(I18nLabels labels) {
        label.setName("status");   // for the window test (WindowDriver)
        panel.setBorder(BorderFactory.createEmptyBorder(8, 18, 10, 18));
        progressBar.setPreferredSize(new Dimension(220, 14));
        progressBar.setVisible(false);
        panel.add(label, BorderLayout.CENTER);
        panel.add(progressBar, BorderLayout.EAST);
        labels.on(() -> label.setText(message.get()));
    }

    JPanel panel() {
        return panel;
    }

    /** Shows this, and again whenever the language changes. */
    void say(Supplier<String> message) {
        this.message = message;
        label.setText(message.get());
    }

    /** The progress bar shown, moving until told how far, or hidden. */
    void busy(boolean busy) {
        progressBar.setVisible(busy);
        progress(-1);
    }

    /** How far it has gone, 0 to 1; below 0, not known. */
    void progress(double fraction) {
        progressBar.setIndeterminate(fraction < 0);
        if (fraction >= 0) progressBar.setValue((int) (fraction * 1000));
    }

    /** The tooltip's lines, as HTML already escaped; none, no tooltip. */
    void tip(List<String> htmlLines) {
        label.setToolTipText(htmlLines.isEmpty() ? null : "<html>" + String.join("<br>", htmlLines) + "</html>");
    }
}
