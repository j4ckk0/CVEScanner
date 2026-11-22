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
import java.awt.FlowLayout;
import java.util.Comparator;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.HyperlinkEvent;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;

/**
 * The details of what is selected in the tab shown: a finding; in the packages' tab, the package's most severe
 * finding, in the Dependencies tab the dependency's (given by MainWindow); in the Ignored tab, the finding set aside
 * and why; nothing in the unchecked dependencies' tab. A link in it is copied, never opened. Above it, buttons for what
 * the tables' right-click menus do: copy the advisory's link, the CVEs, the package; ignore it, or stop ignoring it.
 */
final class DetailsPane {

    /** What the details need of the window. */
    interface Host {
        boolean scanned();

        Ignores.Split split();

        Ignores ignores();

        Environment environment();

        void copyLink(String url);

        void ignore(Finding f);

        void stopIgnoring(IgnoredFinding i);
    }

    private static final int FINDINGS = MainWindow.FINDINGS_TAB, PACKAGES = MainWindow.PACKAGES_TAB, IGNORED = MainWindow.IGNORED_TAB;

    private final FindingTables tables;
    private final Host host;
    private final JEditorPane pane = new JEditorPane("text/html", "");
    private final JScrollPane scroll = new JScrollPane(pane);
    private final JPanel panel = new JPanel(new BorderLayout());
    private final JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    private final JButton ignoreButton = new JButton(), stopButton = new JButton();
    /** What the details show: the finding, and the entry setting it aside when it is one of the Ignored tab. */
    private Finding shown;
    private IgnoredFinding shownIgnored;

    DetailsPane(FindingTables tables, I18nLabels labels, Host host) {
        this.tables = tables;
        this.host = host;
        pane.setName("details");   // for the window test (WindowDriver)
        pane.setEditable(false);
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.addHyperlinkListener(e -> {
            // the address as the page wrote it (getDescription), never resolved into a URL
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) host.copyLink(e.getDescription());
        });
        scroll.setPreferredSize(new Dimension(400, 300));
        actions.add(button(labels, "menu.finding.copyAdvisoryLink", () -> host.copyLink(shown.url())));
        actions.add(button(labels, "menu.finding.copyCves", () -> Clipboard.copy(shown.cves().isEmpty() ? shown.id() : shown.cveText())));
        actions.add(button(labels, "menu.finding.copyNvdLink",
                () -> host.copyLink(shown.cves().stream().map(FindingDetails::nvdUrl).collect(Collectors.joining(" ")))));
        actions.add(button(labels, "menu.finding.copyCoordinate", () -> Clipboard.copy(shown.ecosystem().coordinate(shown.pkg(), shown.version()))));
        labels.text(ignoreButton, "menu.finding.ignore").addActionListener(_ -> { if (shown != null) host.ignore(shown); });
        labels.text(stopButton, "menu.ignored.stop").addActionListener(_ -> { if (shownIgnored != null) host.stopIgnoring(shownIgnored); });
        for (var b : java.util.List.of(ignoreButton, stopButton)) {
            b.putClientProperty("JComponent.sizeVariant", "small");
            actions.add(b);
        }
        actions.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        panel.add(actions, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        showing(null, null);
    }

    /** A small button of the actions' row, acting on the finding shown. */
    private JButton button(I18nLabels labels, String key, Runnable action) {
        var b = labels.text(new JButton(), key);
        b.putClientProperty("JComponent.sizeVariant", "small");
        b.addActionListener(_ -> { if (shown != null) action.run(); });
        return b;
    }

    /** The actions' row for what is shown: none for nothing, Stop ignoring for a finding set aside, Ignore otherwise. */
    private void showing(Finding f, IgnoredFinding i) {
        shown = f;
        shownIgnored = i;
        actions.setVisible(f != null);
        ignoreButton.setVisible(i == null);
        stopButton.setVisible(i != null && !i.rule().fromVex());
    }

    JComponent component() {
        return panel;
    }

    /** The details of the selection in this tab. */
    void show(int tab) {
        switch (tab) {
            case FINDINGS -> show(tables.selectedFinding());
            case PACKAGES -> show(worstFinding(tables.selectedPackage()));
            case IGNORED -> showIgnored();
            default -> show((Finding) null);
        }
    }

    /** The details of this finding; null, the placeholder. */
    void show(Finding f) {
        showing(f, null);
        pane.setText(f == null ? FindingDetails.placeholder(host.scanned())
                : FindingDetails.page(f, host.environment(), null, "", host.ignores().statementsFor(f)));
        pane.setCaretPosition(0);
    }

    private void showIgnored() {
        var i = tables.selectedIgnored();
        showing(i == null ? null : i.finding(), i);
        pane.setText(i == null ? FindingDetails.placeholder(host.scanned())
                : FindingDetails.page(i.finding(), host.environment(), i.rule(), host.ignores().shown(),
                        host.ignores().statementsFor(i.finding())));
        pane.setCaretPosition(0);
    }

    private Finding worstFinding(PackageSummary p) {
        if (p == null) return null;
        return host.split().active().stream()
                .filter(f -> f.ecosystem() == p.ecosystem() && f.pkg().equals(p.pkg()) && f.version().equals(p.version()))
                .max(Comparator.comparing(Finding::severity)).orElse(null);
    }
}
