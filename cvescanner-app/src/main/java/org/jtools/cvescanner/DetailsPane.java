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

import java.awt.Dimension;
import java.util.Comparator;
import javax.swing.JEditorPane;
import javax.swing.JScrollPane;
import javax.swing.event.HyperlinkEvent;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;

/**
 * The details of what is selected in the tab shown: a finding; in the packages' tab, the package's most severe
 * finding, in the Dependencies tab the dependency's (given by MainWindow); in the Ignored tab, the finding set aside
 * and why; nothing in the unchecked dependencies' tab. A link in it is copied, never opened.
 */
final class DetailsPane {

    /** What the details need of the window. */
    interface Host {
        boolean scanned();

        Ignores.Split split();

        Ignores ignores();

        Environment environment();

        void copyLink(String url);
    }

    private static final int FINDINGS = MainWindow.FINDINGS_TAB, PACKAGES = MainWindow.PACKAGES_TAB, IGNORED = MainWindow.IGNORED_TAB;

    private final FindingTables tables;
    private final Host host;
    private final JEditorPane pane = new JEditorPane("text/html", "");
    private final JScrollPane scroll = new JScrollPane(pane);

    DetailsPane(FindingTables tables, Host host) {
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
    }

    JScrollPane component() {
        return scroll;
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
        pane.setText(f == null ? FindingDetails.placeholder(host.scanned())
                : FindingDetails.page(f, host.environment(), null, "", host.ignores().statementsFor(f)));
        pane.setCaretPosition(0);
    }

    private void showIgnored() {
        var i = tables.selectedIgnored();
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
