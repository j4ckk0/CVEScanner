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
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.FindingFilter;

/**
 * What the tables show: the search (every word, over the columns), the lowest severity, the ecosystem, and the three
 * boxes the command line has too (FindingFilter). Says each change through the Runnable given.
 */
final class FilterBar {

    private final HintField searchField = new HintField("", 32);
    private final JComboBox<Choice<Severity>> severityCombo = new JComboBox<>(List.of(
            new Choice<Severity>("filter.allSeverities", null), new Choice<>("filter.critical", Severity.CRITICAL),
            new Choice<>("filter.highUp", Severity.HIGH), new Choice<>("filter.mediumUp", Severity.MEDIUM),
            new Choice<>("filter.lowUp", Severity.LOW)).toArray(Choice[]::new));
    private final JComboBox<Choice<Ecosystem>> ecosystemCombo = new JComboBox<>(List.of(
            new Choice<Ecosystem>("filter.allEcosystems", null), new Choice<>("filter.maven", Ecosystem.MAVEN),
            new Choice<>("filter.npm", Ecosystem.NPM), new Choice<>("filter.pypi", Ecosystem.PYPI),
            new Choice<>("filter.cots", Ecosystem.COTS)).toArray(Choice[]::new));
    private final JCheckBox cveOnlyBox = new JCheckBox();
    private final JCheckBox hideApproxBox = new JCheckBox();
    private final JCheckBox hideNameMatchBox = new JCheckBox();
    private final JPanel panel = new JPanel(new WrapLayout(FlowLayout.LEFT, 12, 8));

    /** @param cveOnly --cve-only, the box ticked from the start; @param changed run on each change */
    FilterBar(I18nLabels labels, boolean cveOnly, Runnable changed) {
        var searchTimer = new Timer(200, _ -> changed.run());
        searchTimer.setRepeats(false);
        cveOnlyBox.setSelected(cveOnly);
        panel.setBorder(BorderFactory.createEmptyBorder(6, 8, 2, 8));
        labels.bind(searchField::setHint, "filter.searchHint");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void removeUpdate(DocumentEvent e) { searchTimer.restart(); }
            public void changedUpdate(DocumentEvent e) { searchTimer.restart(); }
        });
        searchField.registerKeyboardAction(_ -> searchField.setText(""), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_FOCUSED);
        severityCombo.addActionListener(_ -> changed.run());
        ecosystemCombo.addActionListener(_ -> changed.run());
        labels.text(cveOnlyBox, "filter.onlyWithCve").addActionListener(_ -> changed.run());
        labels.text(hideApproxBox, "filter.hideApproximate").addActionListener(_ -> changed.run());
        labels.text(hideNameMatchBox, "filter.hideNameMatches").addActionListener(_ -> changed.run());
        labels.tip(hideNameMatchBox, "filter.hideNameMatches.tip");
        var clear = labels.text(new JButton(), "filter.clear");
        clear.addActionListener(_ -> {
            searchField.setText("");
            severityCombo.setSelectedIndex(0);
            ecosystemCombo.setSelectedIndex(0);
            cveOnlyBox.setSelected(false);
            hideApproxBox.setSelected(false);
            hideNameMatchBox.setSelected(false);
            changed.run();
        });
        panel.add(labels.text(new JLabel(), "filter.search"));
        panel.add(searchField);
        panel.add(severityCombo);
        panel.add(ecosystemCombo);
        panel.add(cveOnlyBox);
        panel.add(hideApproxBox);
        panel.add(hideNameMatchBox);
        panel.add(clear);
        labels.on(() -> List.<Component>of(severityCombo, ecosystemCombo).forEach(Component::repaint));
    }

    JPanel panel() {
        return panel;
    }

    /** The words searched, in lower case. */
    List<String> searchTerms() {
        return Arrays.stream(searchField.getText().toLowerCase(Locale.ROOT).split("\\s+")).filter(s -> !s.isBlank()).toList();
    }

    /** The ecosystem shown; null for all. */
    Ecosystem ecosystem() {
        return ecosystemCombo.getSelectedItem() instanceof Choice<?> choice ? (Ecosystem) choice.value() : null;
    }

    /** The filters chosen, the command line's own rule (FindingFilter); the search is the table's, over its columns. */
    FindingFilter facets() {
        var min = severityCombo.getSelectedItem() instanceof Choice<?> choice ? (Severity) choice.value() : null;
        Ecosystem ecosystem = ecosystem();
        return new FindingFilter(min, ecosystem == null ? Set.of() : Set.of(ecosystem), cveOnlyBox.isSelected(),
                hideApproxBox.isSelected(), hideNameMatchBox.isSelected(), List.of());
    }

    /** Searches this text: a package's name, from its row or its finding. */
    void search(String text) {
        searchField.setText(text);
    }

    /** Shows this severity and above: the index of its choice, 0 for all. */
    void minSeverity(int index) {
        severityCombo.setSelectedIndex(index);
    }

    /** The search field focused, its text selected (Ctrl+F). */
    void focusSearch() {
        searchField.requestFocusInWindow();
        searchField.selectAll();
    }
}
