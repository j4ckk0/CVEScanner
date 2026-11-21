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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.time.LocalDate;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.ToIntFunction;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.model.Finding;

/**
 * Asks how to set a finding aside: for its version of its package, every version, or every package; why; until when.
 * Says how many findings the entry would set aside, and in which file it is written. Every text of the finding is
 * shown as text, never as HTML (SwingText.noHtml).
 */
final class IgnoreDialog {

    private IgnoreDialog() {}

    /**
     * The entry asked for; empty when the dialog is cancelled.
     *
     * @param count how many findings an entry would set aside
     */
    static Optional<IgnoreRule> ask(Component owner, Finding f, String file, ToIntFunction<IgnoreRule> count) {
        var panel = new JPanel(new GridBagLayout());
        var c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;
        String id = f.cves().isEmpty() ? f.id() : f.cves().getFirst();
        panel.add(SwingText.noHtml(new JLabel(I18n.text("ignore.dialog.what", id, f.pkg(), f.version()))), c);

        var scopes = new EnumMap<IgnoreRule.Scope, JRadioButton>(IgnoreRule.Scope.class);
        scopes.put(IgnoreRule.Scope.VERSION, SwingText.noHtml(new JRadioButton(I18n.text("ignore.dialog.scope.version", f.version()), true)));
        scopes.put(IgnoreRule.Scope.PACKAGE, SwingText.noHtml(new JRadioButton(I18n.text("ignore.dialog.scope.package", f.pkg()))));
        scopes.put(IgnoreRule.Scope.EVERYWHERE, SwingText.noHtml(new JRadioButton(I18n.text("ignore.dialog.scope.everywhere", id))));
        var group = new ButtonGroup();
        c.gridwidth = 1;
        c.gridy++;
        panel.add(new JLabel(I18n.text("ignore.dialog.scope")), c);
        c.gridx = 1;
        for (var button : scopes.values()) {
            group.add(button);
            panel.add(button, c);
            c.gridy++;
        }
        var reason = new JTextField(36);
        var until = new HintField(I18n.text("ignore.dialog.until.hint"), 12);
        c.gridx = 0;
        panel.add(new JLabel(I18n.text("ignore.dialog.reason")), c);
        c.gridx = 1;
        panel.add(reason, c);
        c.gridy++;
        c.gridx = 0;
        panel.add(new JLabel(I18n.text("ignore.dialog.until")), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.NONE;
        panel.add(until, c);
        c.fill = GridBagConstraints.HORIZONTAL;
        var counted = new JLabel(" ");
        Runnable recount = () -> counted.setText(I18n.text("ignore.dialog.count",
                count.applyAsInt(IgnoreRule.forFinding(f, scope(scopes), "", null))));
        scopes.values().forEach(b -> b.addActionListener(_ -> recount.run()));
        recount.run();
        c.gridy++;
        c.gridx = 0;
        c.gridwidth = 2;
        counted.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        panel.add(counted, c);
        c.gridy++;
        panel.add(SwingText.noHtml(new JLabel(I18n.text("ignore.dialog.file", file))), c);

        while (true) {
            int choice = JOptionPane.showOptionDialog(owner, panel, I18n.text("ignore.dialog.title"), JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE, null, new Object[]{I18n.text("ignore.dialog.ok"), I18n.text("ignore.dialog.cancel")},
                    I18n.text("ignore.dialog.ok"));
            if (choice != 0) return Optional.empty();
            String problem = reason.getText().isBlank() ? I18n.text("ignore.dialog.reason.missing") : null;
            LocalDate date = null;
            if (problem == null) {
                try {
                    date = IgnoreRule.until(until.getText(), LocalDate.now());
                } catch (IllegalArgumentException e) {
                    problem = e.getMessage();
                }
            }
            if (problem == null) return Optional.of(IgnoreRule.forFinding(f, scope(scopes), reason.getText(), date));
            JOptionPane.showMessageDialog(owner, SwingText.plain(problem), I18n.text("ignore.dialog.title"), JOptionPane.WARNING_MESSAGE);
        }
    }

    private static IgnoreRule.Scope scope(Map<IgnoreRule.Scope, JRadioButton> scopes) {
        return scopes.entrySet().stream().filter(e -> e.getValue().isSelected()).map(Map.Entry::getKey).findFirst()
                .orElse(IgnoreRule.Scope.VERSION);
    }
}
