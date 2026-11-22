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
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Scrollable;
import org.jtools.cvescanner.fix.FixOutcome;
import org.jtools.cvescanner.fix.FixPlan;
import org.jtools.cvescanner.fix.Step;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The fixes as they would be applied, shown before anything runs: per package, the command or the edit, what was
 * checked of the new version, or why it cannot be applied. A major version change is applied only once ticked here.
 * Then what applying them gave, with the tools' log to copy. Every text of a project is shown as text, never as HTML.
 */
final class FixDialog {

    private FixDialog() {}

    /** The plans to run: those the user left ticked. Empty when cancelled or when none can be applied. */
    static List<FixPlan> confirm(Component owner, List<FixPlan> plans, Path root) {
        var boxes = new LinkedHashMap<FixPlan, JCheckBox>();
        var content = content(plans, boxes, root);
        if (plans.stream().noneMatch(FixPlan::applicable)) {
            JOptionPane.showMessageDialog(owner, content, I18n.text("fixDialog.title"), JOptionPane.INFORMATION_MESSAGE);
            return List.of();
        }
        int choice = JOptionPane.showOptionDialog(owner, content, I18n.text("fixDialog.title"), JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE, null, new Object[]{I18n.text("fixDialog.apply"), I18n.text("fixDialog.cancel")},
                I18n.text("fixDialog.apply"));
        if (choice != 0) return List.of();
        return boxes.entrySet().stream().filter(e -> e.getValue().isSelected()).map(Map.Entry::getKey).toList();
    }

    /**
     * The plans, one under the other, each with its tick (kept in boxes), its steps or why not, what was checked; the
     * files named from the folder scanned.
     */
    static JPanel content(List<FixPlan> plans, Map<FixPlan, JCheckBox> boxes, Path root) {
        String prefix = root.toAbsolutePath().normalize() + File.separator;
        var panel = new WidthTrackingPanel();
        var c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets = new Insets(2, 4, 2, 4);
        for (FixPlan plan : plans) {
            var r = plan.request();
            var box = SwingText.noHtml(new JCheckBox(r.pkg() + "   " + r.from() + " → " + r.to()));
            box.setEnabled(plan.applicable());
            box.setSelected(plan.applicable() && !plan.majorJump());
            c.insets = new Insets(10, 4, 2, 4);
            panel.add(box, c);
            c.gridy++;
            var lines = new ArrayList<String>();
            var full = new ArrayList<String>();
            if (!plan.applicable()) {
                lines.add(I18n.text("fixDialog.notApplied", plan.notApplicable().text()));
            } else {
                for (Step step : plan.steps()) {
                    lines.add(step.brief().replace(prefix, ""));
                    full.add(step.shown().replace(prefix, ""));
                }
                if (plan.requirement() != null) lines.add(plan.requirement().text());
                plan.notes().forEach(note -> lines.add(note.text()));
                if (plan.majorVersionChange()) lines.add(I18n.text("fixDialog.majorJump"));
            }
            var detail = SwingText.plain(String.join("\n", lines));
            detail.setLineWrap(true);
            detail.setWrapStyleWord(true);
            // the programs by their full path, which the short lines leave out; every text escaped
            if (!full.isEmpty())
                detail.setToolTipText("<html>" + String.join("<br>", full.stream().map(SwingText::html).toList()) + "</html>");
            detail.setForeground(plan.applicable() ? detail.getForeground() : Color.GRAY);
            detail.setBorder(BorderFactory.createEmptyBorder(0, 28, 0, 0));
            c.insets = new Insets(0, 4, 2, 4);
            panel.add(detail, c);
            c.gridy++;
            boxes.put(plan, box);
        }
        c.weighty = 1;
        panel.add(new JPanel(), c);
        var scroll = new JScrollPane(panel);
        scroll.setPreferredSize(new Dimension(900, Math.min(520, 140 + 90 * plans.size())));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        var content = new JPanel(new BorderLayout(0, 10));
        var intro = SwingText.plain(I18n.text("fixDialog.intro"));
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setColumns(80);
        content.add(intro, BorderLayout.NORTH);
        content.add(scroll, BorderLayout.CENTER);
        return content;
    }

    /** The plans' panel in its scroll pane: as wide as the pane, so that long lines wrap rather than run past its edge. */
    private static final class WidthTrackingPanel extends JPanel implements Scrollable {
        WidthTrackingPanel() {
            super(new GridBagLayout());
        }

        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int orientation, int direction) { return r.height; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    /** What applying the fixes gave: per package applied or why not, then the tools' log, which can be copied. */
    static void results(Component owner, List<FixOutcome> outcomes) {
        long applied = outcomes.stream().filter(FixOutcome::applied).count();
        var summary = new StringBuilder(I18n.text("fixDialog.results.count", applied, outcomes.size() - applied)).append("\n\n");
        var log = new StringBuilder();
        for (FixOutcome o : outcomes) {
            var r = o.plan().request();
            summary.append(r.pkg()).append("   ").append(r.from()).append(" → ").append(r.to()).append(": ").append(o.reason().text()).append('\n');
            log.append(o.log());
        }
        summary.append('\n').append(I18n.text("fixDialog.results.rescan"));
        var area = new JTextArea(log.toString(), 14, 90);
        area.setEditable(false);
        var content = new JPanel(new BorderLayout(0, 10));
        content.add(SwingText.plain(summary.toString()), BorderLayout.NORTH);
        content.add(new JScrollPane(area), BorderLayout.CENTER);
        int choice = JOptionPane.showOptionDialog(owner, content, I18n.text("fixDialog.results.title"), JOptionPane.DEFAULT_OPTION,
                applied == outcomes.size() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE, null,
                new Object[]{I18n.text("fixDialog.results.copyLog"), I18n.text("fixDialog.results.ok")}, I18n.text("fixDialog.results.ok"));
        if (choice == 0) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(summary + "\n" + log), null);
    }
}
