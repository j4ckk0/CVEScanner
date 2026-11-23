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
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The database zips a scan reads, each listed once with a tick box: those of the database folder (--db-dir), those the
 * command line named (--db), those added in the window. A scan reads the ticked ones; an unticked zip stays listed for
 * next time. The list drops down from its button, the field beside it showing the zips ticked.
 */
final class DatabaseChoice {

    /** The rows shown before the list scrolls: NVD's yearly feeds alone are some 25 zips. */
    private static final int VISIBLE_ROWS = 12;

    private final Component owner;
    private final I18nLabels labels;
    private final Settings settings;
    private final Path dbDir;
    private final JTextField field = new JTextField(40);
    private final JButton chooseButton = new JButton();
    private final JPopupMenu popup = new JPopupMenu();
    /** Every zip listed, in order: the command line's first, then those added in the window. */
    private final List<Path> listed = new ArrayList<>();
    /** Those added in the window, kept in the settings; the only ones the list can remove, the others come back at start. */
    private final List<Path> added = new ArrayList<>();
    /** The unticked zips, by key(). */
    private final Set<Path> unticked = new HashSet<>();
    /** Told when the zips ticked change. */
    private Runnable onChange = () -> { };

    /** @param given the zips the command line named, --db-dir's among them; @param dbDir --db-dir, its zips never removed */
    DatabaseChoice(Component owner, I18nLabels labels, Settings settings, List<Path> given, Path dbDir) {
        this.owner = owner;
        this.labels = labels;
        this.settings = settings;
        this.dbDir = dbDir;
        added.addAll(saved(Settings.DATABASES).stream().filter(Files::isRegularFile).toList());
        listed.addAll(union(given, added));
        unticked.addAll(untickedAtStart(saved(Settings.DATABASES_UNTICKED), given, dbDir));
        field.setEditable(false);
        field.setName("databases");   // for the window test and the README's pictures (WindowDriver)
        field.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                showList();
            }
        });
        chooseButton.setName("databaseChoose");
        labels.tip(labels.text(chooseButton, "toolbar.chooseDatabase"), "toolbar.chooseDatabase.tip");
        chooseButton.addActionListener(_ -> showList());
        labels.on(this::updateField);
    }

    void onChange(Runnable changed) {
        onChange = changed;
    }

    /** The field outlined in red while no zip is ticked: a scan needs one. */
    void outline(boolean missing) {
        field.putClientProperty("JComponent.outline", missing ? "error" : null);
    }

    /** The zips ticked, for a scan. */
    List<Path> files() {
        return listed.stream().filter(p -> !unticked.contains(key(p))).toList();
    }

    /** Its row of the toolbar, columns 0 to 2 at the row the constraints are set to. */
    void addRow(JPanel rows, GridBagConstraints c) {
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.database"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(field, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(chooseButton, c);
    }

    // ------------------------------------------------------------------------------------------- what is listed

    /** The same file however named: the key of the list, so that no zip is listed twice. */
    static Path key(Path p) {
        return p.toAbsolutePath().normalize();
    }

    /** These zips, then those of the others not among them already. */
    static List<Path> union(List<Path> first, List<Path> then) {
        var all = new LinkedHashMap<Path, Path>();
        for (Path p : first) all.putIfAbsent(key(p), p);
        for (Path p : then) all.putIfAbsent(key(p), p);
        return List.copyOf(all.values());
    }

    /**
     * The zips unticked at start: those unticked last time, but a zip the command line named itself (--db, outside
     * --db-dir), which was named to be read.
     */
    static Set<Path> untickedAtStart(List<Path> before, List<Path> given, Path dbDir) {
        var out = new HashSet<Path>();
        for (Path p : before) out.add(key(p));
        for (Path p : given) if (!inFolder(p, dbDir)) out.remove(key(p));
        return out;
    }

    private static boolean inFolder(Path p, Path dbDir) {
        return dbDir != null && key(p).getParent() != null && key(p).getParent().equals(key(dbDir));
    }

    private List<Path> saved(String setting) {
        String value = settings.get(setting, "");
        return value.isBlank() ? List.of() : Arrays.stream(value.split(Pattern.quote(File.pathSeparator))).map(Path::of).toList();
    }

    private void save() {
        settings.set(Settings.DATABASES, added.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        settings.set(Settings.DATABASES_UNTICKED, unticked.stream().map(Path::toString).sorted().collect(Collectors.joining(File.pathSeparator)));
    }

    private void changed() {
        save();
        updateField();
        onChange.run();
    }

    private void tick(Path p, boolean on) {
        if (on) unticked.remove(key(p));
        else unticked.add(key(p));
        changed();
    }

    private void tickAll(boolean on) {
        for (Path p : listed) if (on) unticked.remove(key(p)); else unticked.add(key(p));
        changed();
        showList();
    }

    /** Zips chosen in the file chooser: listed, ticked; one listed already is ticked, not listed again. */
    private void add(List<Path> chosen) {
        for (Path p : chosen) {
            unticked.remove(key(p));
            if (!among(listed, p)) {
                listed.add(p);
                added.add(p);
            }
        }
        changed();
    }

    private static boolean among(List<Path> paths, Path p) {
        return paths.stream().anyMatch(q -> key(q).equals(key(p)));
    }

    private void remove(Path p) {
        listed.removeIf(q -> key(q).equals(key(p)));
        added.removeIf(q -> key(q).equals(key(p)));
        unticked.remove(key(p));
        changed();
        showList();
    }

    // ------------------------------------------------------------------------------------------- the list

    /** The list dropped down below the button: a tick box a zip, and what adds others. */
    private void showList() {
        popup.setVisible(false);
        popup.removeAll();
        var panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        panel.add(new JLabel(I18n.text(listed.isEmpty() ? "database.list.empty" : "database.list.title")), BorderLayout.NORTH);
        if (!listed.isEmpty()) {
            var rows = new JPanel();
            rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));
            for (Path p : listed) rows.add(row(p));
            var scroll = new JScrollPane(rows, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            scroll.getVerticalScrollBar().setUnitIncrement(16);
            int height = 0;
            for (int i = 0; i < Math.min(listed.size(), VISIBLE_ROWS); i++) height += rows.getComponent(i).getPreferredSize().height;
            var insets = scroll.getInsets();
            int scrollbar = listed.size() > VISIBLE_ROWS ? scroll.getVerticalScrollBar().getPreferredSize().width : 0;
            scroll.setPreferredSize(new Dimension(rows.getPreferredSize().width + scrollbar + insets.left + insets.right,
                    height + insets.top + insets.bottom));
            panel.add(scroll, BorderLayout.CENTER);
        }
        var buttons = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        if (!listed.isEmpty()) {
            buttons.add(button("databaseAll", "database.list.all", () -> tickAll(true)));
            buttons.add(Box.createHorizontalStrut(6));
            buttons.add(button("databaseNone", "database.list.none", () -> tickAll(false)));
            buttons.add(Box.createHorizontalStrut(18));
        }
        buttons.add(button("databaseAdd", "database.list.add", this::choose));
        panel.add(buttons, BorderLayout.SOUTH);
        popup.add(panel);
        popup.show(chooseButton, chooseButton.getWidth() - popup.getPreferredSize().width, chooseButton.getHeight());
    }

    private JButton button(String name, String key, Runnable action) {
        var b = new JButton(I18n.text(key));
        b.setName(name);   // for the window test (WindowDriver)
        b.addActionListener(_ -> action.run());
        return b;
    }

    /** A zip's row: its tick box, named by the file and its folder (OSV's exports are all all.zip); × for one added here. */
    private JPanel row(Path p) {
        var row = new JPanel(new BorderLayout(8, 0));
        row.setOpaque(false);
        Path parent = key(p).getParent();
        var box = new JCheckBox(p.getFileName() + (parent != null ? "   —   " + shortFolder(parent) : ""), !unticked.contains(key(p)));
        box.setName("database:" + key(p));   // for the window test (WindowDriver)
        box.setToolTipText(inFolder(p, dbDir) ? I18n.text("database.list.folder.tip") : key(p).toString());
        box.addActionListener(_ -> tick(p, box.isSelected()));
        row.add(box, BorderLayout.CENTER);
        if (among(added, p)) {
            var remove = new JButton("×");
            remove.setName("databaseRemove:" + key(p));
            remove.setToolTipText(I18n.text("database.list.remove.tip"));
            remove.putClientProperty("JButton.buttonType", "toolBarButton");
            remove.addActionListener(_ -> remove(p));
            row.add(remove, BorderLayout.EAST);
        }
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    /** A folder as the list shows it: the home folder as ~, a long one cut in its middle. */
    static String shortFolder(Path folder) {
        String text = folder.toString(), home = System.getProperty("user.home");
        if (home != null && !home.isEmpty() && (text.equals(home) || text.startsWith(home + File.separator)))
            text = "~" + text.substring(home.length());
        return text.length() <= 50 ? text : text.substring(0, 16) + "…" + text.substring(text.length() - 33);
    }

    private void choose() {
        popup.setVisible(false);
        File start = !added.isEmpty() ? added.getLast().toFile().getParentFile()
                : dbDir != null && Files.isDirectory(dbDir) ? dbDir.toFile() : new File(System.getProperty("user.home"));
        var chooser = new JFileChooser(start);
        chooser.setDialogTitle(I18n.text("database.chooser.title"));
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("database.chooser.filter"), "zip"));
        var help = new JLabel(I18n.text("database.chooser.help"));
        help.setVerticalAlignment(SwingConstants.TOP);
        chooser.setAccessory(help);
        if (chooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION)
            add(Arrays.stream(chooser.getSelectedFiles()).map(File::toPath).toList());
    }

    private void updateField() {
        var ticked = files();
        boolean none = ticked.isEmpty();
        field.setText(none ? I18n.text(listed.isEmpty() ? "toolbar.database.none" : "toolbar.database.noneTicked")
                : ticked.stream().map(p -> p.getFileName().toString()).collect(Collectors.joining("  ;  ")));
        field.setForeground(none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        field.setCaretPosition(0);
        field.setToolTipText(none ? null : I18n.text("toolbar.database.tip", ticked.size(), listed.size(),
                ticked.stream().map(Path::toString).collect(Collectors.joining(",  "))));
    }
}
