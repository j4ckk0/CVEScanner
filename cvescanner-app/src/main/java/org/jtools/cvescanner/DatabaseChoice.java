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
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The database zips a scan reads: those the command line named (--db), else those chosen last time (Settings), chosen
 * again with a file chooser or cleared.
 */
final class DatabaseChoice {

    private final Component owner;
    private final I18nLabels labels;
    private final Settings settings;
    private final Path dbDir;
    private final JTextField field = new JTextField(40);
    private final JButton clearButton = new JButton();
    private final List<Path> files = new ArrayList<>();
    /** Told when the zips chosen change. */
    private Runnable onChange = () -> { };

    /** @param given the zips the command line named; @param dbDir --db-dir, where the chooser opens when none is chosen */
    DatabaseChoice(Component owner, I18nLabels labels, Settings settings, List<Path> given, Path dbDir) {
        this.owner = owner;
        this.labels = labels;
        this.settings = settings;
        this.dbDir = dbDir;
        if (!given.isEmpty()) files.addAll(given);
        else restore();
        field.setEditable(false);
        field.setName("databases");   // for the window test and the README's pictures (WindowDriver)
        labels.text(clearButton, "toolbar.clearDatabase");
        clearButton.addActionListener(_ -> set(List.of()));
        labels.on(this::updateField);
    }

    void onChange(Runnable changed) {
        onChange = changed;
    }

    /** The field outlined in red while no zip is chosen: a scan needs one. */
    void outline(boolean missing) {
        field.putClientProperty("JComponent.outline", missing ? "error" : null);
    }

    /** The zips chosen, for a scan. */
    List<Path> files() {
        return List.copyOf(files);
    }

    /** Its row of the toolbar, columns 0 to 3 at the row the constraints are set to. */
    void addRow(JPanel rows, GridBagConstraints c) {
        var choose = labels.text(new JButton(), "toolbar.chooseDatabase");
        choose.addActionListener(_ -> choose());
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.database"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(field, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(choose, c);
        c.gridx = 3;
        rows.add(clearButton, c);
    }

    private void choose() {
        File start = !files.isEmpty() ? files.getFirst().toFile().getParentFile()
                : dbDir != null && Files.isDirectory(dbDir) ? dbDir.toFile() : new File(System.getProperty("user.home"));
        var chooser = new JFileChooser(start);
        chooser.setDialogTitle(I18n.text("database.chooser.title"));
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("database.chooser.filter"), "zip"));
        var help = new JLabel(I18n.text("database.chooser.help"));
        help.setVerticalAlignment(SwingConstants.TOP);
        chooser.setAccessory(help);
        if (chooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION)
            set(Arrays.stream(chooser.getSelectedFiles()).map(File::toPath).toList());
    }

    private void set(List<Path> chosen) {
        files.clear();
        files.addAll(chosen);
        settings.set(Settings.DATABASES, chosen.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        updateField();
        onChange.run();
    }

    private void restore() {
        String saved = settings.get(Settings.DATABASES, "");
        if (!saved.isBlank())
            Arrays.stream(saved.split(Pattern.quote(File.pathSeparator))).map(Path::of).filter(Files::isRegularFile).forEach(files::add);
    }

    private void updateField() {
        boolean none = files.isEmpty();
        field.setText(none ? I18n.text("toolbar.database.none") : files.stream().map(Path::toString).collect(Collectors.joining("  ;  ")));
        field.setForeground(none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        field.setCaretPosition(0);
        clearButton.setEnabled(!none);
    }
}
