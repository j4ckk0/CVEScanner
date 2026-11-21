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
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The VEX documents a scan reads besides the folder's own *.vex.json: chosen once, kept in the settings, used from the
 * next scan. Their not_affected and false_positive statements set findings aside, in the Ignored tab.
 */
final class VexDocuments {

    private final Component owner;
    private final I18nLabels labels;
    private final Settings settings;
    private final Supplier<Path> scanFolder;
    private final JTextField field = new JTextField(40);
    private final JButton noneButton = new JButton();
    private final List<Path> files = new ArrayList<>();

    /** @param given those the command line named (--vex), else the ones the settings keep */
    VexDocuments(Component owner, I18nLabels labels, Settings settings, List<Path> given, Supplier<Path> scanFolder) {
        this.owner = owner;
        this.labels = labels;
        this.settings = settings;
        this.scanFolder = scanFolder;
        if (!given.isEmpty()) files.addAll(given);
        else {
            String saved = settings.get(Settings.VEX_FILES, "");
            if (!saved.isBlank())
                Arrays.stream(saved.split(Pattern.quote(File.pathSeparator))).map(Path::of).filter(Files::isRegularFile).forEach(files::add);
        }
        labels.on(this::updateField);
    }

    /** The documents chosen, for Engine.scan (ScanOptions.vexFiles). */
    List<Path> files() {
        return List.copyOf(files);
    }

    /** Its row of the toolbar, at the row the constraints are set to. */
    void addRow(JPanel rows, GridBagConstraints c) {
        var choose = labels.text(new JButton(), "toolbar.chooseVex");
        choose.addActionListener(_ -> choose());
        labels.text(noneButton, "toolbar.noVex");
        noneButton.addActionListener(_ -> set(List.of()));
        field.setEditable(false);
        c.gridx = 0;
        rows.add(labels.text(new JLabel(), "toolbar.vex"), c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(field, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(choose, c);
        c.gridx = 3;
        rows.add(noneButton, c);
    }

    private void choose() {
        Path start = !files.isEmpty() && files.getFirst().getParent() != null ? files.getFirst().getParent() : scanFolder.get();
        var chooser = new JFileChooser(start.toFile());
        chooser.setDialogTitle(I18n.text("vex.chooser.title"));
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("vex.chooser.filter"), "json"));
        if (chooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION)
            set(Arrays.stream(chooser.getSelectedFiles()).map(File::toPath).toList());
    }

    private void set(List<Path> chosen) {
        files.clear();
        files.addAll(chosen);
        settings.set(Settings.VEX_FILES, chosen.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        updateField();
    }

    private void updateField() {
        boolean none = files.isEmpty();
        field.setText(none ? I18n.text("toolbar.vex.folderOnly")
                : I18n.text("toolbar.vex.chosen", String.join("  ;  ", files.stream().map(Path::toString).toList())));
        field.setForeground(none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        field.setCaretPosition(0);
        noneButton.setEnabled(!none);
    }
}
