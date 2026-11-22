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
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreFile;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.ScanResult;

/**
 * The window's ignore file: which one is read (the folder's own, one chosen, none), Ignore… and Stop ignoring, which
 * write it. Once the file is read again the window sets its findings apart anew (Host.reread), without a new scan.
 */
final class IgnoreActions {

    /** What the window gives: the scan shown, its findings as set apart now, what to do once the file is read again. */
    interface Host {
        ScanResult result();

        Ignores.Split split();

        /** The file was read again: the findings are to be set apart anew; these are the warnings of reading it. */
        void reread(List<Phrase> warnings);

        /** The ignore entries an analysis from another computer carries: the folder's own file, which is there. */
        Ignores carried();

        void say(Supplier<String> message);
    }

    private final Component owner;
    private final I18nLabels labels;
    private final Host host;
    private final Supplier<Path> scanFolder;
    private final JTextField field = new JTextField(40);
    private final JButton ownButton = new JButton();
    /** The ignore file to read: null for the folder's own, Ignores.DISABLED for none (Engine.scan). */
    private Path choice;
    /** Standard mode: the row hidden, the folder's own file read whatever was chosen. */
    private boolean standard;
    private final List<Component> row = new ArrayList<>();
    /** The ignore file in use, the scan's or the one chosen since; read again after the window writes it. */
    private Ignores ignores = Ignores.NONE;

    IgnoreActions(Component owner, I18nLabels labels, Host host, Path choice, Supplier<Path> scanFolder) {
        this.owner = owner;
        this.labels = labels;
        this.host = host;
        this.choice = choice;
        this.scanFolder = scanFolder;
        labels.on(this::updateField);
    }

    /** The file a scan is to read (Engine.scan): in standard mode, the folder's own. */
    Path choice() {
        return standard ? null : choice;
    }

    /** Standard mode: the row hidden, the folder's own file read from the next scan; the choice kept for expert mode. */
    void standard(boolean on) {
        standard = on;
        row.forEach(c -> c.setVisible(!on));
    }

    Ignores ignores() {
        return ignores;
    }

    /** The ignore file a scan read. */
    void scanned(Ignores read) {
        ignores = read;
    }

    /** Its row of the toolbar, at the row the constraints are set to. */
    void addRow(JPanel rows, GridBagConstraints c) {
        var choose = labels.text(new JButton(), "toolbar.chooseIgnoreFile");
        choose.addActionListener(_ -> choose());
        choose.setName("ignoreChoose");   // for the window test (WindowDriver)
        labels.text(ownButton, "toolbar.ownIgnoreFile");
        ownButton.addActionListener(_ -> setChoice(null));
        field.setEditable(false);
        var label = labels.text(new JLabel(), "toolbar.ignoreFile");
        row.addAll(List.of(label, field, choose, ownButton));
        c.gridx = 0;
        rows.add(label, c);
        c.gridx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        rows.add(field, c);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.gridx = 2;
        rows.add(choose, c);
        c.gridx = 3;
        rows.add(ownButton, c);
    }

    private void choose() {
        Path start = choice != null && choice.getParent() != null ? choice.getParent() : scanFolder.get();
        var chooser = new JFileChooser(start.toFile());
        chooser.setDialogTitle(I18n.text("ignore.chooser.title"));
        chooser.setFileFilter(new FileNameExtensionFilter(I18n.text("ignore.chooser.filter"), "csv"));
        if (chooser.showOpenDialog(owner) == JFileChooser.APPROVE_OPTION) setChoice(chooser.getSelectedFile().toPath());
    }

    /** Reads this ignore file from now on: the findings shown are set apart again at once, without a new scan. */
    private void setChoice(Path file) {
        choice = file;
        updateField();
        var result = host.result();
        if (result == null) return;
        var warnings = new ArrayList<Phrase>();
        try {
            // an analysis from another computer: the folder's own file is there, its entries carried in the analysis
            Ignores read = file == null && result.imported() != null ? host.carried().withoutVex()
                    : Ignores.load(result.root(), file, warnings::add);
            ignores = read.withVex(ignores.vex());   // the VEX documents' stay
        } catch (IOException e) {
            failed(e);
            return;
        }
        host.reread(warnings);
        host.say(() -> I18n.text("ignore.applied", host.split().ignored().size()));
    }

    private void updateField() {
        boolean own = choice == null, none = Ignores.DISABLED.equals(choice);
        field.setText(own ? I18n.text("toolbar.ignoreFile.own", IgnoreFile.NAME)
                : none ? I18n.text("toolbar.ignoreFile.disabled") : choice.toString());
        field.setForeground(own || none ? Color.GRAY : UIManager.getColor("TextField.foreground"));
        field.setCaretPosition(0);
        ownButton.setEnabled(!own);
    }

    /** Asks how to set this finding aside, writes the entry, sets the findings apart again; false when nothing was written. */
    boolean ignore(Finding f) {
        if (noFile(I18n.text("ignore.dialog.title"))) return false;
        var rule = IgnoreDialog.ask(owner, f, ignores.file().toString(),
                r -> (int) host.split().active().stream().filter(r::matches).count());
        if (rule.isEmpty()) return false;
        try {
            IgnoreFile.append(ignores.file(), rule.get());
        } catch (IOException e) {
            failed(e);
            return false;
        }
        int before = host.split().ignored().size();
        reread();
        int added = host.split().ignored().size() - before;
        host.say(() -> I18n.text("ignore.done", added, ignores.shown()));
        return true;
    }

    /** Takes the entry setting this finding aside out of the file, after asking when it sets others aside too. */
    void stopIgnoring(IgnoredFinding i) {
        if (i.rule().fromVex()) {   // a VEX document is the product team's statement: changed there, not here
            JOptionPane.showMessageDialog(owner, SwingText.plain(I18n.text("ignore.stop.vex", i.rule().source())), I18n.text("ignore.stop.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        long others = host.split().ignored().stream().filter(x -> x.rule().equals(i.rule())).count() - 1;
        if (others > 0 && JOptionPane.showConfirmDialog(owner, SwingText.plain(I18n.text("ignore.stop.others", others, i.rule().line())),
                I18n.text("ignore.stop.title"), JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION)
            return;
        if (noFile(I18n.text("ignore.stop.title"))) return;
        boolean removed;
        try {
            removed = IgnoreFile.remove(ignores.file(), i.rule());
        } catch (IOException e) {
            failed(e);
            return;
        }
        if (!removed)
            JOptionPane.showMessageDialog(owner, SwingText.plain(I18n.text("ignore.stop.notFound", ignores.shown())), I18n.text("ignore.stop.title"),
                    JOptionPane.WARNING_MESSAGE);
        reread();
        if (removed) host.say(() -> I18n.text("ignore.stopped", others + 1));
    }

    /**
     * Whether there is no ignore file to write, said: none read (--no-ignore), or an analysis made on another computer,
     * whose file is there.
     */
    private boolean noFile(String title) {
        if (ignores.file() != null) return false;
        boolean imported = host.result() != null && host.result().imported() != null;
        JOptionPane.showMessageDialog(owner, SwingText.plain(I18n.text(imported ? "ignore.imported" : "ignore.disabled")), title,
                JOptionPane.INFORMATION_MESSAGE);
        return true;
    }

    /** The ignore file read again, once the window wrote it (or someone edited it), and the findings set apart again. */
    private void reread() {
        var warnings = new ArrayList<Phrase>();
        try {
            ignores = ignores.reload(warnings::add);
        } catch (IOException e) {
            failed(e);
        }
        host.reread(warnings);
    }

    private void failed(IOException e) {
        JOptionPane.showMessageDialog(owner, SwingText.plain(e.getMessage()), I18n.text("ignore.failed.title"), JOptionPane.ERROR_MESSAGE);
    }
}
