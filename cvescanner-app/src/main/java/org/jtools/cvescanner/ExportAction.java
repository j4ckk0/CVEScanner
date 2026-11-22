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
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.report.Reports;

/**
 * File ▸ Export: the reports of the findings shown (the filters applied) written into a folder chosen, the folder
 * then shown, to copy: the program starts no other one, a file manager no more than a browser.
 */
final class ExportAction {

    private ExportAction() {}

    static void run(Component owner, Path outDir, ScanResult result, Ignores.Split split, FindingTables tables,
                    EnvironmentBar environmentBar, StatusLine status) {
        if (result == null) return;
        var chooser = new JFileChooser(outDir.toAbsolutePath().toFile());
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        var visible = tables.shownFindings();
        int total = tables.allFindings().size();
        chooser.setDialogTitle(I18n.text("export.chooser.title", visible.size()));
        chooser.setApproveButtonText(I18n.text("export.chooser.approve"));
        if (chooser.showSaveDialog(owner) != JFileChooser.APPROVE_OPTION) return;
        boolean filtered = visible.size() != total;
        try {
            var written = Reports.writeAll(result, split.withActive(visible), chooser.getSelectedFile().toPath(),
                    filtered ? List.of(Phrase.of("export.filter", visible.size(), total)) : List.of(),
                    environmentBar.environment(), environmentBar.preferV4(), I18n.language(), tables.facets().hideTransitive());
            String folder = chooser.getSelectedFile().getAbsolutePath();
            int choice = JOptionPane.showOptionDialog(owner,
                    SwingText.plain(I18n.text("export.done", written.stream().map(Path::toString).collect(Collectors.joining("\n")))),
                    I18n.text("export.done.title"), JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null,
                    new Object[]{I18n.text("export.copyFolder"), I18n.text("export.ok")}, I18n.text("export.ok"));
            if (choice == 0) {
                Clipboard.copy(folder);
                status.say(() -> I18n.text("export.folderCopied", folder));
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(owner, SwingText.plain(e.getMessage()), I18n.text("export.failed.title"), JOptionPane.ERROR_MESSAGE);
        }
    }
}
