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

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

/** The folders scanned last, newest first, kept in the settings: a ▾ button beside the folder lists them to scan again. */
final class RecentFolders {

    static final int KEPT = 8;

    private final Settings settings;
    private final JButton button = new JButton("▾");

    /** @param chosen given the folder picked in the list */
    RecentFolders(I18nLabels labels, Settings settings, Consumer<Path> chosen) {
        this.settings = settings;
        button.setName("recentFolders");   // for the window test (WindowDriver)
        labels.tip(button, "toolbar.recentFolders");
        button.addActionListener(_ -> {
            var menu = new JPopupMenu();
            for (Path folder : folders()) {
                var item = new JMenuItem(folder.toString());
                item.addActionListener(_ -> chosen.accept(folder));
                menu.add(item);
            }
            menu.show(button, 0, button.getHeight());
        });
        update();
    }

    JButton button() {
        return button;
    }

    /** The folders kept that are still there, newest first. */
    List<Path> folders() {
        String kept = settings.get(Settings.RECENT_FOLDERS, "");
        if (kept.isBlank()) return List.of();
        return Arrays.stream(kept.split(Pattern.quote(File.pathSeparator))).map(Path::of).filter(Files::isDirectory).toList();
    }

    /** This folder first in the list, once. */
    void scanned(Path folder) {
        var list = new ArrayList<>(folders());
        Path normal = folder.toAbsolutePath().normalize();
        list.remove(normal);
        list.addFirst(normal);
        settings.set(Settings.RECENT_FOLDERS, list.stream().limit(KEPT).map(Path::toString).collect(Collectors.joining(File.pathSeparator)));
        update();
    }

    private void update() {
        button.setEnabled(!folders().isEmpty());
    }
}
