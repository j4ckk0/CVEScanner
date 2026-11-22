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
import java.awt.Dimension;
import java.awt.Font;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.i18n.I18n;

/**
 * The Help menu: the command line's options (its --help), where the preferences are kept, the program's licence, the
 * terms of the Java runtime it carries, and what the program is — its version, its home page. All of it read from the
 * program and its runtime: the home page is an address to copy, never opened, as the program reaches no network
 * (README, "No network").
 */
final class HelpMenu {

    /** Where the program lives, its sources and its releases. */
    static final String HOME_PAGE = "https://github.com/j4ckk0/CVEScanner";
    /** Where the runtime's builds come from, and its sources. */
    static final String TEMURIN_RELEASES = "https://adoptium.net/temurin/releases/";
    static final String OPENJDK_SOURCES = "https://github.com/openjdk/jdk25u";
    /** The program's licence, packed in it beside its classes (pom.xml). */
    private static final String LICENCE = "LICENSE";
    /** The licence of the runtime's base module, where every JDK keeps it: java.home/legal/java.base/LICENSE. */
    private static final List<String> RUNTIME_LICENCE = List.of("legal", "java.base", "LICENSE");
    private static final String JAVA_HOME = "java.home";
    private static final String JAVA_VERSION = "java.runtime.version";
    private static final String JAVA_VENDOR = "java.vendor";
    /** Between the paragraphs of a dialog's text. */
    private static final String PARAGRAPH = "\n\n";
    private static final int COLUMNS = 72;

    private final Component owner;
    private final Settings settings;

    private HelpMenu(Component owner, Settings settings) {
        this.owner = owner;
        this.settings = settings;
    }

    /** The menu, its dialogs over owner; its labels bound with these. */
    static JMenu of(Component owner, I18nLabels labels, Settings settings) {
        HelpMenu help = new HelpMenu(owner, settings);
        JMenu menu = labels.menu(new JMenu(), "menu.help");
        JMenuItem licence = labels.menu(new JMenuItem(), "menu.help.licence");
        licence.addActionListener(_ -> help.show("licence.title", licenceText(), licenceFile()));
        JMenuItem runtime = labels.menu(new JMenuItem(), "menu.help.runtime");
        runtime.addActionListener(_ -> help.show("runtime.title", runtimeText(), runtimeLicence()));
        JMenuItem commandLine = labels.menu(new JMenuItem(), "menu.help.commandLine");
        commandLine.setName("commandLineHelp");   // for the window test (WindowDriver)
        commandLine.addActionListener(_ -> help.show("commandLine.title", I18n.text("commandLine.intro"), Options.usage()));
        JMenuItem preferences = labels.menu(new JMenuItem(), "menu.help.preferences");
        preferences.setName("preferencesHelp");   // for the window test (WindowDriver)
        preferences.addActionListener(_ -> help.preferences());
        JMenuItem about = labels.menu(new JMenuItem(), "menu.help.about");
        about.addActionListener(_ -> help.show("about.title", aboutText(), null));
        menu.add(commandLine);
        menu.add(preferences);
        menu.addSeparator();
        menu.add(licence);
        menu.add(runtime);
        menu.addSeparator();
        menu.add(about);
        return menu;
    }

    /**
     * Help ▸ Preferences folder: where the settings are kept, the path to copy (the program opens no file manager, as it
     * opens no browser: NoNetworkTest), and the settings to clear, the defaults coming back at the next start.
     */
    private void preferences() {
        Path file = settings.file();
        String title = I18n.text("preferences.title");
        if (file == null) {
            JOptionPane.showMessageDialog(owner, content(I18n.text("preferences.none"), null), title, JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String folder = file.getParent().toString();
        Object[] options = {I18n.text("preferences.copy"), I18n.text("preferences.clear"), I18n.text("preferences.close")};
        int choice = JOptionPane.showOptionDialog(owner, content(I18n.text("preferences.where", folder, file.getFileName()), null), title,
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[2]);
        if (choice == 0) Clipboard.copy(folder);
        if (choice == 1 && JOptionPane.showConfirmDialog(owner, I18n.text("preferences.clear.confirm"), title, JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION) {
            try {
                settings.clear();
                JOptionPane.showMessageDialog(owner, I18n.text("preferences.cleared"), title, JOptionPane.INFORMATION_MESSAGE);
            } catch (java.io.IOException e) {
                JOptionPane.showMessageDialog(owner, SwingText.plain(e.getMessage()), title, JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /** The program's licence, said, then where its full text is. */
    static String licenceText() {
        return I18n.text("licence.intro") + PARAGRAPH + I18n.text("licence.files");
    }

    /** The runtime carried, its terms, and where its notices and its sources are. */
    static String runtimeText() {
        return I18n.text("runtime.which", System.getProperty(JAVA_VENDOR), System.getProperty(JAVA_VERSION),
                System.getProperty(JAVA_HOME))
                + PARAGRAPH + I18n.text("runtime.cpe")
                + PARAGRAPH + I18n.text("runtime.notices", TEMURIN_RELEASES, OPENJDK_SOURCES);
    }

    /** What the program is: its version, what it does, its licence, its home page, the runtime it runs on. */
    static String aboutText() {
        String version = Launcher.version();
        return (version == null ? I18n.text("about.version.classes") : I18n.text("about.version", version))
                + PARAGRAPH + I18n.text("about.description")
                + PARAGRAPH + I18n.text("about.licence")
                + PARAGRAPH + I18n.text("about.home", HOME_PAGE)
                + PARAGRAPH + I18n.text("about.java", System.getProperty(JAVA_VERSION),
                        System.getProperty(JAVA_VENDOR));
    }

    /** The full text of the program's licence, from inside the program; null when it is not there. */
    static String licenceFile() {
        try (InputStream in = HelpMenu.class.getResourceAsStream(LICENCE)) {
            return in == null ? null : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException _) {
            return null;
        }
    }

    /** The full text of the runtime's licence, from the runtime itself; null when it has none to read. */
    static String runtimeLicence() {
        Path file = Path.of(System.getProperty(JAVA_HOME), RUNTIME_LICENCE.toArray(String[]::new));
        try {
            return Files.isRegularFile(file) ? Files.readString(file, StandardCharsets.UTF_8) : null;
        } catch (IOException _) {
            return null;
        }
    }

    /** The dialog over the window, under the title of titleKey. */
    private void show(String titleKey, String text, String fullText) {
        JOptionPane.showMessageDialog(owner, content(text, fullText), I18n.text(titleKey),
                JOptionPane.INFORMATION_MESSAGE);
    }

    /** What a dialog shows: its text, then a text as written (a licence, the command line's options) if any (null: none). */
    static JPanel content(String text, String fullText) {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(area(text, false));
        if (fullText != null) {
            content.add(Box.createRigidArea(new Dimension(0, 8)));
            JScrollPane scroll = new JScrollPane(area(fullText, true));
            scroll.setPreferredSize(new Dimension(620, 320));
            scroll.setAlignmentX(Component.LEFT_ALIGNMENT);
            content.add(scroll);
        }
        return content;
    }

    /** Text to read and to select (an address to copy), not to change; a licence in a fixed font, as written. */
    private static JTextArea area(String text, boolean licence) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(licence);
        area.setLineWrap(!licence);
        area.setWrapStyleWord(true);
        area.setColumns(licence ? 0 : COLUMNS);
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        area.setCaretPosition(0);
        if (licence) {
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
        } else {
            // its width first: a wrapped text measures its height for the width it has, none before
            area.setSize(area.getPreferredSize().width, Short.MAX_VALUE);
        }
        return area;
    }
}
