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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.swing.ButtonGroup;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import org.jtools.cvescanner.engine.ScanOptions;
import org.jtools.cvescanner.i18n.I18n;

/** The View menu: the look the window is shown in, and how old a database may be before a scan says so. */
final class ViewMenu {

    private static final String LOOK_CLASS = "lookClass";   // each look item's class, as a client property

    private final JFrame frame;
    private final I18nLabels labels;
    private final Settings settings;
    private final Runnable lookChanged;
    private final List<JRadioButtonMenuItem> lookItems = new ArrayList<>();

    /** @param lookChanged run once the window is shown in another look (the colours that depend on it) */
    ViewMenu(JFrame frame, I18nLabels labels, Settings settings, Runnable lookChanged) {
        this.frame = frame;
        this.labels = labels;
        this.settings = settings;
        this.lookChanged = lookChanged;
    }

    JMenu menu() {
        JMenu view = labels.menu(new JMenu(), "menu.view");
        view.add(lookMenu());
        JMenuItem age = labels.menu(new JMenuItem(), "menu.view.dbMaxAge");
        age.addActionListener(_ -> chooseDbMaxAge());
        view.add(age);
        return view;
    }

    /** The days past which a database's newest record is said to be old, as the settings keep it; 30 when not set. */
    int dbMaxAge() {
        try {
            return Math.max(0, Integer.parseInt(settings.get(Settings.DB_MAX_AGE, String.valueOf(ScanOptions.DEFAULT_DB_MAX_AGE_DAYS))));
        } catch (NumberFormatException _) {
            return ScanOptions.DEFAULT_DB_MAX_AGE_DAYS;
        }
    }

    /** View ▸ Database age: how old a database may be before a scan says so, kept for the next time. */
    private void chooseDbMaxAge() {
        var days = new JSpinner(new SpinnerNumberModel(dbMaxAge(), 0, 3650, 1));
        var panel = new JPanel(new BorderLayout(0, 6));
        panel.add(new JLabel(I18n.text("dbMaxAge.label")), BorderLayout.NORTH);
        panel.add(days, BorderLayout.CENTER);
        if (JOptionPane.showConfirmDialog(frame, panel, I18n.text("dbMaxAge.title"), JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION)
            settings.set(Settings.DB_MAX_AGE, days.getValue().toString());
    }

    /**
     * View ▸ Look: FlatLaf's looks, light and dark, and those Java has here — the system's, Nimbus, Metal… —, the one
     * chosen kept for the next time (Settings), the window shown in it at once.
     */
    private JMenu lookMenu() {
        JMenu menu = labels.menu(new JMenu(), "menu.look");
        String current = currentLook();
        String system = UIManager.getSystemLookAndFeelClassName();
        List<UIManager.LookAndFeelInfo> installed = new ArrayList<>(List.of(UIManager.getInstalledLookAndFeels()));
        // FlatLaf's first, then the system's, then the others as Java lists them
        installed.sort(Comparator.comparingInt((UIManager.LookAndFeelInfo look) ->
                look.getClassName().startsWith("com.formdev.flatlaf") ? 0
                        : look.getClassName().equals(system) ? 1 : 2));
        ButtonGroup looks = new ButtonGroup();
        for (UIManager.LookAndFeelInfo look : installed) {
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(look.getName(), look.getClassName().equals(current));
            if (look.getClassName().equals(system)) {
                labels.on(() -> item.setText(I18n.text("menu.look.system", look.getName())));
            }
            item.putClientProperty(LOOK_CLASS, look.getClassName());
            item.addActionListener(_ -> applyLook(look.getClassName()));
            looks.add(item);
            lookItems.add(item);
            menu.add(item);
        }
        return menu;
    }

    private static String currentLook() {
        return UIManager.getLookAndFeel().getClass().getName();
    }

    /** Shows the window in this look, keeps it for the next time, and says so in the menu. */
    void applyLook(String className) {
        Looks.use(className);
        SwingUtilities.updateComponentTreeUI(frame);
        lookChanged.run();
        settings.set(Settings.LOOK, currentLook());
        for (JRadioButtonMenuItem item : lookItems) {
            item.setSelected(currentLook().equals(item.getClientProperty(LOOK_CLASS)));
        }
    }
}
