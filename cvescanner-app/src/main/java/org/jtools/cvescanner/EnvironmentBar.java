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
import java.awt.FlowLayout;
import java.awt.Insets;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.jtools.cvescanner.cli.Options;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.i18n.I18n;

/**
 * Where the scanned software runs and which CVSS version to prefer: a preset or the reach and requirements one by one.
 * The choice is the command line's when it gives one, else the one kept in the settings, and is kept again at each
 * change; the window then scores the findings anew (onChange), without a new scan.
 */
final class EnvironmentBar {

    private final Component owner;
    private final I18nLabels labels;
    private final Settings settings;
    private final Runnable onChange;
    private final JComboBox<Environment> envCombo = new JComboBox<>();
    private final JComboBox<Reach> reachCombo = new JComboBox<>(Reach.values());
    private final JComboBox<Requirement> crCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> irCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Requirement> arCombo = new JComboBox<>(Requirement.values());
    private final JComboBox<Choice<Boolean>> cvssCombo = new JComboBox<>(List.of(
            new Choice<>("environment.cvss4First", true), new Choice<>("environment.cvss3First", false)).toArray(Choice[]::new));
    private Environment environment = Environment.NONE;
    private boolean preferV4 = true;
    /** Standard mode: the CVSS version's choice hidden, 4.0 first whatever was chosen. */
    private boolean standard;
    /** Set while the controls are made to show the choice: their own events then change nothing. */
    private boolean updating;

    EnvironmentBar(Component owner, I18nLabels labels, Settings settings, Options opts, Runnable onChange) {
        this.owner = owner;
        this.labels = labels;
        this.settings = settings;
        this.onChange = onChange;
        restore(opts);
        labels.on(() -> List.of(cvssCombo, envCombo, reachCombo, crCombo, irCombo, arCombo).forEach(Component::repaint));
    }

    Environment environment() {
        return environment;
    }

    boolean preferV4() {
        return standard || preferV4;
    }

    /** Standard mode: the CVSS version's choice hidden, 4.0 first; the choice kept for expert mode. */
    void standard(boolean on) {
        standard = on;
        cvssCombo.setVisible(!on);
    }

    JPanel panel() {
        var p = new JPanel(new WrapLayout(FlowLayout.LEFT, 10, 8));
        p.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 8));
        Environment.PRESETS.forEach(envCombo::addItem);
        labels.tip(envCombo, "environment.preset.tip");
        labels.tip(reachCombo, "environment.reach.tip");
        for (var c : List.of(crCombo, irCombo, arCombo)) labels.tip(c, "environment.requirement.tip");
        labels.tip(cvssCombo, "environment.cvss.tip");
        cvssCombo.setName("cvss");   // for the window test (WindowDriver)
        var help = new JButton("?");
        help.setMargin(new Insets(1, 6, 1, 6));
        help.addActionListener(_ -> JOptionPane.showMessageDialog(owner, new JLabel(I18n.text("environment.help")),
                I18n.text("environment.help.title"), JOptionPane.INFORMATION_MESSAGE));
        envCombo.addActionListener(_ -> {
            if (updating || !(envCombo.getSelectedItem() instanceof Environment e) || e.key().equals(Environment.CUSTOM)) return;
            setEnvironment(e);
        });
        for (var c : List.<JComboBox<?>>of(reachCombo, crCombo, irCombo, arCombo))
            c.addActionListener(_ -> {
                if (!updating)
                    setEnvironment(Environment.of((Reach) reachCombo.getSelectedItem(), (Requirement) crCombo.getSelectedItem(),
                            (Requirement) irCombo.getSelectedItem(), (Requirement) arCombo.getSelectedItem()));
            });
        cvssCombo.addActionListener(_ -> {
            if (!updating && cvssCombo.getSelectedItem() instanceof Choice<?> choice) {
                preferV4 = (Boolean) choice.value();
                changed();
            }
        });
        p.add(labels.text(new JLabel(), "environment.label"));
        p.add(envCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(labels.text(new JLabel(), "environment.reachable"));
        p.add(reachCombo);
        p.add(labels.text(new JLabel(), "environment.confidentiality"));
        p.add(crCombo);
        p.add(labels.text(new JLabel(), "environment.integrity"));
        p.add(irCombo);
        p.add(labels.text(new JLabel(), "environment.availability"));
        p.add(arCombo);
        p.add(Box.createHorizontalStrut(8));
        p.add(cvssCombo);
        p.add(help);
        labels.on(this::sync);   // once the presets are in the list, to select the one chosen
        return p;
    }

    private void setEnvironment(Environment e) {
        environment = e;
        sync();
        changed();
    }

    private void changed() {
        save();
        onChange.run();
    }

    /** The controls showing the choice: a custom environment gets its entry in the presets' list. */
    private void sync() {
        updating = true;
        try {
            if (environment.key().equals(Environment.CUSTOM)) {
                boolean present = false;
                for (int i = 0; i < envCombo.getItemCount(); i++) present |= envCombo.getItemAt(i).key().equals(Environment.CUSTOM);
                if (!present) envCombo.addItem(new Environment(Environment.CUSTOM, Reach.UNRESTRICTED,
                        Requirement.NOT_DEFINED, Requirement.NOT_DEFINED, Requirement.NOT_DEFINED));
                for (int i = 0; i < envCombo.getItemCount(); i++) if (envCombo.getItemAt(i).key().equals(Environment.CUSTOM)) envCombo.setSelectedIndex(i);
            } else {
                envCombo.setSelectedItem(environment);
            }
            reachCombo.setSelectedItem(environment.reach());
            crCombo.setSelectedItem(environment.confidentiality());
            irCombo.setSelectedItem(environment.integrity());
            arCombo.setSelectedItem(environment.availability());
            cvssCombo.setSelectedIndex(preferV4 ? 0 : 1);
        } finally {
            updating = false;
        }
    }

    private void restore(Options opts) {
        if (opts.environmentGiven) environment = opts.environment;
        else {
            try {
                String key = settings.get(Settings.ENVIRONMENT, "none");
                if (key.equals(Environment.CUSTOM)) {
                    environment = Environment.of(Reach.valueOf(settings.get(Settings.REACH, "UNRESTRICTED")),
                            Requirement.valueOf(settings.get(Settings.CONFIDENTIALITY, "NOT_DEFINED")),
                            Requirement.valueOf(settings.get(Settings.INTEGRITY, "NOT_DEFINED")),
                            Requirement.valueOf(settings.get(Settings.AVAILABILITY, "NOT_DEFINED")));
                } else {
                    environment = Environment.preset(key);
                }
            } catch (RuntimeException _) { environment = Environment.NONE; }   // a value of another version: the default
        }
        preferV4 = opts.cvssGiven ? opts.preferV4 : Boolean.parseBoolean(settings.get(Settings.PREFER_CVSS4, "true"));
    }

    private void save() {
        settings.set(Settings.ENVIRONMENT, environment.key());
        settings.set(Settings.REACH, environment.reach().name());
        settings.set(Settings.CONFIDENTIALITY, environment.confidentiality().name());
        settings.set(Settings.INTEGRITY, environment.integrity().name());
        settings.set(Settings.AVAILABILITY, environment.availability().name());
        settings.set(Settings.PREFER_CVSS4, Boolean.toString(preferV4));
    }
}
