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
import javax.swing.JComponent;
import javax.swing.JTextArea;
import javax.swing.UIManager;

final class Gui {
    private Gui() {}

    static void installLookAndFeel() {
        try {
            String system = UIManager.getSystemLookAndFeelClassName();
            if (system.contains("Metal")) {
                for (var info : UIManager.getInstalledLookAndFeels())
                    if (info.getName().equals("Nimbus")) { UIManager.setLookAndFeel(info.getClassName()); return; }
            }
            UIManager.setLookAndFeel(system);
        } catch (Exception _) { /* keep the default look and feel */ }
    }

    static String hex(Color c) { return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue()); }

    /** Text as HTML shows it, every character that could open a tag or end an attribute escaped. */
    static String html(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    /**
     * A message as plain text, for a dialog: a string given to Swing as it is would be read as HTML should it begin
     * with <html>, and a file name or an advisory may.
     */
    static JTextArea plain(String text) {
        var area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(false);
        area.setBorder(null);
        area.setFont(UIManager.getFont("Label.font"));
        return area;
    }

    /** A label that shows its text as it is, never as HTML (see plain). */
    static <T extends JComponent> T noHtml(T component) {
        component.putClientProperty("html.disable", Boolean.TRUE);
        return component;
    }
}
