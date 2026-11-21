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


import java.awt.GraphicsEnvironment;
import javax.swing.SwingUtilities;
import org.jtools.cvescanner.cli.Cli;
import org.jtools.cvescanner.cli.Options;

public final class Launcher {
    public static void main(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("ERROR: " + e.getMessage());
            System.err.println(Options.USAGE);
            System.exit(1);
            return;
        }
        if (opts.help) {
            System.out.println(Options.USAGE);
            return;
        }
        if (opts.noGui || GraphicsEnvironment.isHeadless()) {
            System.exit(Cli.run(opts));
        }
        SwingUtilities.invokeLater(() -> {
            Gui.installLookAndFeel();
            new MainWindow(opts).setVisible(true);
        });
    }
}
