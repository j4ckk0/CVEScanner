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
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;

/**
 * The entry point: the window, in the look chosen (View ▸ Look; FlatLaf Light until one is), or with --no-gui (or no
 * display) the command line. Both speak the language --lang asks for, else the one chosen in the window (Settings),
 * else French.
 */
public final class Launcher {

    private Launcher() {
    }

    /**
     * The program's version: its module's, linked into the distributions' runtime image, or its jar's manifest's on
     * the class path; null when it runs from its classes.
     */
    static String version() {
        Module module = Launcher.class.getModule();
        if (module.isNamed() && module.getDescriptor().rawVersion().isPresent()) {
            return module.getDescriptor().rawVersion().get();
        }
        return Launcher.class.getPackage().getImplementationVersion();
    }

    public static void main(String[] args) {
        Settings settings = Settings.load();
        I18nLanguage requested = Options.requestedLanguage(args);
        I18n.use(requested != null ? requested : I18nLanguage.ofCode(settings.get(Settings.LANGUAGE, I18nLanguage.DEFAULT.code())));
        MainWindow.useSwingLocale();
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println(I18n.text("cli.error", e.getMessage()));
            System.err.println(Options.usage());
            System.exit(1);
            return;
        }
        if (opts.help) {
            System.out.println(Options.usage());
            return;
        }
        if (opts.noGui || GraphicsEnvironment.isHeadless()) {
            System.exit(Cli.run(opts));
        }
        SwingUtilities.invokeLater(() -> {
            Looks.use(settings.get(Settings.LOOK, Looks.DEFAULT));
            new MainWindow(opts, settings).setVisible(true);
        });
    }
}
