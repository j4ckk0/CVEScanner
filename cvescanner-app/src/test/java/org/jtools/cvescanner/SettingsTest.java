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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SettingsTest {

    @TempDir
    Path folder;

    @Test
    void aSettingIsKeptBesideTheProgramForTheNextTime() {
        Settings.in(folder).set(Settings.LOOK, "javax.swing.plaf.metal.MetalLookAndFeel");
        assertTrue(Files.isRegularFile(folder.resolve("cvescanner.properties")));
        assertEquals("javax.swing.plaf.metal.MetalLookAndFeel", Settings.in(folder).get(Settings.LOOK, "none"));
    }

    @Test
    void clearedTheyAreForgottenTheirFileLeftEmpty() throws IOException {
        var settings = Settings.in(folder.resolve("not yet made"));
        settings.set(Settings.LANGUAGE, "en");
        assertTrue(Files.isRegularFile(settings.file()), "its folder made at the first setting");
        settings.clear();
        assertEquals("the default", Settings.in(folder.resolve("not yet made")).get(Settings.LANGUAGE, "the default"),
                "an empty file left: an old one beside the program is not taken over again");
        assertEquals("the default", settings.get(Settings.LANGUAGE, "the default"));
        settings.set(Settings.LOOK, "x");
        assertEquals("the default", Settings.in(folder.resolve("not yet made")).get(Settings.LANGUAGE, "the default"), "not written back");
    }

    @Test
    void theUsersFolderIsTheSystemsOwn() {
        Path user = Settings.userFolder();
        assertTrue(user.endsWith("cvescanner") || user.endsWith("CVEScanner"), user.toString());
    }

    @Test
    void untilOneIsSetNothingIsWritten() {
        assertEquals("the default", Settings.in(folder).get(Settings.LOOK, "the default"));
        assertFalse(Files.exists(folder.resolve("cvescanner.properties")));
    }

    @Test
    void aFolderThatCannotBeWrittenInKeepsNothingAndIsNoError() throws IOException {
        Path locked = Files.createDirectory(folder.resolve("locked"));
        if (!Files.getFileStore(locked).supportsFileAttributeView("posix")) {
            return;   // Windows: no POSIX permissions to take away
        }
        Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("r-xr-xr-x"));
        try {
            Settings settings = Settings.in(locked);
            settings.set(Settings.LOOK, "javax.swing.plaf.metal.MetalLookAndFeel");
            assertEquals("javax.swing.plaf.metal.MetalLookAndFeel", settings.get(Settings.LOOK, "none"), "held");
            assertFalse(Files.exists(locked.resolve("cvescanner.properties")));
        } finally {
            Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
    }
}
