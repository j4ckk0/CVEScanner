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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The folders scanned last, and the folder a drop on the window gives. */
class RecentFoldersTest {

    @TempDir
    Path dir;

    @Test
    void theLastFoldersScannedNewestFirstOnceEachThoseGoneLeftOut() throws IOException {
        var settings = Settings.in(Files.createDirectories(dir.resolve("program")));
        var folders = new ArrayList<Path>();
        for (int i = 0; i < RecentFolders.KEPT + 2; i++) folders.add(Files.createDirectories(dir.resolve("p" + i)));
        var recent = new RecentFolders(new I18nLabels(), settings, _ -> { });
        assertFalse(recent.button().isEnabled(), "nothing scanned yet");
        recent.scanned(folders.get(0));
        recent.scanned(folders.get(1));
        recent.scanned(folders.get(0));
        assertEquals(List.of(folders.get(0), folders.get(1)), recent.folders());
        assertTrue(recent.button().isEnabled());
        for (Path p : folders) recent.scanned(p);
        assertEquals(RecentFolders.KEPT, recent.folders().size());
        assertEquals(folders.getLast(), recent.folders().getFirst());
        Files.delete(folders.getLast());
        assertEquals(RecentFolders.KEPT - 1, new RecentFolders(new I18nLabels(), settings, _ -> { }).folders().size(), "a folder gone, left out");
    }

    @Test
    void aDropGivesAFolderAFileItsFolder() throws IOException {
        Path folder = Files.createDirectories(dir.resolve("my project"));
        Path file = Files.writeString(folder.resolve("pom.xml"), "<project/>");
        assertEquals(Optional.of(folder), FolderDrop.folder(files(folder)));
        assertEquals(Optional.of(folder), FolderDrop.folder(files(file)));
        assertEquals(Optional.of(folder), FolderDrop.fromUriList("# from a file manager\r\n" + folder.toUri() + "\r\n"));
        assertEquals(Optional.empty(), FolderDrop.fromUriList("https://example.org/\r\n"));
        assertEquals(Path.of("/srv/café"), FolderDrop.filePath("file://localhost/srv/caf%C3%A9"));
        assertEquals(Path.of("/srv/a b"), FolderDrop.filePath("file:/srv/a%20b"));
    }

    private static Transferable files(Path p) {
        return new Transferable() {
            public DataFlavor[] getTransferDataFlavors() { return new DataFlavor[] {DataFlavor.javaFileListFlavor}; }
            public boolean isDataFlavorSupported(DataFlavor f) { return f.equals(DataFlavor.javaFileListFlavor); }
            public Object getTransferData(DataFlavor f) { return List.of(p.toFile()); }
        };
    }
}
