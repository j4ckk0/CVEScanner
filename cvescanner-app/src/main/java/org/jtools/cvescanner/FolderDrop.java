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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import javax.swing.TransferHandler;
import org.jtools.cvescanner.analysis.AnalysisFile;

/**
 * A folder dropped on the window: scanned. A file dropped stands for its folder. File managers give a file list, or on
 * Linux the text/uri-list of file: addresses.
 */
final class FolderDrop extends TransferHandler {

    private static final DataFlavor URI_LIST = uriList();
    private final Consumer<Path> dropped;

    FolderDrop(Consumer<Path> dropped) {
        this.dropped = dropped;
    }

    @Override
    public boolean canImport(TransferSupport support) {
        return support.isDrop() && (support.isDataFlavorSupported(DataFlavor.javaFileListFlavor)
                || URI_LIST != null && support.isDataFlavorSupported(URI_LIST));
    }

    @Override
    public boolean importData(TransferSupport support) {
        if (!canImport(support)) return false;
        Optional<Path> folder = folder(support.getTransferable());
        folder.ifPresent(dropped);
        return folder.isPresent();
    }

    /** The folder a drop gives: its first entry, a file's folder for a file; an analysis file itself (AnalysisFile). */
    static Optional<Path> folder(Transferable t) {
        try {
            Path first = null;
            if (t.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                List<?> files = (List<?>) t.getTransferData(DataFlavor.javaFileListFlavor);
                if (!files.isEmpty() && files.getFirst() instanceof File f) first = f.toPath();
            } else if (URI_LIST != null && t.isDataFlavorSupported(URI_LIST)) {
                first = fromUriList((String) t.getTransferData(URI_LIST)).orElse(null);
            }
            if (first == null) return Optional.empty();
            if (AnalysisFile.named(first) && Files.isRegularFile(first)) return Optional.of(first);   // opened, not its folder scanned
            return Optional.of(Files.isDirectory(first) ? first : first.getParent()).filter(Files::isDirectory);
        } catch (Exception _) {   // a drop that cannot be read: nothing scanned
            return Optional.empty();
        }
    }

    /** The first file: address of a text/uri-list, its comment lines (#) left out. */
    static Optional<Path> fromUriList(String list) {
        return list.lines().map(String::strip).filter(l -> l.startsWith("file:")).findFirst().map(FolderDrop::filePath);
    }

    /**
     * A file: address's path, its host (none, localhost) left out and its %XX decoded; read by hand, java.net being
     * what the program does without (NoNetworkTest). file:///C:/… is C:/… on Windows.
     */
    static Path filePath(String address) {
        String rest = address.substring("file:".length());
        if (rest.startsWith("//")) {
            int slash = rest.indexOf('/', 2);
            rest = slash < 0 ? "/" : rest.substring(slash);
        }
        var bytes = new ByteArrayOutputStream();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '%' && i + 2 < rest.length()) {
                bytes.write(Integer.parseInt(rest.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                bytes.writeBytes(String.valueOf(c).getBytes(StandardCharsets.UTF_8));
            }
        }
        String path = bytes.toString(StandardCharsets.UTF_8);
        return Path.of(path.matches("/[A-Za-z]:.*") ? path.substring(1) : path);
    }

    private static DataFlavor uriList() {
        try {
            return new DataFlavor("text/uri-list;class=java.lang.String");
        } catch (ClassNotFoundException _) {
            return null;
        }
    }
}
