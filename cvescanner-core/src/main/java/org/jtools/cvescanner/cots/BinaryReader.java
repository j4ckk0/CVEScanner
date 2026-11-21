package org.jtools.cvescanner.cots;

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

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.DependencyCollector;

/**
 * The components off-the-shelf a project carries as binaries: a Windows DLL or EXE named by its version resource
 * (PeVersionInfo: "FFmpeg" 4.4.2), else by its file name (gdal304.dll, avcodec-58.dll, libgdal.so.30, ffmpeg-4.4.2.exe).
 * A file name gives a version only when it spells one out (name-1.2.3), shown approximate; an ABI number (avcodec-58,
 * libgdal.so.30) is not the product's version, and such a binary is unchecked. Only binaries KnownProducts names are
 * reported — not every DLL of a folder —, and one product's binaries of a folder count once.
 */
public final class BinaryReader {

    /** A file name's stem and the version it spells out: ffmpeg-4.4.2, libpng16-1.6.37. */
    private static final Pattern NAMED_VERSION = Pattern.compile("(.+?)[-_](\\d+(?:\\.\\d+){1,3})");
    /** What follows a library's name and is not its version: an ABI number, an architecture. */
    private static final Pattern TRAILER = Pattern.compile("(?:[-_.]?(?:x64|x86|amd64|arm64|win32|win64|\\d+(?:[._]\\d+)*))+$");
    private static final Pattern VERSION = Pattern.compile("\\d+(?:[.,]\\s*\\d+){1,3}");

    private BinaryReader() {
    }

    public static void scan(List<Path> binaries, DependencyCollector col) {
        Set<String> seen = new HashSet<>();   // product, version, folder: once each
        for (Path file : binaries) {
            String fileName = file.getFileName().toString();
            String lower = fileName.toLowerCase(Locale.ROOT);
            String id = null, version = null;
            boolean approximate = false;
            if (lower.endsWith(".dll") || lower.endsWith(".exe")) {
                var info = PeVersionInfo.read(file).orElse(null);
                if (info != null && info.productName() != null && KnownProducts.isKnown(info.productName())) {
                    id = KnownProducts.identify(info.productName());
                    version = version(info.productVersion() != null ? info.productVersion() : info.fileVersion());
                }
            }
            String stem = lower.replaceFirst("\\.(dll|exe|dylib)$", "").replaceFirst("\\.so(\\.\\d+)*$", "");
            if (id == null) {
                Matcher named = NAMED_VERSION.matcher(stem);
                if (named.matches() && known(named.group(1)) != null) {
                    id = known(named.group(1));
                    version = named.group(2);
                    approximate = true;
                } else {
                    id = known(TRAILER.matcher(stem).replaceFirst(""));
                }
            }
            if (id == null) continue;
            Path folder = file.getParent();
            if (!seen.add(id + "|" + version + "|" + folder)) continue;
            if (version == null) col.miss(Ecosystem.COTS, id, "", file, Phrase.of("reason.noBinaryVersion"));
            else col.add(Ecosystem.COTS, id, version, file, "binary", approximate);
        }
    }

    /** The component a binary's stem names, with or without its "lib"; null when none is known. */
    private static String known(String stem) {
        if (stem.isEmpty()) return null;
        if (KnownProducts.isKnown(stem)) return KnownProducts.identify(stem);
        if (stem.startsWith("lib") && KnownProducts.isKnown(stem.substring(3))) return KnownProducts.identify(stem.substring(3));
        if (KnownProducts.isKnown("lib" + stem)) return KnownProducts.identify("lib" + stem);
        return null;
    }

    /** A version resource's version as dotted numbers: "3, 4, 1, 0" is 3.4.1.0; null when it holds none. */
    static String version(String text) {
        if (text == null) return null;
        Matcher m = VERSION.matcher(text);
        return m.find() ? m.group().replaceAll(",\\s*", ".") : null;
    }
}
