package org.jtools.cvescanner.installed;

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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.DependencyCollector;

/**
 * The Maven artifacts an installed product ships, read from its jars, WARs and EARs: each META-INF/maven/…/pom.properties
 * names one (a shaded jar names several), and the jars inside (a fat jar's BOOT-INF/lib, a WAR's WEB-INF/lib, an
 * EAR's modules) are read in turn, nothing extracted to disk. A jar is not trusted for being one: what is read is
 * bounded, and a jar that cannot be read is said and passed over.
 */
public final class JarReader {

    private static final Pattern POM_PROPERTIES = Pattern.compile("META-INF/maven/[^/]+/[^/]+/pom\\.properties");
    private static final Pattern FILE_NAME = Pattern.compile("(.+?)-(\\d[\\w.+-]*)\\.(?:jar|war|ear)");
    private static final int MAX_DEPTH = 3, MAX_ENTRIES = 200_000, MAX_SMALL_FILE = 64 * 1024;

    private JarReader() {}

    public static void scan(List<Path> jars, DependencyCollector col, Consumer<Phrase> warn) {
        for (Path jar : jars) {
            try (InputStream in = Files.newInputStream(jar)) {
                read(new ZipInputStream(in), col.rel(jar), jar.getFileName().toString(), 0, col);
            } catch (IOException | RuntimeException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(jar), e.getMessage()));
            }
        }
    }

    /**
     * A jar's artifacts, then those of the jars inside it. One holding no coordinates and no jar is an artifact
     * CVEScanner cannot check: said, with what its manifest or its file name tells of it.
     *
     * @param shown the jar as the findings name it: "app.jar", "app.jar!/BOOT-INF/lib/x.jar"
     */
    private static void read(ZipInputStream zip, String shown, String name, int depth, DependencyCollector col) throws IOException {
        boolean coordinates = false, nested = false;
        Manifest manifest = null;
        int entries = 0;
        for (ZipEntry e; (e = zip.getNextEntry()) != null; ) {
            if (++entries > MAX_ENTRIES) throw new IOException("more than " + MAX_ENTRIES + " entries");
            String n = e.getName();
            if (POM_PROPERTIES.matcher(n).matches()) {
                var p = new Properties();
                p.load(new StringReader(new String(small(zip), StandardCharsets.ISO_8859_1)));
                String g = p.getProperty("groupId"), a = p.getProperty("artifactId"), v = p.getProperty("version");
                if (g != null && a != null && v != null && !g.isBlank() && !a.isBlank() && !v.isBlank()) {
                    col.add(Ecosystem.MAVEN, g.strip() + ":" + a.strip(), v.strip(), shown, "installed", false);
                    coordinates = true;
                }
            } else if (n.equals("META-INF/MANIFEST.MF")) {
                manifest = new Manifest(new ByteArrayInputStream(small(zip)));
            } else if (depth < MAX_DEPTH && !e.isDirectory() && isArchive(n)) {
                nested = true;
                read(new ZipInputStream(new KeepOpen(zip)), shown + "!/" + n, n.substring(n.lastIndexOf('/') + 1), depth + 1, col);
            }
        }
        if (entries == 0) throw new IOException("not a zip archive");
        if (!coordinates && !nested) unchecked(manifest, shown, name, col);
    }

    private static void unchecked(Manifest manifest, String shown, String name, DependencyCollector col) {
        String title = null, version = null;
        if (manifest != null) {
            var a = manifest.getMainAttributes();
            title = first(a.getValue("Bundle-SymbolicName"), a.getValue("Implementation-Title"));
            version = first(a.getValue("Bundle-Version"), a.getValue("Implementation-Version"));
        }
        Matcher m = FILE_NAME.matcher(name);
        if (title == null) title = m.matches() ? m.group(1) : name;
        if (version == null && m.matches()) version = m.group(2);
        col.miss(Ecosystem.MAVEN, title.split(";")[0].strip(), version, shown, Phrase.of("reason.jarNoCoordinates"));
    }

    private static boolean isArchive(String entry) {
        String n = entry.toLowerCase(java.util.Locale.ROOT);
        return n.endsWith(".jar") || n.endsWith(".war");
    }

    private static String first(String a, String b) {
        return a != null && !a.isBlank() ? a : b != null && !b.isBlank() ? b : null;
    }

    /** The current entry, a small file (pom.properties, MANIFEST.MF): at most 64 KiB of it. */
    private static byte[] small(InputStream in) throws IOException {
        return in.readNBytes(MAX_SMALL_FILE);
    }

    /** A jar inside a jar, read from its entry: closing it must not close the jar around it. */
    private static final class KeepOpen extends FilterInputStream {
        KeepOpen(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // the outer jar's stream stays open: its next entries are still to be read
        }
    }
}
