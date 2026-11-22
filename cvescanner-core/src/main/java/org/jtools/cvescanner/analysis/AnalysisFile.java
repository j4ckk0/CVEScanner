package org.jtools.cvescanner.analysis;

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Reach;
import org.jtools.cvescanner.cvss.Requirement;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;

/**
 * A scan kept in a file, to be opened on another computer that cannot reach the folder scanned: a zip holding
 * analysis.json, the dependencies found, those that could not be checked, the findings with their CVSS data, the ignore
 * file's entries and the VEX statements, the databases read and the warnings. Opened, it is the scan as it was; matched
 * again there (Engine.recheck), it is the same dependencies checked against that computer's databases.
 */
public final class AnalysisFile {
    private AnalysisFile() {}

    /** The extension the window's choosers and the command line know an analysis file by. */
    public static final String EXTENSION = ".cvescan";
    static final String ENTRY = "analysis.json";
    static final String FORMAT = "cvescanner-analysis";
    /** The version of the format this program writes; a file of a later one is refused, its fields perhaps not these. */
    static final int FORMAT_VERSION = 1;
    /** The most analysis.json is read of: a scan of thousands of dependencies takes some MB. */
    static final long MAX_SIZE = 256L << 20;

    /** Whether this path names an analysis file, by its extension. */
    public static boolean named(Path p) {
        return p != null && p.getFileName() != null && p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(EXTENSION);
    }

    /** The name proposed for a scan's file: its folder's and the day, "my-app-2026-11-23.cvescan". */
    public static String defaultName(ScanResult r, Clock clock) {
        String folder = r.imported() != null ? folderName(r.imported().root()) : r.root().getFileName() == null ? "analysis"
                : r.root().getFileName().toString();
        return folder + "-" + java.time.LocalDate.now(clock) + EXTENSION;
    }

    /**
     * Writes the scan, the file replaced when there is one, with the environment and the CVSS version its findings are
     * scored for: where it is opened, they are shown as here.
     */
    public static void write(ScanResult r, Path file, Environment environment, boolean preferV4) throws IOException {
        write(r, file, environment, preferV4, Instant.now());
    }

    static void write(ScanResult r, Path file, Environment environment, boolean preferV4, Instant now) throws IOException {
        var m = new LinkedHashMap<String, Object>();
        m.put("format", FORMAT);
        m.put("formatVersion", FORMAT_VERSION);
        m.put("program", version());
        m.put("exportedAt", now.toString());
        // an analysis opened here, passed on: where it was made, and when
        var from = r.imported();
        m.put("root", from != null ? from.root() : r.root().toString());
        if (from != null && from.exportedAt() != null) m.put("firstExportedAt", from.exportedAt().toString());
        m.put("rechecked", from != null && from.rechecked());
        var scoring = new LinkedHashMap<String, Object>();
        scoring.put("environment", environment.key());
        scoring.put("reach", environment.reach().name());
        scoring.put("confidentiality", environment.confidentiality().name());
        scoring.put("integrity", environment.integrity().name());
        scoring.put("availability", environment.availability().name());
        scoring.put("preferV4", preferV4);
        m.put("scoring", scoring);
        m.put("mode", r.mode().name());
        m.put("directOnly", r.directOnly());
        m.put("gradleLocked", r.gradleLocked());
        m.put("mavenRepository", r.mavenRepository() == null ? null : r.mavenRepository().toString());
        m.put("gradleCache", r.gradleCache() == null ? null : r.gradleCache().toString());
        m.put("fileCounts", r.fileCounts());
        var databases = new LinkedHashMap<String, Object>();
        r.snapshots().forEach((name, said) -> databases.put(name, AnalysisJson.phrase(said)));
        m.put("databases", databases);
        m.put("warnings", r.warnings().stream().map(AnalysisJson::phrase).toList());
        var ignores = new LinkedHashMap<String, Object>();
        ignores.put("shown", r.ignores().shown());
        ignores.put("read", r.ignores().read());
        ignores.put("rules", r.ignores().rules().stream().map(AnalysisJson::rule).toList());
        ignores.put("vex", r.ignores().vex().stream().map(AnalysisJson::statement).toList());
        m.put("ignores", ignores);
        m.put("dependencies", r.dependencies().stream().map(AnalysisJson::dependency).toList());
        m.put("unresolved", r.unresolved().stream().map(AnalysisJson::unresolved).toList());
        m.put("findings", r.findings().stream().map(AnalysisJson::finding).toList());
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Path partial = file.resolveSibling(file.getFileName() + ".part");   // a file half written is never taken for one
        try (OutputStream out = Files.newOutputStream(partial); var zip = new ZipOutputStream(out)) {
            zip.putNextEntry(new ZipEntry(ENTRY));
            zip.write(Json.write(m).getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        } catch (IOException e) {
            Files.deleteIfExists(partial);
            throw e;
        }
        Files.move(partial, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * The scan an analysis file holds, ScanResult.imported saying where from. Its ignore entries are kept, the file
     * they were read from not: it is on the other computer.
     *
     * @throws IOException when it is not an analysis file, a later program's, or damaged; the message says which
     */
    public static ScanResult read(Path file) throws IOException {
        return read(file, MAX_SIZE);
    }

    static ScanResult read(Path file, long maxSize) throws IOException {
        String shown = file.getFileName() == null ? file.toString() : file.getFileName().toString();
        Map<String, Object> m;
        try (var zip = new ZipFile(file.toFile())) {
            ZipEntry entry = zip.getEntry(ENTRY);
            if (entry == null) throw new IOException(I18n.text("analysisFile.notOne", shown));
            m = Json.obj(Json.parse(text(zip, entry, shown, maxSize)));
        } catch (ZipException e) {
            throw new IOException(I18n.text("analysisFile.notOne", shown));
        } catch (IllegalArgumentException e) {   // Json's
            throw new IOException(I18n.text("analysisFile.damaged", shown, e.getMessage()));
        }
        if (!FORMAT.equals(m.get("format"))) throw new IOException(I18n.text("analysisFile.notOne", shown));
        long version = AnalysisJson.whole(m, "formatVersion");
        if (version > FORMAT_VERSION)
            throw new IOException(I18n.text("analysisFile.newer", shown, Json.str(m, "program") == null ? "?" : Json.str(m, "program")));
        try {
            return result(m, file);
        } catch (AnalysisJson.Malformed | DateTimeParseException | ClassCastException e) {
            throw new IOException(I18n.text("analysisFile.damaged", shown, e.getMessage()));
        }
    }

    private static String text(ZipFile zip, ZipEntry entry, String shown, long maxSize) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            var out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1 << 16];
            long total = 0;
            for (int n; (n = in.read(buffer)) > 0; ) {
                total += n;
                if (total > maxSize) throw new IOException(I18n.text("analysisFile.tooLarge", shown, Math.max(1, maxSize >> 20)));
                out.write(buffer, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private static ScanResult result(Map<String, Object> m, Path file) {
        String rootText = AnalysisJson.required(m, "root");
        var dependencies = Json.arr(m.get("dependencies")).stream().map(AnalysisJson::dependency).toList();
        var unresolved = Json.arr(m.get("unresolved")).stream().map(AnalysisJson::unresolved).toList();
        var findings = Json.arr(m.get("findings")).stream().map(AnalysisJson::finding).toList();
        var databases = new LinkedHashMap<String, Phrase>();
        Json.obj(m.get("databases")).forEach((name, said) -> databases.put(name, AnalysisJson.phrase(said)));
        var counts = new LinkedHashMap<String, Integer>();
        Json.obj(m.get("fileCounts")).forEach((kind, n) -> counts.put(kind, n instanceof Number number ? number.intValue() : 0));
        var warnings = Json.arr(m.get("warnings")).stream().map(AnalysisJson::phrase).toList();
        var i = Json.obj(m.get("ignores"));
        var ignores = new Ignores(null, Json.str(i, "shown") == null ? "" : Json.str(i, "shown"),
                Json.arr(i.get("rules")).stream().map(AnalysisJson::rule).toList(), AnalysisJson.flag(i, "read"),
                Json.arr(i.get("vex")).stream().map(AnalysisJson::statement).toList());
        String first = AnalysisJson.text(m, "firstExportedAt");
        Instant exported = Instant.parse(first != null ? first : AnalysisJson.required(m, "exportedAt"));
        var s = m.get("scoring") == null ? null : Json.obj(m.get("scoring"));
        Environment environment = s == null ? null : Environment.of(AnalysisJson.enumOf(Reach.class, AnalysisJson.required(s, "reach")),
                AnalysisJson.enumOf(Requirement.class, AnalysisJson.required(s, "confidentiality")),
                AnalysisJson.enumOf(Requirement.class, AnalysisJson.required(s, "integrity")),
                AnalysisJson.enumOf(Requirement.class, AnalysisJson.required(s, "availability")));
        var imported = new ScanResult.Imported(file.toAbsolutePath().normalize().toString(), exported,
                AnalysisJson.text(m, "program"), rootText, AnalysisJson.flag(m, "rechecked"), environment,
                s == null || !Boolean.FALSE.equals(s.get("preferV4")));
        return new ScanResult(path(rootText, folderName(rootText)), findings, dependencies, unresolved, databases, counts, warnings,
                ignores, AnalysisJson.enumOf(ScanMode.class, AnalysisJson.required(m, "mode")),
                path(AnalysisJson.text(m, "mavenRepository"), null), path(AnalysisJson.text(m, "gradleCache"), null),
                AnalysisJson.flag(m, "gradleLocked"), AnalysisJson.flag(m, "directOnly"), imported);
    }

    /** A path the other computer wrote, as this one can hold it; else the one given. */
    private static Path path(String text, String otherwise) {
        if (text == null) return otherwise == null ? null : Path.of(otherwise);
        try {
            return Path.of(text);
        } catch (InvalidPathException e) {
            return otherwise == null ? null : Path.of(otherwise);
        }
    }

    /** The last name of a path, whichever system wrote it. */
    static String folderName(String path) {
        var names = new ArrayList<String>(List.of(path.split("[/\\\\]")));
        names.removeIf(String::isBlank);
        String last = names.isEmpty() ? "analysis" : names.getLast();
        return last.replaceAll("[^\\w.-]", "_");
    }

    /** The program's version, as its module or its jar's manifest says it; null when run from the classes. */
    private static String version() {
        Module module = AnalysisFile.class.getModule();
        if (module.isNamed() && module.getDescriptor().rawVersion().isPresent()) return module.getDescriptor().rawVersion().get();
        return AnalysisFile.class.getPackage().getImplementationVersion();
    }
}
