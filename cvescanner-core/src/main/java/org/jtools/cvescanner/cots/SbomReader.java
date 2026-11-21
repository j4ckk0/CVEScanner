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

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.project.Collector;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * The components a software bill of materials lists: CycloneDX JSON (bom.json, *.cdx.json, its components and theirs)
 * and SPDX JSON (*.spdx.json, its packages). A component with a Maven or npm package URL (purl) is checked as the
 * project's own Maven or npm dependencies are; one with a CPE, or with a name only, as a component off-the-shelf.
 */
public final class SbomReader {

    private SbomReader() {
    }

    public static void scan(List<Path> sboms, Collector col, Consumer<Phrase> warn) {
        for (Path file : sboms) {
            try {
                var root = Json.obj(Json.parse(ProjectFiles.readText(file)));
                if (root.containsKey("spdxVersion")) {
                    for (Object p : Json.arr(root.get("packages"))) spdxPackage(Json.obj(p), file, col);
                } else {
                    for (Object c : Json.arr(root.get("components"))) cycloneDxComponent(Json.obj(c), file, col, 0);
                }
            } catch (IOException | RuntimeException e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(file), e.getMessage()));
            }
        }
    }

    private static void cycloneDxComponent(Map<String, Object> c, Path file, Collector col, int depth) {
        component(text(c.get("name")), text(c.get("version")), text(c.get("purl")), text(c.get("cpe")), file, col);
        if (depth < 16) {
            for (Object child : Json.arr(c.get("components"))) cycloneDxComponent(Json.obj(child), file, col, depth + 1);
        }
    }

    private static void spdxPackage(Map<String, Object> p, Path file, Collector col) {
        String purl = "", cpe = "";
        for (Object o : Json.arr(p.get("externalRefs"))) {
            var ref = Json.obj(o);
            String type = text(ref.get("referenceType")), locator = text(ref.get("referenceLocator"));
            if (type.equals("purl") && purl.isEmpty() && !locator.isEmpty()) purl = locator;
            if ((type.equals("cpe23Type") || type.equals("cpe22Type")) && cpe.isEmpty() && locator.startsWith("cpe:2.3:")) cpe = locator;
        }
        String version = text(p.get("versionInfo"));
        component(text(p.get("name")), version.equals("NOASSERTION") ? "" : version, purl, cpe, file, col);
    }

    /** A component, its identity from its purl first (Maven, npm), then its CPE, then its name. */
    private static void component(String name, String version, String purl, String cpe, Path file, Collector col) {
        if (purl.startsWith("pkg:maven/") || purl.startsWith("pkg:npm/")) {
            Purl p = Purl.parse(purl);
            String v = version.isEmpty() ? p.version() : version;
            String ecosystem = p.type().equals("maven") ? "Maven" : "npm";
            String id = p.type().equals("maven") ? p.namespace() + ":" + p.name()
                    : p.namespace().isEmpty() ? p.name() : p.namespace() + "/" + p.name();
            if (v.isEmpty()) col.miss(ecosystem, id, "", file, Phrase.of("reason.noVersion"));
            else col.add(ecosystem, id, v, file, "sbom", false);
            return;
        }
        String id;
        String v = version;
        if (cpe.startsWith("cpe:2.3:")) {
            String[] f = Cpe.fields(cpe);
            id = f[3] + ":" + f[4];
            if (v.isEmpty() && !f[5].equals("*") && !f[5].equals("-")) v = f[5];
        } else if (!name.isEmpty()) {
            id = KnownProducts.identify(name);
        } else {
            return;
        }
        if (v.isEmpty()) col.miss("COTS", id, "", file, Phrase.of("reason.noVersion"));
        else col.add("COTS", id, v, file, "sbom", false);
    }

    private static String text(Object o) {
        return o instanceof String s ? s.strip() : "";
    }

    /** A package URL's parts: pkg:type/namespace/name@version, percent-decoded (%40angular is @angular). */
    record Purl(String type, String namespace, String name, String version) {
        static Purl parse(String purl) {
            String rest = purl.substring("pkg:".length());
            int cut = indexOfAny(rest, "?#");
            if (cut >= 0) rest = rest.substring(0, cut);
            String version = "";
            int at = rest.lastIndexOf('@');
            if (at > rest.indexOf('/')) {
                version = decode(rest.substring(at + 1));
                rest = rest.substring(0, at);
            }
            int slash = rest.indexOf('/');
            String type = rest.substring(0, Math.max(slash, 0));
            String path = rest.substring(slash + 1);
            int last = path.lastIndexOf('/');
            String namespace = last < 0 ? "" : decode(path.substring(0, last));
            return new Purl(type, namespace, decode(path.substring(last + 1)), version);
        }

        private static int indexOfAny(String s, String chars) {
            for (int i = 0; i < s.length(); i++) if (chars.indexOf(s.charAt(i)) >= 0) return i;
            return -1;
        }

        /** Percent-decoding, as a purl's parts are encoded; a malformed escape is kept as written. */
        private static String decode(String s) {
            var bytes = new ByteArrayOutputStream();
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '%' && i + 2 < s.length()
                        && Character.digit(s.charAt(i + 1), 16) >= 0 && Character.digit(s.charAt(i + 2), 16) >= 0) {
                    bytes.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                    i += 2;
                } else {
                    byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                    bytes.write(b, 0, b.length);
                }
            }
            return bytes.toString(StandardCharsets.UTF_8);
        }
    }
}
