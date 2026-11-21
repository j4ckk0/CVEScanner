package org.jtools.cvescanner.ignore;

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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * A CycloneDX VEX document (*.vex.json): its vulnerabilities' analyses, each for the packages it affects, named by
 * their package URL or by a component's bom-ref. Read as data: a statement that cannot be tied to a package is said
 * and left out, a document that is not CycloneDX JSON is said and read as none.
 */
public final class VexFile {

    /** Larger than any VEX a product team writes: a file past it is not read. */
    private static final long MAX_SIZE = 64L * 1024 * 1024;

    private VexFile() {}

    /** Whether a file name is a VEX document's: *.vex.json, *.vex.cdx.json. */
    public static boolean isVex(String fileName) {
        String n = fileName.toLowerCase(java.util.Locale.ROOT);
        return n.endsWith(".vex.json") || n.endsWith(".vex.cdx.json");
    }

    public static List<VexStatement> read(Path file, String shown, Consumer<Phrase> warn) throws IOException {
        if (Files.size(file) > MAX_SIZE) {
            warn.accept(Phrase.of("vex.warning.tooLarge", shown));
            return List.of();
        }
        Map<String, Object> doc;
        try {
            doc = Json.obj(Json.parse(ProjectFiles.readText(file)));
        } catch (IllegalArgumentException e) {
            warn.accept(Phrase.of("vex.warning.notJson", shown, e.getMessage()));
            return List.of();
        }
        if (!"CycloneDX".equals(Json.str(doc, "bomFormat"))) {
            warn.accept(Phrase.of("vex.warning.notCycloneDx", shown));
            return List.of();
        }
        var purls = new HashMap<String, String>();   // bom-ref → purl, of the document's components
        for (Object c : Json.arr(doc.get("components"))) {
            var component = Json.obj(c);
            String ref = Json.str(component, "bom-ref"), purl = Json.str(component, "purl");
            if (ref != null && purl != null) purls.put(ref, purl);
        }
        var out = new ArrayList<VexStatement>();
        for (Object v : Json.arr(doc.get("vulnerabilities"))) {
            var vuln = Json.obj(v);
            String id = Json.str(vuln, "id");
            var analysis = Json.obj(vuln.get("analysis"));
            String state = Json.str(analysis, "state");
            if (id == null || id.isBlank() || state == null) continue;   // nothing stated
            String justification = Json.str(analysis, "justification"), detail = Json.str(analysis, "detail");
            var affects = Json.arr(vuln.get("affects"));
            if (affects.isEmpty()) {   // stated of the product as a whole: every package
                out.add(new VexStatement(id, "", "", state, justification, detail, shown));
                continue;
            }
            for (Object a : affects) {
                String ref = Json.str(Json.obj(a), "ref");
                String purl = ref == null ? null : ref.startsWith("pkg:") ? ref : purls.get(ref);
                String[] pkg = purl == null ? null : fromPurl(purl);
                if (pkg == null) {
                    warn.accept(Phrase.of("vex.warning.unknownRef", shown, id, ref == null ? "—" : ref));
                    continue;
                }
                out.add(new VexStatement(id, pkg[0], pkg[1], state, justification, detail, shown));
            }
        }
        return out;
    }

    /**
     * A package URL as CVEScanner names the package: pkg:maven/g/a@1.0 → g:a and 1.0, pkg:npm/%40scope/name@1.0 →
     * @scope/name, pkg:pypi/name, pkg:generic/product; null for one it cannot read.
     */
    static String[] fromPurl(String purl) {
        String p = purl;
        int hash = p.indexOf('#'), query = p.indexOf('?');
        if (hash >= 0) p = p.substring(0, hash);
        if (query >= 0) p = p.substring(0, query);
        if (!p.startsWith("pkg:")) return null;
        p = p.substring(4);
        int slash = p.indexOf('/');
        if (slash <= 0) return null;
        String type = p.substring(0, slash).toLowerCase(java.util.Locale.ROOT), rest = p.substring(slash + 1);
        String version = "";
        int at = rest.lastIndexOf('@');
        if (at >= 0) {
            version = decode(rest.substring(at + 1));
            rest = rest.substring(0, at);
        }
        int last = rest.lastIndexOf('/');
        String namespace = last < 0 ? "" : decode(rest.substring(0, last)), name = decode(rest.substring(last + 1));
        if (name.isEmpty()) return null;
        String pkg = switch (type) {
            case "maven" -> namespace.isEmpty() ? name : namespace + ":" + name;
            case "npm" -> namespace.isEmpty() ? name : namespace + "/" + name;
            default -> name;   // pypi, generic, and the others: the name
        };
        return new String[]{pkg, version};
    }

    /** A purl segment's percent-encoding undone (%40 is @, %2B is +), as UTF-8; a broken escape kept as written. */
    static String decode(String s) {
        var bytes = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); ) {
            int c = s.codePointAt(i);
            if (c == '%' && isHex(s, i + 1) && isHex(s, i + 2)) {
                bytes.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 3;
            } else {
                byte[] b = Character.toString(c).getBytes(StandardCharsets.UTF_8);
                bytes.write(b, 0, b.length);
                i += Character.charCount(c);
            }
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static boolean isHex(String s, int i) {
        return i < s.length() && Character.digit(s.charAt(i), 16) >= 0;
    }
}
