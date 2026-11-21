package org.jtools.cvescanner.project;

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


import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.jtools.cvescanner.i18n.Phrase;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

// ----------------------------------------------------------------------------------------------- Maven
public final class MavenScanner {
    private static final Pattern PROP = Pattern.compile("\\$\\{([^}]+)\\}");

    record PomDep(String group, String artifact, String version, String scope) {}

    static final class Pom {
        final Path path;
        String groupId, artifactId, version;
        String[] parent;   // groupId, artifactId, version, relativePath
        final Map<String, String> props = new HashMap<>();
        final List<PomDep> deps = new ArrayList<>(), managed = new ArrayList<>();

        Pom(Path path) { this.path = path.toAbsolutePath().normalize(); }
    }

    private MavenScanner() {}

    /**
     * The program's only XML parser, set to fetch nothing: a pom.xml of a scanned repository could name a DTD or an
     * external entity, which a parser left as it is would fetch, from the network or a file (README, "No network").
     * A POM has no DOCTYPE, so one is refused; nothing outside the file is read even should that check give way.
     */
    static DocumentBuilder pomParser() {
        try {
            var f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            var builder = f.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("external entity refused: " + systemId);
            });
            builder.setErrorHandler(new DefaultHandler());
            return builder;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void scan(List<Path> paths, Collector col, Consumer<Phrase> warn) {
        DocumentBuilder builder = pomParser();
        var poms = new ArrayList<Pom>();
        for (Path p : paths) {
            try {
                poms.add(parse(p, builder.parse(p.toFile()).getDocumentElement()));
            } catch (Exception e) {
                warn.accept(Phrase.of("warning.skipped", col.rel(p), e.getMessage()));
            }
        }
        var index = new PomIndex(poms);
        for (Pom pom : poms) {
            var entries = new ArrayList<Map.Entry<PomDep, Boolean>>();
            pom.deps.forEach(d -> entries.add(Map.entry(d, false)));
            pom.managed.stream().filter(d -> !"import".equals(d.scope())).forEach(d -> entries.add(Map.entry(d, true)));
            for (var e : entries) {
                PomDep d = e.getKey();
                boolean managed = e.getValue();
                String g = index.resolve(pom, d.group()), a = index.resolve(pom, d.artifact());
                if (g == null || a == null) continue;
                String name = g + ":" + a;
                String raw = d.version() != null ? d.version() : managed ? null : index.managedVersion(pom, g, a);
                String scope = managed ? "dependencyManagement" : d.scope();
                if (raw == null) {
                    col.miss("Maven", name, "", pom.path, Phrase.of("reason.managedOutside"));
                    continue;
                }
                String v = index.resolve(pom, raw);
                if (v.contains("${")) col.miss("Maven", name, raw, pom.path, Phrase.of("reason.unresolvedProperty"));
                else if (v.startsWith("[") || v.startsWith("(")) col.miss("Maven", name, raw, pom.path, Phrase.of("reason.versionRange"));
                else col.add("Maven", name, v, pom.path, scope, false);
            }
        }
    }

    private static String local(Node n) { return n.getLocalName() != null ? n.getLocalName() : n.getNodeName(); }

    private static Element child(Element el, String name) {
        for (Node n = el.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e && name.equals(local(e))) return e;
        return null;
    }

    private static String text(Element el, String name) {
        Element c = child(el, name);
        if (c == null) return null;
        String t = c.getTextContent().strip();
        return t.isEmpty() ? null : t;
    }

    private static Pom parse(Path path, Element root) {
        var pom = new Pom(path);
        Element parent = child(root, "parent");
        if (parent != null) {
            Element rel = child(parent, "relativePath");
            pom.parent = new String[]{text(parent, "groupId"), text(parent, "artifactId"), text(parent, "version"),
                    rel == null ? "../pom.xml" : rel.getTextContent().strip()};
        }
        pom.groupId = Objects.requireNonNullElse(text(root, "groupId"), pom.parent != null ? Objects.toString(pom.parent[0], "") : "");
        pom.artifactId = text(root, "artifactId");
        pom.version = text(root, "version") != null ? text(root, "version") : pom.parent != null ? pom.parent[2] : null;

        Element mainProps = child(root, "properties");
        readProps(mainProps, pom.props, true);
        var all = root.getElementsByTagNameNS("*", "properties");
        for (int k = 0; k < all.getLength(); k++)              // profile properties as a fallback
            if (all.item(k) != mainProps) readProps((Element) all.item(k), pom.props, false);

        walk(root, new ArrayDeque<>(), pom);
        return pom;
    }

    private static void readProps(Element props, Map<String, String> into, boolean override) {
        if (props == null) return;
        for (Node n = props.getFirstChild(); n != null; n = n.getNextSibling())
            if (n instanceof Element e) {
                if (override) into.put(local(e), e.getTextContent().strip());
                else into.putIfAbsent(local(e), e.getTextContent().strip());
            }
    }

    private static void walk(Element el, Deque<String> ancestors, Pom pom) {
        for (Node n = el.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (!(n instanceof Element c)) continue;
            String tag = local(c);
            if (tag.equals("dependency")) {
                String scope = Objects.requireNonNullElse(text(c, "scope"), "compile");
                if (ancestors.contains("dependencyManagement")) {
                    pom.managed.add(new PomDep(text(c, "groupId"), text(c, "artifactId"), text(c, "version"), scope));
                } else {
                    pom.deps.add(new PomDep(text(c, "groupId"), text(c, "artifactId"), text(c, "version"),
                            ancestors.contains("plugin") ? "plugin" : scope));
                }
            } else if (!tag.equals("properties")) {
                ancestors.push(tag);
                walk(c, ancestors, pom);
                ancestors.pop();
            }
        }
    }

    private static final class PomIndex {
        private final Map<String, Pom> byCoordinates = new HashMap<>();
        private final Map<Path, Pom> byPath = new HashMap<>();

        PomIndex(List<Pom> poms) {
            for (Pom p : poms) {
                byCoordinates.put(p.groupId + ":" + p.artifactId, p);
                byPath.put(p.path, p);
            }
        }

        Pom parentOf(Pom pom) {
            if (pom.parent == null) return null;
            Pom cand = byCoordinates.get(pom.parent[0] + ":" + pom.parent[1]);
            if (cand != null && cand != pom) return cand;
            String rel = pom.parent[3];
            if (rel == null || rel.isEmpty()) return null;
            Path p = pom.path.getParent().resolve(rel).normalize();
            if (Files.isDirectory(p)) p = p.resolve("pom.xml");
            cand = byPath.get(p);
            return cand != pom ? cand : null;
        }

        List<Pom> chain(Pom pom) {
            var out = new ArrayList<Pom>();
            for (Pom p = pom; p != null && !out.contains(p); p = parentOf(p)) out.add(p);
            return out;
        }

        String property(Pom pom, String key) {
            for (Pom p : chain(pom)) if (p.props.containsKey(key)) return p.props.get(key);
            return switch (key) {
                case "project.version", "pom.version", "version" -> pom.version;
                case "project.groupId", "pom.groupId", "groupId" -> pom.groupId;
                case "project.artifactId" -> pom.artifactId;
                case "project.parent.version" -> pom.parent == null ? null : pom.parent[2];
                case "project.parent.groupId" -> pom.parent == null ? null : pom.parent[0];
                default -> null;
            };
        }

        String resolve(Pom pom, String s) {
            if (s == null) return null;
            for (int k = 0; k < 10; k++) {
                String next = PROP.matcher(s).replaceAll(m -> {
                    String v = property(pom, m.group(1));
                    return Matcher.quoteReplacement(v != null ? v : m.group());
                });
                if (next.equals(s)) break;
                s = next;
            }
            return s;
        }

        String managedVersion(Pom pom, String g, String a) {
            for (Pom p : chain(pom))
                for (PomDep d : p.managed)
                    if (d.version() != null && g.equals(resolve(p, d.group())) && a.equals(resolve(p, d.artifact())))
                        return d.version();
            return null;
        }
    }
}
