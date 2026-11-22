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
import java.util.Optional;
import java.util.OptionalInt;
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
import org.jtools.cvescanner.model.Ecosystem;

public final class MavenReader {
    private static final Pattern PROP = Pattern.compile("\\$\\{([^}]+)\\}");

    /**
     * A dependency as a pom writes it, its texts unresolved.
     *
     * @param exclusions the "group:artifact" its own dependencies leave out, either part "*" for any
     * @param type "jar" unless written: an import of dependency management is a "pom"
     * @param scopeWritten whether the pom writes its scope: when not, a dependency takes its management's
     */
    record PomDep(String group, String artifact, String version, String scope, boolean optional, List<String> exclusions,
                  String type, boolean scopeWritten) {
        PomDep(String group, String artifact, String version, String scope) {
            this(group, artifact, version, scope, false, List.of(), "jar", true);
        }
    }

    static final class Pom {
        final Path path;
        String groupId, artifactId, version;
        String[] parent;   // groupId, artifactId, version, relativePath
        final Map<String, String> props = new HashMap<>();
        final List<PomDep> deps = new ArrayList<>(), managed = new ArrayList<>();
        /** The maven-compiler-plugin's release, target and source, as written: the Java the project is built for. */
        String compilerRelease, compilerTarget, compilerSource;

        Pom(Path path) { this.path = path.toAbsolutePath().normalize(); }
    }

    private MavenReader() {}

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

    public static void scan(List<Path> paths, DependencyCollector col, Consumer<Phrase> warn) {
        scan(paths, col, warn, null);
    }

    /**
     * The dependencies the poms declare and manage; with a local repository, their transitive dependencies too
     * (MavenTransitive), and a version an external parent or an imported BOM manages.
     *
     * @param repository the local Maven repository; null, the declared dependencies only
     */
    public static void scan(List<Path> paths, DependencyCollector col, Consumer<Phrase> warn, MavenRepository repository) {
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
        var transitive = repository == null ? null : new MavenTransitive(repository, index);
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
                if (raw == null && transitive != null && !managed) {   // managed by a parent or a BOM outside the folder
                    var m = transitive.model(pom).managed().get(name);
                    if (m != null) raw = m.version();
                }
                if (raw == null) {
                    col.miss(Ecosystem.MAVEN, name, "", pom.path, Phrase.of("reason.managedOutside"));
                    continue;
                }
                String v = index.resolve(pom, raw);
                if (v.contains("${") && transitive != null) v = transitive.model(pom).resolve(v);   // a parent's outside
                if (v.contains("${")) col.miss(Ecosystem.MAVEN, name, raw, pom.path, Phrase.of("reason.unresolvedProperty"));
                else if (v.startsWith("[") || v.startsWith("(")) col.miss(Ecosystem.MAVEN, name, raw, pom.path, Phrase.of("reason.versionRange"));
                else col.add(Ecosystem.MAVEN, name, v, pom.path, scope, false);
            }
            if (transitive != null) transitive.resolve(pom, col);
        }
        if (transitive != null) transitive.warnings().forEach(warn);
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

    static Pom parse(Path path, Element root) {
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
            if (tag.equals("plugin") && "maven-compiler-plugin".equals(text(c, "artifactId")) && child(c, "configuration") != null) {
                Element conf = child(c, "configuration");
                if (pom.compilerRelease == null) pom.compilerRelease = text(conf, "release");
                if (pom.compilerTarget == null) pom.compilerTarget = text(conf, "target");
                if (pom.compilerSource == null) pom.compilerSource = text(conf, "source");
            }
            if (tag.equals("dependency")) {
                String scope = Objects.requireNonNullElse(text(c, "scope"), "compile");
                boolean optional = "true".equalsIgnoreCase(text(c, "optional"));
                var exclusions = new ArrayList<String>();
                Element excl = child(c, "exclusions");
                if (excl != null)
                    for (Node x = excl.getFirstChild(); x != null; x = x.getNextSibling())
                        if (x instanceof Element e && local(e).equals("exclusion"))
                            exclusions.add(Objects.requireNonNullElse(text(e, "groupId"), "*") + ":" + Objects.requireNonNullElse(text(e, "artifactId"), "*"));
                String type = Objects.requireNonNullElse(text(c, "type"), "jar");
                boolean scopeWritten = text(c, "scope") != null;
                if (ancestors.contains("dependencyManagement")) {
                    pom.managed.add(new PomDep(text(c, "groupId"), text(c, "artifactId"), text(c, "version"), scope, optional,
                            List.copyOf(exclusions), type, scopeWritten));
                } else {
                    pom.deps.add(new PomDep(text(c, "groupId"), text(c, "artifactId"), text(c, "version"),
                            ancestors.contains("plugin") ? "plugin" : scope, optional, List.copyOf(exclusions), type, scopeWritten));
                }
            } else if (!tag.equals("properties")) {
                ancestors.push(tag);
                walk(c, ancestors, pom);
                ancestors.pop();
            }
        }
    }

    static final class PomIndex {
        private final Map<String, Pom> byCoordinates = new HashMap<>();
        private final Map<Path, Pom> byPath = new HashMap<>();

        PomIndex(List<Pom> poms) {
            for (Pom p : poms) {
                byCoordinates.put(p.groupId + ":" + p.artifactId, p);
                byPath.put(p.path, p);
            }
        }

        /** The scanned pom of this group and artifact, whatever its version; null when none. */
        Pom byCoordinates(String group, String artifact) {
            return byCoordinates.get(group + ":" + artifact);
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

    /** Where the version of a dependency is written: a literal in a pom, or a property a pom defines. */
    public record VersionSite(Path pom, String property) {
        public boolean literal() { return property == null; }
    }

    /**
     * The poms of a scanned folder, their parents among them: where a dependency's version is written, and the Java
     * the project is built for. A pom that cannot be read is left out.
     */
    public static final class Tree {
        private final PomIndex index;

        private Tree(PomIndex index) {
            this.index = index;
        }

        public static Tree of(List<Path> poms) {
            DocumentBuilder builder = pomParser();
            var read = new ArrayList<Pom>();
            for (Path p : poms) {
                try {
                    read.add(parse(p, builder.parse(p.toFile()).getDocumentElement()));
                } catch (Exception _) {
                    // left out: the scan has already said it could not read it
                }
            }
            return new Tree(new PomIndex(read));
        }

        /**
         * Where the version of g:a, as this pom uses it, is written: in its dependencies or its dependency management,
         * else in a parent's dependency management; a literal, or a ${property} of the pom (or parent) defining it.
         * Empty when the pom is not in the tree, or the version is written some other way.
         */
        public Optional<VersionSite> versionSite(Path pomPath, String group, String artifact) {
            Pom pom = index.byPath.get(pomPath.toAbsolutePath().normalize());
            if (pom == null) return Optional.empty();
            Pom where = null;
            String raw = null;
            for (PomDep d : concat(pom.deps, pom.managed))
                if (d.version() != null && group.equals(index.resolve(pom, d.group())) && artifact.equals(index.resolve(pom, d.artifact()))) {
                    where = pom;
                    raw = d.version();
                    break;
                }
            if (raw == null) {
                outer:
                for (Pom p : index.chain(pom))
                    for (PomDep d : p.managed)
                        if (d.version() != null && group.equals(index.resolve(p, d.group())) && artifact.equals(index.resolve(p, d.artifact()))) {
                            where = p;
                            raw = d.version();
                            break outer;
                        }
            }
            if (raw == null) return Optional.empty();
            if (!raw.contains("${")) return Optional.of(new VersionSite(where.path, null));
            var m = PROP.matcher(raw.strip());
            if (!m.matches()) return Optional.empty();
            for (Pom p : index.chain(where))
                if (p.props.containsKey(m.group(1))) return Optional.of(new VersionSite(p.path, m.group(1)));
            return Optional.empty();
        }

        /** The scanned pom of this group and artifact: a module of the folder; empty when none. */
        public Optional<Path> module(String group, String artifact) {
            Pom pom = index.byCoordinates(group, artifact);
            return pom == null ? Optional.empty() : Optional.of(pom.path);
        }

        /** The pom and its parents among the scanned ones, the pom first; empty when it is not in the tree. */
        public List<Path> chain(Path pomPath) {
            Pom pom = index.byPath.get(pomPath.toAbsolutePath().normalize());
            return pom == null ? List.of() : index.chain(pom).stream().map(p -> p.path).toList();
        }

        /** The Java version the pom is built for (8 for "1.8"), from the compiler's properties or plugin; empty when none says. */
        public OptionalInt javaTarget(Path pomPath) {
            Pom pom = index.byPath.get(pomPath.toAbsolutePath().normalize());
            if (pom == null) return OptionalInt.empty();
            for (String raw : new String[]{index.property(pom, "maven.compiler.release"), first(pom, "release"),
                    index.property(pom, "maven.compiler.target"), first(pom, "target"), index.property(pom, "maven.compiler.source"),
                    first(pom, "source")}) {
                OptionalInt v = javaVersion(index.resolve(pom, raw));
                if (v.isPresent()) return v;
            }
            return OptionalInt.empty();
        }

        private String first(Pom pom, String which) {
            for (Pom p : index.chain(pom)) {
                String v = switch (which) {
                    case "release" -> p.compilerRelease;
                    case "target" -> p.compilerTarget;
                    default -> p.compilerSource;
                };
                if (v != null) return index.resolve(p, v);
            }
            return null;
        }

        private static List<PomDep> concat(List<PomDep> a, List<PomDep> b) {
            var out = new ArrayList<>(a);
            out.addAll(b);
            return out;
        }
    }

    /** "1.8" and "8" are Java 8, "11" Java 11; anything else says no version. */
    public static OptionalInt javaVersion(String raw) {
        if (raw == null) return OptionalInt.empty();
        var m = Pattern.compile("(?:1\\.)?(\\d+)").matcher(raw.strip());
        return m.matches() ? OptionalInt.of(Integer.parseInt(m.group(1))) : OptionalInt.empty();
    }
}
