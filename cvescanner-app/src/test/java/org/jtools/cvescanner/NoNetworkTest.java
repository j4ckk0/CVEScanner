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

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.FileSystems;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.jtools.cvescanner.engine.Engine;
import org.junit.jupiter.api.Test;

/**
 * CVEScanner never reaches the network (README, "No network"): no class of the program may name what the JDK
 * reaches it with. Read from the compiled classes rather than the sources, so that nothing escapes through an
 * import, a fully qualified name or a method reference. The enforcer rule of the parent pom.xml keeps out any
 * library, whose classes this test would not read.
 */
class NoNetworkTest {

    /** This module's classes; the comparison's and the view's are found where the tests load them from. */
    private static final Path CLASSES = Path.of("target", "classes");

    /** The JDK's packages that reach the network, as class files spell them. */
    private static final List<String> FORBIDDEN_PACKAGES = List.of(
            "java/net/",                              // sockets, URL connections, the HTTP client, name lookups
            "javax/net/",                             // TLS sockets
            "jdk/net/", "sun/net/", "com/sun/net/",   // the JDK's socket options, its internal clients, its HTTP server
            "java/rmi/", "javax/rmi/",                // remote objects
            "javax/naming/",                          // JNDI: LDAP, DNS
            "javax/management/remote/");              // JMX over the network

    /**
     * Classes elsewhere that reach the network, hand over to a program that may, or make an XML parser — which fetches
     * the DTDs and entities a document names unless told not to: MavenScanner.pomParser makes the program's only one.
     */
    private static final List<Pattern> FORBIDDEN_CLASSES = Stream.of(
                    "java/awt/Desktop",                        // browse() and mail() start the browser and the mail client
                    "java/lang/ProcessBuilder",                // another program would do what this one may not
                    "javax/xml/parsers/DocumentBuilderFactory",
                    "javax/xml/parsers/SAXParserFactory",
                    "org/xml/sax/helpers/XMLReaderFactory",
                    "javax/xml/transform/TransformerFactory",
                    "javax/xml/validation/SchemaFactory",
                    "javax/xml/xpath/XPathFactory",
                    "javax/xml/catalog/CatalogManager")
            .map(name -> Pattern.compile(Pattern.quote(name) + "(?!\\w)"))
            .toList();

    /** Methods of classes that are otherwise allowed. */
    private static final List<String> FORBIDDEN_METHODS = List.of(
            "java/lang/Runtime.exec",                          // as ProcessBuilder
            "java/lang/System.load",                           // native code, which this test cannot read
            "java/lang/System.loadLibrary",
            "java/lang/Runtime.load",
            "java/lang/Runtime.loadLibrary",
            "javax/xml/stream/XMLInputFactory.newInstance",    // an XML parser, as above
            "javax/xml/stream/XMLInputFactory.newFactory",
            "javax/xml/stream/XMLInputFactory.newDefaultFactory");

    /** A class that may name what the rule forbids elsewhere, as its purpose is to keep the network out. */
    private record Exemption(String className, List<String> names, List<String> methods) {

        boolean covers(String classFile) {
            return classFile.equals(className + ".class") || classFile.startsWith(className + "$");
        }
    }

    private static final Exemption NO_EXEMPTION = new Exemption("", List.of(), List.of());

    private static final String RESOLVER = "org/jtools/cvescanner/NoNetworkResolver";

    private static final String MAVEN_SCANNER = "org/jtools/cvescanner/project/MavenScanner";

    private static final List<Exemption> EXEMPTIONS = List.of(
            // refuses every name lookup: names the types it implements (the longest first: each is removed in turn)
            new Exemption(RESOLVER, List.of(
                    "java/net/spi/InetAddressResolverProvider$Configuration",
                    "java/net/spi/InetAddressResolverProvider",
                    "java/net/spi/InetAddressResolver$LookupPolicy",
                    "java/net/spi/InetAddressResolver",
                    "java/net/UnknownHostException",
                    "java/net/InetAddress"), List.of()),
            // the module's descriptor: names the resolver's service, which it provides
            new Exemption("module-info", List.of("java/net/spi/InetAddressResolverProvider"), List.of()),
            // makes the program's only XML parser, for the pom.xml files, set to fetch nothing (PomParserTest)
            new Exemption(MAVEN_SCANNER, List.of("javax/xml/parsers/DocumentBuilderFactory"), List.of()));

    @Test
    void noClassOfTheProgramReachesTheNetwork() throws IOException, URISyntaxException {
        List<String> uses = new ArrayList<>();
        for (Path root : programClasses()) {
            List<Path> classFiles;
            try (Stream<Path> files = Files.walk(root)) {
                classFiles = files.filter(file -> file.toString().endsWith(".class")).sorted().toList();
            }
            assertFalse(classFiles.isEmpty(), root + " holds no class: the test would pass reading nothing");
            for (Path classFile : classFiles) {
                String name = root.relativize(classFile).toString().replace('\\', '/');
                uses.addAll(networkUses(name, ClassFileNames.read(classFile)));
            }
        }
        assertEquals(List.of(), uses, "what reaches the network (README, \"No network\")");
    }

    /**
     * The program's two modules' classes: this one's, and those of the scan — its target/classes in a build of the
     * whole project, or its jar.
     */
    private static List<Path> programClasses() throws IOException, URISyntaxException {
        List<Path> roots = new ArrayList<>(List.of(CLASSES));
        for (Class<?> of : List.of(Engine.class)) {
            Path location = Path.of(of.getProtectionDomain().getCodeSource().getLocation().toURI());
            roots.add(Files.isDirectory(location) ? location : FileSystems.newFileSystem(location).getPath("/"));
        }
        return roots;
    }

    /** The check finds each kind of use: a test that cannot fail would prove nothing. */
    @Test
    void theCheckFindsEachWayToTheNetwork() throws IOException {
        String uses = String.join("\n", networkUses("Offender", ClassFileNames.read(OFFENDER)));

        assertTrue(uses.contains("java/net/Socket"), uses);
        assertTrue(uses.contains("java/awt/Desktop"), uses);
        assertTrue(uses.contains("calls java/lang/Runtime.exec"), uses);
        assertTrue(uses.contains("javax.net.ssl.SSLSocket"), uses);   // named in a string, for reflection
        assertTrue(uses.contains("javax/xml/parsers/DocumentBuilderFactory"), uses);
        assertTrue(uses.contains("calls javax/xml/stream/XMLInputFactory.newInstance"), uses);
    }

    /** An exemption covers what it names, and nothing else of the network. */
    @Test
    void anExemptionCoversWhatItNamesOnly() throws IOException {
        String asResolver = String.join("\n", networkUses(RESOLVER + ".class", ClassFileNames.read(OFFENDER)));
        assertTrue(asResolver.contains("java/net/Socket"), asResolver);

        String asMavenScanner = String.join("\n", networkUses(MAVEN_SCANNER + ".class", ClassFileNames.read(OFFENDER)));
        assertTrue(asMavenScanner.contains("java/net/Socket"), asMavenScanner);
        assertTrue(asMavenScanner.contains("calls javax/xml/stream/XMLInputFactory.newInstance"), asMavenScanner);
    }

    private static final Path OFFENDER =
            Path.of("target", "test-classes", "org", "jtools", "cvescanner", "NoNetworkTest$Offender.class");

    /** One line per name of the class that reaches the network, saying which; none when it does not. */
    private static List<String> networkUses(String classFile, ClassFileNames names) {
        Exemption exemption = EXEMPTIONS.stream().filter(e -> e.covers(classFile)).findFirst().orElse(NO_EXEMPTION);
        List<String> uses = new ArrayList<>();
        for (String constant : names.constants()) {
            String asPath = constant.replace('.', '/');   // a class named for reflection is written with dots
            for (String exempted : exemption.names()) {
                asPath = asPath.replace(exempted, "");
            }
            String checked = asPath;
            boolean forbidden = FORBIDDEN_PACKAGES.stream().anyMatch(checked::contains)
                    || FORBIDDEN_CLASSES.stream().anyMatch(name -> name.matcher(checked).find());
            if (forbidden) {
                uses.add(classFile + ": " + constant);
            }
        }
        for (String method : names.calledMethods()) {
            if (FORBIDDEN_METHODS.contains(method) && !exemption.methods().contains(method)) {
                uses.add(classFile + ": calls " + method);
            }
        }
        return uses;
    }

    /**
     * What a class file names, from its constant pool: every UTF-8 constant (the classes it uses, the descriptors
     * of its fields and methods, its string literals) and the methods it calls, as "owner.name".
     */
    private record ClassFileNames(List<String> constants, List<String> calledMethods) {

        static ClassFileNames read(Path classFile) throws IOException {
            try (InputStream in = Files.newInputStream(classFile)) {
                return read(in, classFile.toString());
            }
        }

        static ClassFileNames read(InputStream stream, String classFile) throws IOException {
            {
                DataInputStream in = new DataInputStream(new BufferedInputStream(stream));
                if (in.readInt() != 0xCAFEBABE) {
                    throw new IOException(classFile + ": not a class file");
                }
                in.readUnsignedShort();   // minor version
                in.readUnsignedShort();   // major version
                int count = in.readUnsignedShort();
                String[] utf8 = new String[count];
                int[] classNameIndex = new int[count];
                int[] nameAndTypeNameIndex = new int[count];
                List<int[]> methodRefs = new ArrayList<>();   // its class's index, its name-and-type's index
                for (int i = 1; i < count; i++) {
                    int tag = in.readUnsignedByte();
                    switch (tag) {
                        case 1 -> utf8[i] = in.readUTF();   // the class file's modified UTF-8 is DataInput's
                        case 7 -> classNameIndex[i] = in.readUnsignedShort();
                        case 10, 11 -> methodRefs.add(new int[] {in.readUnsignedShort(), in.readUnsignedShort()});
                        case 12 -> {
                            nameAndTypeNameIndex[i] = in.readUnsignedShort();
                            in.readUnsignedShort();
                        }
                        case 8, 16, 19, 20 -> in.readUnsignedShort();
                        case 15 -> {
                            in.readUnsignedByte();
                            in.readUnsignedShort();
                        }
                        case 3, 4, 9, 17, 18 -> in.readInt();
                        case 5, 6 -> {
                            in.readLong();
                            i++;   // a long or a double takes two entries
                        }
                        default -> throw new IOException(classFile + ": unknown constant tag " + tag);
                    }
                }
                List<String> constants = Stream.of(utf8).filter(s -> s != null).toList();
                List<String> calledMethods = methodRefs.stream()
                        .map(ref -> utf8[classNameIndex[ref[0]]] + "." + utf8[nameAndTypeNameIndex[ref[1]]])
                        .toList();
                return new ClassFileNames(constants, calledMethods);
            }
        }
    }

    /** Each thing the program may not do, for theCheckFindsEachWayToTheNetwork to find. Never run. */
    @SuppressWarnings("unused")
    private static final class Offender {

        void connect() throws IOException {
            new java.net.Socket("localhost", 1).close();
        }

        void browse() throws Exception {
            java.awt.Desktop.getDesktop().open(null);
        }

        void exec() throws IOException {
            Runtime.getRuntime().exec(new String[] {"true"});
        }

        void reflect() throws ClassNotFoundException {
            Class.forName("javax.net.ssl.SSLSocket");
        }

        void parse() throws Exception {
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.stream.XMLInputFactory.newInstance();
        }
    }
}
