package org.jtools.cvescanner.fix;

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
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** A made-up machine for the fixes' tests: its PATH, its home and caches, its programs, all in a temporary folder. */
final class FakeMachine {

    final Path bin, home;

    FakeMachine(Path dir) throws IOException {
        bin = Files.createDirectories(dir.resolve("bin"));
        home = Files.createDirectories(dir.resolve("home"));
    }

    Machine machine() {
        return new Machine(List.of(bin), false, List.of(""), home, null);
    }

    /** A program on the PATH, its script given (a shell script: the runner's tests run where there is a shell). */
    Path program(String name, String script) throws IOException {
        Path p = bin.resolve(name);
        Files.writeString(p, "#!/bin/sh\n" + script + "\n");
        p.toFile().setExecutable(true);
        return p;
    }

    void versionsPlugin() throws IOException {
        Path v = Files.createDirectories(home.resolve(".m2/repository/org/codehaus/mojo/versions-maven-plugin/2.21.0"));
        Files.writeString(v.resolve("versions-maven-plugin-2.21.0.jar"), "jar");
    }

    /** A jar in the local Maven repository whose one class is of this Java version. */
    void jar(String group, String artifact, String version, int java) throws IOException {
        Path dir = Files.createDirectories(home.resolve(".m2/repository").resolve(group.replace('.', '/')).resolve(artifact).resolve(version));
        try (var zip = new ZipOutputStream(Files.newOutputStream(dir.resolve(artifact + "-" + version + ".jar")))) {
            zip.putNextEntry(new ZipEntry("a/B.class"));
            zip.write(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, (byte) (java + 44)});
            zip.closeEntry();
        }
    }

    /** npm's cache holding the registry document of a package: its versions and their engines.node. */
    void npmPackage(String name, String documentJson) throws Exception {
        Path cache = home.resolve(".npm/_cacache");
        byte[] content = documentJson.getBytes(StandardCharsets.UTF_8);
        byte[] sha512 = MessageDigest.getInstance("SHA-512").digest(content);
        String hex = HexFormat.of().formatHex(sha512);
        Path c = Files.createDirectories(cache.resolve("content-v2/sha512").resolve(hex.substring(0, 2)).resolve(hex.substring(2, 4)));
        Files.write(c.resolve(hex.substring(4)), content);
        String key = "make-fetch-happen:request-cache:https://registry.npmjs.org/" + name;
        String h = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        String entry = "{\"key\":\"" + key + "\",\"integrity\":\"sha512-" + Base64.getEncoder().encodeToString(sha512) + "\"}";
        String line = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(entry.getBytes(StandardCharsets.UTF_8))) + "\t" + entry;
        Path bucket = Files.createDirectories(cache.resolve("index-v5").resolve(h.substring(0, 2)).resolve(h.substring(2, 4)));
        Files.writeString(bucket.resolve(h.substring(4)), "\n" + line);
    }
}
