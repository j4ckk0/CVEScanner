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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.OptionalInt;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * The Java a library version needs, read from its jar in the machine's caches (the local Maven repository, Gradle's):
 * the newest class-file version among its classes, those for later Java releases of a multi-release jar and
 * module-info left aside. Nothing is fetched: a jar not cached gives no answer.
 */
final class ArtifactJava {

    private ArtifactJava() {}

    /** Whether this version is in the local Maven repository or Gradle's cache: what an offline build can use. */
    static boolean cached(Machine machine, String group, String artifact, String version) {
        if (Files.isDirectory(machine.mavenRepository().resolve(group.replace('.', '/')).resolve(artifact).resolve(version))) return true;
        return Files.isDirectory(machine.gradleCache().resolve(group).resolve(artifact).resolve(version));
    }

    static OptionalInt of(Machine machine, String group, String artifact, String version) {
        String file = artifact + "-" + version + ".jar";
        Path maven = machine.mavenRepository().resolve(group.replace('.', '/')).resolve(artifact).resolve(version).resolve(file);
        if (Files.isRegularFile(maven)) return of(maven);
        Path gradle = machine.gradleCache().resolve(group).resolve(artifact).resolve(version);
        if (Files.isDirectory(gradle)) {
            try (Stream<Path> hashes = Files.list(gradle)) {
                for (Path hash : hashes.toList()) {
                    Path jar = hash.resolve(file);
                    if (Files.isRegularFile(jar)) return of(jar);
                }
            } catch (IOException _) {
                // no answer, then
            }
        }
        return OptionalInt.empty();
    }

    /** The Java this jar needs: 8 for class files of major 52; empty when it holds no class or cannot be read. */
    static OptionalInt of(Path jar) {
        int newest = 0;
        try (var zip = new ZipInputStream(Files.newInputStream(jar))) {
            for (ZipEntry e; (e = zip.getNextEntry()) != null; ) {
                String name = e.getName();
                if (!name.endsWith(".class") || name.startsWith("META-INF/versions/") || name.endsWith("module-info.class")) continue;
                newest = Math.max(newest, major(zip));
            }
        } catch (IOException | RuntimeException _) {
            return OptionalInt.empty();
        }
        return newest == 0 ? OptionalInt.empty() : OptionalInt.of(newest - 44);
    }

    /** A class file's major version: after its magic number (CAFEBABE) and its minor version. */
    private static int major(InputStream in) throws IOException {
        var data = new DataInputStream(in);
        if (data.readInt() != 0xCAFEBABE) return 0;
        data.readUnsignedShort();
        return data.readUnsignedShort();
    }
}
