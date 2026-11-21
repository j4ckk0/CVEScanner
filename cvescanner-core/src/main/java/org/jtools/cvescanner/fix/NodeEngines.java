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
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import org.jtools.cvescanner.json.Json;

/**
 * The Node a package version needs ("engines": {"node": …}), read from npm's cache: the registry's document of the
 * package, which npm keeps under the sha-256 of its request key, its content under its integrity. Nothing is fetched:
 * a package npm has not cached gives no answer.
 */
final class NodeEngines {

    private static final String REGISTRY = "https://registry.npmjs.org/";

    private NodeEngines() {}

    /** The version's engines.node: "" when it states none, empty when the cache does not hold the package. */
    static Optional<String> of(Machine machine, String pkg, String version) {
        for (String name : List.of(pkg.replace("/", "%2f"), pkg)) {
            Optional<Map<String, Object>> doc = document(machine.npmCache(), "make-fetch-happen:request-cache:" + REGISTRY + name);
            if (doc.isEmpty()) continue;
            Map<String, Object> versions = Json.obj(doc.get().get("versions"));
            if (!versions.containsKey(version)) return Optional.empty();
            String node = Json.str(Json.obj(Json.obj(versions.get(version)).get("engines")), "node");
            return Optional.of(node == null ? "" : node);
        }
        return Optional.empty();
    }

    /** The JSON content cached under this key: its index bucket, its last entry's integrity, that content. */
    static Optional<Map<String, Object>> document(Path cache, String key) {
        try {
            String h = hex("SHA-256", key.getBytes(StandardCharsets.UTF_8));
            Path bucket = cache.resolve("index-v5").resolve(h.substring(0, 2)).resolve(h.substring(2, 4)).resolve(h.substring(4));
            if (!Files.isRegularFile(bucket)) return Optional.empty();
            String integrity = null;
            for (String line : Files.readAllLines(bucket, StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab < 0) continue;
                Map<String, Object> entry = Json.obj(Json.parse(line.substring(tab + 1)));
                if (key.equals(Json.str(entry, "key")) && Json.str(entry, "integrity") != null) integrity = Json.str(entry, "integrity");
            }
            if (integrity == null) return Optional.empty();
            String first = integrity.strip().split("\\s+")[0];
            int dash = first.indexOf('-');
            String algorithm = first.substring(0, dash), digest = HexFormat.of().formatHex(Base64.getDecoder().decode(first.substring(dash + 1)));
            Path content = cache.resolve("content-v2").resolve(algorithm).resolve(digest.substring(0, 2)).resolve(digest.substring(2, 4))
                    .resolve(digest.substring(4));
            if (!Files.isRegularFile(content)) return Optional.empty();
            byte[] data = Files.readAllBytes(content);
            if (data.length > 1 && (data[0] & 0xff) == 0x1f && (data[1] & 0xff) == 0x8b)
                try (var in = new GZIPInputStream(Files.newInputStream(content))) { data = in.readAllBytes(); }
            return Optional.of(Json.obj(Json.parse(new String(data, StandardCharsets.UTF_8))));
        } catch (IOException | RuntimeException | NoSuchAlgorithmException _) {
            return Optional.empty();
        }
    }

    private static String hex(String algorithm, byte[] data) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(data));
    }
}
