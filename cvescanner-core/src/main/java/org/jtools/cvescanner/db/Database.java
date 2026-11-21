package org.jtools.cvescanner.db;

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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.jtools.cvescanner.engine.ScanListener;

public final class Database {
    private Database() {}

    public static Path zipPath(Path cache, String eco) { return cache.resolve(eco + "-all.zip"); }

    public static void update(String eco, Path cache, ScanListener l) throws IOException, InterruptedException {
        Files.createDirectories(cache);
        Path dest = zipPath(cache, eco), part = cache.resolve(eco + "-all.zip.part");
        URI uri = URI.create(Osv.BASE_URL + "/" + eco + "/all.zip");
        IOException last = null;
        try (var client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                .proxy(ProxySelector.getDefault()).connectTimeout(Duration.ofSeconds(30)).build()) {
            for (int attempt = 1; attempt <= 3; attempt++) {
                try {
                    download(client, uri, eco, dest, part, l);
                    return;
                } catch (IOException e) {
                    last = e;
                    l.status("Download of " + eco + " database failed (attempt " + attempt + "/3): " + e.getMessage());
                    Thread.sleep(2000L * attempt);
                }
            }
        } finally {
            Files.deleteIfExists(part);
        }
        if (Files.isRegularFile(dest)) l.warn("could not download the " + eco + " database (" + last.getMessage() + "); using the cached copy");
        else throw new IOException("Could not download " + uri + ": " + last.getMessage() + "\n\nIf this computer has no "
                + "internet access, put the database zip files in the 'database' folder or click 'Choose database zip…'.", last);
    }

    private static void download(HttpClient client, URI uri, String eco, Path dest, Path part, ScanListener l)
            throws IOException, InterruptedException {
        var req = HttpRequest.newBuilder(uri).GET().timeout(Duration.ofMinutes(30));
        if (Files.isRegularFile(dest)) {
            var lastModified = Files.getLastModifiedTime(dest).toInstant().atZone(ZoneOffset.UTC);
            req.header("If-Modified-Since", DateTimeFormatter.RFC_1123_DATE_TIME.format(lastModified));
        }
        l.status("Checking for a newer " + eco + " database…");
        l.progress(-1);
        HttpResponse<InputStream> resp = client.send(req.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = resp.body()) {
            if (resp.statusCode() == 304) { l.status(eco + " database is already up to date"); return; }
            if (resp.statusCode() != 200) throw new IOException("HTTP " + resp.statusCode());
            long total = resp.headers().firstValueAsLong("Content-Length").orElse(-1);
            try (OutputStream out = Files.newOutputStream(part)) {
                byte[] buf = new byte[1 << 16];
                long done = 0, lastReport = 0;
                for (int r; (r = in.read(buf)) > 0; ) {
                    out.write(buf, 0, r);
                    done += r;
                    if (done - lastReport > (1 << 20)) {
                        lastReport = done;
                        l.status(String.format("Downloading %s database… %.1f MB", eco, done / 1048576.0));
                        if (total > 0) l.progress((double) done / total);
                    }
                }
            }
        }
        Files.move(part, dest, StandardCopyOption.REPLACE_EXISTING);
        resp.headers().firstValue("Last-Modified").ifPresent(lm -> {
            try {
                var t = ZonedDateTime.parse(lm, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                Files.setLastModifiedTime(dest, FileTime.from(t));
            } catch (Exception _) { /* keep local time */ }
        });
        l.status(String.format("Downloaded %s database (%.1f MB)", eco, Files.size(dest) / 1048576.0));
    }
}
