package org.jtools.cvescanner.cli;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.ignore.IgnoreFile;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The ignore file edited from the command line: an entry added, those naming a vulnerability removed, all listed. */
class CliIgnoreTest {

    @TempDir
    Path dir;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();

    @BeforeEach
    void english() {
        I18n.use(I18nLanguage.ENGLISH);
    }

    private int run(String... args) {
        var all = new ArrayList<>(List.of("-d", dir.toString()));
        all.addAll(List.of(args));
        return CliIgnore.run(Options.parse(all.toArray(String[]::new)), new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private List<IgnoreRule> entries() throws Exception {
        return IgnoreFile.read(dir.resolve(IgnoreFile.NAME), "x", w -> { throw new AssertionError(w); });
    }

    @Test
    void anEntryAddedThenListedThenRemovedWithEveryPackageItNames() throws Exception {
        assertEquals(0, run("--ignore-add", "CVE-2021-44228", "--package", "org.apache.logging.log4j:log4j-core",
                "--version", "2.14.1", "--reason", "not exposed, see SEC-12", "--until", "2999-12-31"));
        assertEquals(0, run("--ignore-add", "cve-2021-44228", "--package", "other:lib", "--reason", "test only"));
        assertEquals(0, run("--ignore-add", "GHSA-aaaa", "--reason", "kept"));
        assertEquals(List.of("CVE-2021-44228", "cve-2021-44228", "GHSA-aaaa"), entries().stream().map(IgnoreRule::id).toList());
        assertEquals("not exposed, see SEC-12", entries().getFirst().reason());

        out.reset();
        assertEquals(0, run("--ignore-list"));
        String listed = out.toString(StandardCharsets.UTF_8);
        assertTrue(listed.contains(": CVE-2021-44228  ·  org.apache.logging.log4j:log4j-core  ·  2.14.1  ·  2999-12-31"), listed);
        assertTrue(listed.contains(": GHSA-aaaa  ·  any  ·  any  ·  no end  ·  kept"), listed);

        assertEquals(0, run("--ignore-remove", "CVE-2021-44228", "--package", "OTHER:lib"));
        assertEquals(2, entries().size(), "only the package named");
        assertEquals(0, run("--ignore-remove", "CVE-2021-44228"));
        assertEquals(List.of("GHSA-aaaa"), entries().stream().map(IgnoreRule::id).toList());
        assertTrue(Files.readString(dir.resolve(IgnoreFile.NAME)).startsWith("#"), "the header kept");

        assertEquals(1, run("--ignore-remove", "CVE-2099-1"));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("no entry"), err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void aNamedFileIsTheOneEditedAndAMissingOneCannotBeListed() throws Exception {
        Path named = dir.resolve("reviewed.csv");
        assertEquals(0, run("--ignore", named.toString(), "--ignore-add", "GHSA-bbbb", "--reason", "why"));
        assertTrue(Files.isRegularFile(named));
        assertFalse(Files.exists(dir.resolve(IgnoreFile.NAME)));
        assertEquals(1, run("--ignore", dir.resolve("missing.csv").toString(), "--ignore-list"));
        assertEquals(0, run("--ignore-list"), "the folder's own, absent: nothing in it");
    }

    @Test
    void whatAnEditCannotBeIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-add", "CVE-1"}), "no reason");
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-add", "CVE-1", "--reason", "r",
                "--until", "30/06/2027"}));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-add", "CVE-1", "--reason", "r",
                "--until", "2001-01-01"}), "past");
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-list", "--ignore-remove", "CVE-1"}));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-list", "--no-ignore"}));
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--reason", "r"}), "without --ignore-add");
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--package", "p"}), "without an edit");
        assertThrows(IllegalArgumentException.class, () -> Options.parse(new String[]{"--ignore-remove", "CVE-1", "--until", "2999-01-01"}));
    }
}
