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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.jtools.cvescanner.i18n.Phrase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** An ignore file read as a spreadsheet writes CSV, and written back with every other line as it was. */
class IgnoreFileTest {

    @TempDir
    Path dir;

    private List<IgnoreRule> read(String text, List<Phrase> warnings) throws IOException {
        Path file = dir.resolve(IgnoreFile.NAME);
        Files.writeString(file, text, StandardCharsets.UTF_8);
        return IgnoreFile.read(file, "ignore.csv", warnings::add);
    }

    @Test
    void commentsTheHeaderAndBlankLinesAreSkippedAQuotedReasonKeepsItsCommas() throws IOException {
        var warnings = new ArrayList<Phrase>();
        var rules = read("""
                ﻿# reviewed
                ID,Package,Version,Until,Reason

                CVE-2021-44228,org.apache.logging.log4j:log4j-core,2.14.1,2027-06-30,"Not exposed, see ""SEC-12""\"
                  GHSA-aaaa , , , , test only, for now\r
                """, warnings);
        assertTrue(warnings.isEmpty(), warnings.toString());
        assertEquals(List.of(
                new IgnoreRule("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", LocalDate.of(2027, 6, 30),
                        "Not exposed, see \"SEC-12\"", 4),
                new IgnoreRule("GHSA-aaaa", "", "", null, "test only, for now", 5)), rules);
    }

    @Test
    void aLineWithoutAnIdOrWithAWrongDateIsLeftOutAndSaid() throws IOException {
        var warnings = new ArrayList<Phrase>();
        var rules = read("""
                ,lodash,,,no id
                CVE-2021-1,,,30/06/2027,a French date
                CVE-2021-2
                """, warnings);
        assertEquals(List.of(new IgnoreRule("CVE-2021-2", "", "", null, "", 3)), rules);
        assertEquals(List.of(Phrase.of("ignore.warning.noId", "ignore.csv", 1),
                Phrase.of("ignore.warning.badDate", "ignore.csv", 2, "30/06/2027")), warnings);
    }

    @Test
    void anEntryAddedToNoFileWritesItWithItsHeaderAndReadsBackTheSame() throws IOException {
        Path file = dir.resolve("sub").resolve(IgnoreFile.NAME);
        var rule = new IgnoreRule("CVE-2021-1", "g:a", "1.0", LocalDate.of(2027, 1, 31), "a reason, with \"quotes\"\nand a break", 0);
        IgnoreFile.append(file, rule);
        String text = Files.readString(file);
        assertTrue(text.startsWith(IgnoreFile.HEADER), text);
        var back = IgnoreFile.read(file, "x", w -> { throw new AssertionError(w); });
        assertEquals(1, back.size());
        assertTrue(back.getFirst().sameEntry(new IgnoreRule("CVE-2021-1", "g:a", "1.0", LocalDate.of(2027, 1, 31),
                "a reason, with \"quotes\" and a break", 0)), back.toString());
        try (var files = Files.list(file.getParent())) {
            assertEquals(List.of(file), files.toList(), "no temporary file left");
        }
    }

    @Test
    void addingAndRemovingKeepsEveryOtherLineAsItWasItsLineBreaksToo() throws IOException {
        Path file = dir.resolve(IgnoreFile.NAME);
        String original = "# kept as it is\r\nCVE-2021-1,,,,first\r\n\r\n  # indented comment\r\nCVE-2021-2,,,,second";
        Files.writeString(file, original);
        var added = new IgnoreRule("CVE-2021-3", "", "", null, "third", 0);
        IgnoreFile.append(file, added);
        assertEquals(original + "\r\nCVE-2021-3,,,,third\r\n", Files.readString(file));

        assertTrue(IgnoreFile.remove(file, new IgnoreRule("cve-2021-1", "", "", null, "first", 7)), "found by what it says");
        assertEquals("# kept as it is\r\n\r\n  # indented comment\r\nCVE-2021-2,,,,second\r\nCVE-2021-3,,,,third\r\n",
                Files.readString(file));
        assertFalse(IgnoreFile.remove(file, new IgnoreRule("CVE-2021-2", "", "", null, "another reason", 0)));
        assertTrue(IgnoreFile.remove(file, added));
        assertEquals("# kept as it is\r\n\r\n  # indented comment\r\nCVE-2021-2,,,,second\r\n", Files.readString(file));
    }

    @Test
    void fieldsAreSplitAndJoinedAsASpreadsheetDoes() {
        assertEquals(List.of("a", "b, c", "d\"e", ""), IgnoreFile.split("a,\"b, c\",\"d\"\"e\","));
        assertEquals("a,\"b, c\",\"d\"\"e\",\" f\"", IgnoreFile.join(List.of("a", "b, c", "d\"e", " f")));
        assertEquals(List.of("a", "b, c", "d\"e", " f"), IgnoreFile.split(IgnoreFile.join(List.of("a", "b, c", "d\"e", " f"))));
    }
}
