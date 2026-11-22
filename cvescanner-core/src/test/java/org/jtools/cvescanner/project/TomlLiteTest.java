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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TomlLiteTest {

    @Test
    void tablesArraysOfTablesAndDottedKeys() {
        var doc = TomlLite.parse("""
                # a comment
                name = "app"   # after a value
                [project]
                dependencies = [
                    "requests>=2.25",   # one
                    'django==3.1',
                ]
                optional-dependencies.test = ["pytest"]
                [tool.poetry.group.dev.dependencies]
                black = { version = "^22.1", optional = true }
                [[package]]
                name = "a"
                version = "1.0"
                [[package]]
                name = "b"
                "quoted key" = 2
                """);
        assertEquals("app", doc.get("name"));
        var project = (Map<?, ?>) doc.get("project");
        assertEquals(List.of("requests>=2.25", "django==3.1"), project.get("dependencies"));
        assertEquals(Map.of("test", List.of("pytest")), project.get("optional-dependencies"));
        var dev = (Map<?, ?>) ((Map<?, ?>) ((Map<?, ?>) ((Map<?, ?>) ((Map<?, ?>) doc.get("tool")).get("poetry")).get("group")).get("dev")).get("dependencies");
        assertEquals(Map.of("version", "^22.1", "optional", true), dev.get("black"));
        assertEquals(List.of(Map.of("name", "a", "version", "1.0"), Map.of("name", "b", "quoted key", 2L)), doc.get("package"));
    }

    @Test
    void stringsNumbersDatesAndBooleans() {
        var doc = TomlLite.parse("""
                basic = "a\\tb \\"q\\" \\u00e9"
                literal = 'C:\\path'
                multi = \"\"\"
                one
                two\"\"\"
                folded = \"\"\"one \\
                    two\"\"\"
                raw = '''
                x\\y'''
                int = 1_000
                float = 3.5
                date = 2026-11-22T10:00:00Z
                spaced = 1979-05-27 07:32:00
                yes = true
                """);
        assertEquals("a\tb \"q\" é", doc.get("basic"));
        assertEquals("C:\\path", doc.get("literal"));
        assertEquals("one\ntwo", doc.get("multi"));
        assertEquals("one two", doc.get("folded"));
        assertEquals("x\\y", doc.get("raw"));
        assertEquals(1000L, doc.get("int"));
        assertEquals(3.5, doc.get("float"));
        assertEquals("2026-11-22T10:00:00Z", doc.get("date"));
        assertEquals("1979-05-27 07:32:00", doc.get("spaced"));
        assertEquals(true, doc.get("yes"));
    }

    @Test
    void whatItCannotReadIsSaid() {
        var e = assertThrows(IllegalArgumentException.class, () -> TomlLite.parse("a = 1\nb = \"open\n"));
        assertEquals("TOML line 2: the end of a string expected", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> TomlLite.parse("a = [1, 2"));
        assertThrows(IllegalArgumentException.class, () -> TomlLite.parse("a = 1 b = 2"));
    }
}
