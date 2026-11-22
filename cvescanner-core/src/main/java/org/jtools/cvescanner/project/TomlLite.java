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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Just enough TOML for the files a scan reads (pyproject.toml, poetry.lock, uv.lock, Pipfile): tables and arrays of
 * tables, dotted and quoted keys, strings (basic, literal, multi-line), numbers, booleans, dates (kept as text), arrays
 * spanning lines, inline tables, comments. The result is maps and lists, as Json.parse gives. A text it cannot read
 * throws IllegalArgumentException.
 */
final class TomlLite {

    private final String s;
    private int i;

    private TomlLite(String text) {
        this.s = text;
    }

    static Map<String, Object> parse(String text) {
        return new TomlLite(text).document();
    }

    private Map<String, Object> document() {
        var root = new LinkedHashMap<String, Object>();
        Map<String, Object> current = root;
        while (true) {
            skipBlankLines();
            if (i >= s.length()) return root;
            if (s.charAt(i) == '[') {
                boolean array = s.startsWith("[[", i);
                i += array ? 2 : 1;
                List<String> path = key(array ? "]]" : "]");
                expect(array ? "]]" : "]");
                current = array ? appendTable(root, path) : table(root, path);
            } else {
                List<String> path = key("=");
                expect("=");
                skipSpaces();
                Object value = value();
                Map<String, Object> target = path.size() == 1 ? current : table(current, path.subList(0, path.size() - 1));
                target.put(path.getLast(), value);
            }
            endOfLine();
        }
    }

    /** A key, dotted, its parts bare or quoted, up to the delimiter. */
    private List<String> key(String delimiter) {
        var parts = new ArrayList<String>();
        while (true) {
            skipSpaces();
            if (i >= s.length()) throw error("a key");
            char c = s.charAt(i);
            if (c == '"' || c == '\'') parts.add(string());
            else {
                int start = i;
                while (i < s.length() && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_' || s.charAt(i) == '-')) i++;
                if (i == start) throw error("a key");
                parts.add(s.substring(start, i));
            }
            skipSpaces();
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                continue;
            }
            if (!s.startsWith(delimiter, i)) throw error("'" + delimiter + "'");
            return parts;
        }
    }

    private Object value() {
        if (i >= s.length()) throw error("a value");
        char c = s.charAt(i);
        if (c == '"' || c == '\'') return string();
        if (c == '[') return array();
        if (c == '{') return inlineTable();
        int start = i;
        while (i < s.length() && ",]}#".indexOf(s.charAt(i)) < 0 && !Character.isWhitespace(s.charAt(i))) i++;
        // a date and its time may be apart by a space: 1979-05-27 07:32:00
        if (s.substring(start, i).matches("\\d{4}-\\d{2}-\\d{2}") && i + 3 < s.length() && s.charAt(i) == ' '
                && s.substring(i + 1, i + 4).matches("\\d{2}:")) {
            i++;
            while (i < s.length() && ",]}#".indexOf(s.charAt(i)) < 0 && !Character.isWhitespace(s.charAt(i))) i++;
        }
        String word = s.substring(start, i).strip();
        if (word.equals("true")) return Boolean.TRUE;
        if (word.equals("false")) return Boolean.FALSE;
        if (word.matches("[+-]?\\d[\\d_]*")) return Long.parseLong(word.replace("_", ""));
        if (word.matches("[+-]?\\d[\\d_]*(\\.\\d[\\d_]*)?([eE][+-]?\\d+)?")) return Double.parseDouble(word.replace("_", ""));
        if (word.isEmpty()) throw error("a value");
        return word;   // a date, a time, inf, nan: as written
    }

    private String string() {
        char q = s.charAt(i);
        boolean multi = s.startsWith(String.valueOf(q).repeat(3), i);
        String end = multi ? String.valueOf(q).repeat(3) : String.valueOf(q);
        i += multi ? 3 : 1;
        if (multi && i < s.length() && s.charAt(i) == '\n') i++;
        else if (multi && s.startsWith("\r\n", i)) i += 2;
        var sb = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw error("the end of a string");
            if (s.startsWith(end, i)) {
                i += end.length();
                return sb.toString();
            }
            char c = s.charAt(i++);
            if (!multi && (c == '\n' || c == '\r')) {
                i--;   // the line said is the string's
                throw error("the end of a string");
            }
            if (c == '\\' && q == '"') {
                char e = s.charAt(i++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case 'u' -> { sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                    case '\n', '\r', ' ', '\t' -> {   // a line ending backslash: the blanks after it go
                        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
                    }
                    default -> sb.append(e);
                }
            } else sb.append(c);
        }
    }

    private List<Object> array() {
        i++;   // [
        var out = new ArrayList<Object>();
        while (true) {
            skipBlanksAndComments();
            if (i >= s.length()) throw error("']'");
            if (s.charAt(i) == ']') {
                i++;
                return out;
            }
            out.add(value());
            skipBlanksAndComments();
            if (i < s.length() && s.charAt(i) == ',') i++;
            else if (i < s.length() && s.charAt(i) != ']') throw error("',' or ']'");
        }
    }

    private Map<String, Object> inlineTable() {
        i++;   // {
        var out = new LinkedHashMap<String, Object>();
        while (true) {
            skipSpaces();
            if (i >= s.length()) throw error("'}'");
            if (s.charAt(i) == '}') {
                i++;
                return out;
            }
            List<String> path = key("=");
            expect("=");
            skipSpaces();
            Object v = value();
            (path.size() == 1 ? out : table(out, path.subList(0, path.size() - 1))).put(path.getLast(), v);
            skipSpaces();
            if (i < s.length() && s.charAt(i) == ',') i++;
        }
    }

    /** The table at this path from here, made when missing; an array of tables gives its last. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> table(Map<String, Object> from, List<String> path) {
        Map<String, Object> t = from;
        for (String k : path) {
            Object next = t.computeIfAbsent(k, _ -> new LinkedHashMap<String, Object>());
            if (next instanceof List<?> list && !list.isEmpty() && list.getLast() instanceof Map<?, ?> last) t = (Map<String, Object>) last;
            else if (next instanceof Map<?, ?> m) t = (Map<String, Object>) m;
            else throw new IllegalArgumentException("TOML: " + k + " is not a table");
        }
        return t;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> appendTable(Map<String, Object> root, List<String> path) {
        Map<String, Object> parent = table(root, path.subList(0, path.size() - 1));
        Object list = parent.computeIfAbsent(path.getLast(), _ -> new ArrayList<Object>());
        if (!(list instanceof List<?>)) throw new IllegalArgumentException("TOML: " + path.getLast() + " is not an array of tables");
        var t = new LinkedHashMap<String, Object>();
        ((List<Object>) list).add(t);
        return t;
    }

    private void expect(String token) {
        skipSpaces();
        if (!s.startsWith(token, i)) throw error("'" + token + "'");
        i += token.length();
    }

    private void skipSpaces() {
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++;
    }

    private void skipBlanksAndComments() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c)) i++;
            else if (c == '#') while (i < s.length() && s.charAt(i) != '\n') i++;
            else return;
        }
    }

    private void skipBlankLines() {
        skipBlanksAndComments();
    }

    /** Only a comment may follow a value or a table header on its line. */
    private void endOfLine() {
        skipSpaces();
        if (i < s.length() && s.charAt(i) == '#') while (i < s.length() && s.charAt(i) != '\n') i++;
        if (i < s.length() && s.charAt(i) != '\n' && s.charAt(i) != '\r') throw error("the end of the line");
    }

    private IllegalArgumentException error(String expected) {
        int line = 1;
        for (int k = 0; k < Math.min(i, s.length()); k++) if (s.charAt(k) == '\n') line++;
        return new IllegalArgumentException("TOML line " + line + ": " + expected + " expected");
    }
}
