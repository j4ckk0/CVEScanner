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

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.json.Json;

/**
 * Members written into an object of package.json, at a path from its root (["overrides"], ["pnpm", "overrides"]),
 * its objects made as needed; the rest of the file left as written, its indentation and line ends followed. A member
 * already there takes the new value.
 */
record PackageJsonMembers(Path file, List<String> path, Map<String, String> members) implements Step.Edit {

    PackageJsonMembers {
        path = List.copyOf(path);
        members = new LinkedHashMap<>(members);
    }

    @Override
    public String shown() {
        var sb = new StringBuilder(file.getFileName() + ": " + String.join(".", path));
        members.forEach((k, v) -> sb.append(' ').append(Json.write(k).strip()).append(": ").append(Json.write(v).strip()));
        return sb.toString();
    }

    @Override
    public String apply(String text) {
        String result = text;
        for (var m : members.entrySet()) {
            result = put(result, m.getKey(), m.getValue());
            if (result == null) return null;
        }
        return result;
    }

    /** The member written at the path; null when the file is not a JSON object. */
    private String put(String text, String key, String value) {
        Span object = JsonText.root(text);
        if (object == null) return null;
        String nl = text.contains("\r\n") ? "\r\n" : "\n";
        for (int depth = 0; depth < path.size(); depth++) {
            Span child = JsonText.member(text, object, path.get(depth));
            if (child == null || text.charAt(child.start()) != '{') {
                // the rest of the path made as one inline value, written where the object ends
                String made = quote(key) + ": " + quote(value);
                for (int i = path.size() - 1; i > depth; i--) made = quote(path.get(i)) + ": { " + made + " }";
                if (child != null) return text.substring(0, child.start()) + "{ " + made + " }" + text.substring(child.end());
                return JsonText.insert(text, object, quote(path.get(depth)) + ": { " + made + " }", nl);
            }
            object = child;
        }
        Span existing = JsonText.member(text, object, key);
        if (existing != null) return text.substring(0, existing.start()) + quote(value) + text.substring(existing.end());
        return JsonText.insert(text, object, quote(key) + ": " + quote(value), nl);
    }

    private static String quote(String s) {
        return Json.write(s).strip();
    }

    /** Where a value is in the text: from its first character to just after its last. */
    record Span(int start, int end) {}

    /** Just enough of JSON's grammar to find an object's members in a text and write one into it. */
    static final class JsonText {

        private JsonText() {}

        static Span root(String text) {
            int i = skip(text, 0);
            if (i >= text.length() || text.charAt(i) != '{') return null;
            int end = valueEnd(text, i);
            return end < 0 ? null : new Span(i, end);
        }

        /** The value of this key among the object's own members; null when it has none. */
        static Span member(String text, Span object, String key) {
            int i = skip(text, object.start() + 1);
            while (i < object.end() - 1 && text.charAt(i) == '"') {
                int keyEnd = valueEnd(text, i);
                String k = (String) Json.parse(text.substring(i, keyEnd));
                int colon = skip(text, keyEnd);
                int valueStart = skip(text, colon + 1);
                int valueEnd = valueEnd(text, valueStart);
                if (valueEnd < 0) return null;
                if (k.equals(key)) return new Span(valueStart, valueEnd);
                i = skip(text, valueEnd);
                if (i < text.length() && text.charAt(i) == ',') i = skip(text, i + 1);
            }
            return null;
        }

        /**
         * The member written last in the object: on a line of its own, indented as the object's members are, when the
         * object spans lines; else after the others on its line.
         */
        static String insert(String text, Span object, String member, String nl) {
            int close = object.end() - 1;
            int last = close - 1;
            while (last > object.start() && Character.isWhitespace(text.charAt(last))) last--;
            boolean empty = last == object.start();
            String inner = text.substring(object.start() + 1, close);
            if (!inner.contains("\n")) {
                String written = empty ? " " + member + " " : ", " + member;
                return empty ? text.substring(0, object.start() + 1) + written + text.substring(close)
                        : text.substring(0, last + 1) + written + text.substring(last + 1);
            }
            String indent = empty ? indentOf(text, object.start()) + "  " : indentOf(text, skip(text, object.start() + 1));
            String written = (empty ? "" : ",") + nl + indent + member;
            if (empty) written += nl + indentOf(text, object.start());
            return text.substring(0, last + 1) + written + text.substring(last + 1);
        }

        /** The blanks that begin the line holding this index. */
        private static String indentOf(String text, int index) {
            int lineStart = text.lastIndexOf('\n', index - 1) + 1;
            int i = lineStart;
            while (i < text.length() && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) i++;
            return text.substring(lineStart, i);
        }

        private static int skip(String text, int i) {
            while (i < text.length() && Character.isWhitespace(text.charAt(i))) i++;
            return i;
        }

        /** Just after the value starting here: a string, an object, an array, a word or a number; -1 when it does not end. */
        private static int valueEnd(String text, int i) {
            if (i >= text.length()) return -1;
            char c = text.charAt(i);
            if (c == '"') {
                for (int j = i + 1; j < text.length(); j++) {
                    if (text.charAt(j) == '\\') j++;
                    else if (text.charAt(j) == '"') return j + 1;
                }
                return -1;
            }
            if (c == '{' || c == '[') {
                int depth = 0;
                for (int j = i; j < text.length(); j++) {
                    char d = text.charAt(j);
                    if (d == '"') {
                        j = valueEnd(text, j) - 1;
                        if (j < 0) return -1;
                    } else if (d == '{' || d == '[') depth++;
                    else if ((d == '}' || d == ']') && --depth == 0) return j + 1;
                }
                return -1;
            }
            int j = i;
            while (j < text.length() && ",}] \t\r\n".indexOf(text.charAt(j)) < 0) j++;
            return j;
        }
    }
}
