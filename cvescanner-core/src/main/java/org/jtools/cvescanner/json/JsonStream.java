package org.jtools.cvescanner.json;

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
import java.io.Reader;
import java.util.function.Consumer;

/**
 * The elements of one array of a large JSON document, handed over one at a time as their own text, the document never
 * held whole: an NVD feed is a single object of tens or hundreds of megabytes, its "vulnerabilities" array holding
 * thousands of records. Each element's text is then parsed by Json, alone. Strings and their escapes are followed, so a
 * brace or a bracket inside a string ends nothing.
 */
public final class JsonStream {

    private final Reader in;
    private int pushedBack = -2;

    private JsonStream(Reader in) {
        this.in = in;
    }

    /**
     * Hands over each element of the array that the document's top-level object holds under this key; nothing when it
     * holds none. Throws IllegalArgumentException when the document breaks off inside that array.
     */
    public static void forEachElement(Reader in, String key, Consumer<String> element) throws IOException {
        new JsonStream(in).elements(key, element);
    }

    private int read() throws IOException {
        if (pushedBack != -2) {
            int c = pushedBack;
            pushedBack = -2;
            return c;
        }
        return in.read();
    }

    private void elements(String key, Consumer<String> element) throws IOException {
        if (!findKey(key)) return;
        int c = skipBlanks();
        if (c != '[') return;
        var text = new StringBuilder();
        while (true) {
            c = skipBlanks();
            if (c == ']') return;
            if (c == ',') continue;
            if (c == -1) throw new IllegalArgumentException("the array \"" + key + "\" breaks off");
            text.setLength(0);
            value(c, text);
            element.accept(text.toString());
        }
    }

    /** Reads up to the value of this key in the top-level object; false when the object has no such key. */
    private boolean findKey(String key) throws IOException {
        int depth = 0;
        var name = new StringBuilder();
        for (int c; (c = read()) != -1; ) {
            switch (c) {
                case '{', '[' -> depth++;
                case '}', ']' -> depth--;
                case '"' -> {
                    name.setLength(0);
                    string(name, false);
                    if (depth == 1 && name.toString().equals(key)) {
                        int next = skipBlanks();
                        if (next == ':') return true;
                        pushedBack = next;
                    }
                }
                default -> { }
            }
        }
        return false;
    }

    /** Copies a whole value, its first character already read, into text. */
    private void value(int first, StringBuilder text) throws IOException {
        if (first == '"') {
            text.append('"');
            string(text, true);
            return;
        }
        if (first != '{' && first != '[') {
            // a number, true, false, null: up to the next separator
            text.append((char) first);
            for (int c; (c = read()) != -1; ) {
                if (c == ',' || c == ']' || c == '}' || Character.isWhitespace(c)) {
                    pushedBack = c;
                    return;
                }
                text.append((char) c);
            }
            return;
        }
        int depth = 0;
        for (int c = first; c != -1; c = read()) {
            text.append((char) c);
            switch (c) {
                case '{', '[' -> depth++;
                case '}', ']' -> {
                    if (--depth == 0) return;
                }
                case '"' -> string(text, true);
                default -> { }
            }
        }
        throw new IllegalArgumentException("a value breaks off");
    }

    /** Reads a string's characters after its opening quote, up to and with its closing one; escapes kept as written. */
    private void string(StringBuilder text, boolean withQuote) throws IOException {
        for (int c; (c = read()) != -1; ) {
            if (c == '"') {
                if (withQuote) text.append('"');
                return;
            }
            text.append((char) c);
            if (c == '\\') {
                int escaped = read();
                if (escaped == -1) break;
                text.append((char) escaped);
            }
        }
        throw new IllegalArgumentException("a string breaks off");
    }

    private int skipBlanks() throws IOException {
        int c;
        do {
            c = read();
        } while (c != -1 && Character.isWhitespace(c));
        return c;
    }
}
