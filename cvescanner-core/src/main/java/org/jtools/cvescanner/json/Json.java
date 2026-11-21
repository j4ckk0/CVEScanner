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


import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {
    private final String s;
    private int i;

    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        var p = new Json(text);
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) throw p.error("trailing characters");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) { return o instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of(); }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object o) { return o instanceof List<?> l ? (List<Object>) l : List.of(); }

    public static String str(Map<String, Object> m, String key) { return m.get(key) instanceof String v ? v : null; }

    private IllegalArgumentException error(String msg) { return new IllegalArgumentException("JSON " + msg + " at offset " + i); }

    private void ws() { while (i < s.length() && s.charAt(i) <= ' ') i++; }

    private boolean peek(char c) { return i < s.length() && s.charAt(i) == c; }

    private void expect(char c) {
        if (!peek(c)) throw error("expected '" + c + "'");
        i++;
    }

    private Object value() {
        ws();
        if (i >= s.length()) throw error("unexpected end");
        return switch (s.charAt(i)) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Object literal(String word, Object v) {
        if (!s.startsWith(word, i)) throw error("unexpected token");
        i += word.length();
        return v;
    }

    private Map<String, Object> object() {
        var m = new LinkedHashMap<String, Object>();
        i++;
        ws();
        if (peek('}')) { i++; return m; }
        while (true) {
            ws();
            if (!peek('"')) throw error("expected object key");
            String key = string();
            ws();
            expect(':');
            m.put(key, value());
            ws();
            if (peek(',')) { i++; continue; }
            expect('}');
            return m;
        }
    }

    private List<Object> array() {
        var l = new ArrayList<Object>();
        i++;
        ws();
        if (peek(']')) { i++; return l; }
        while (true) {
            l.add(value());
            ws();
            if (peek(',')) { i++; continue; }
            expect(']');
            return l;
        }
    }

    private String string() {
        i++;
        var sb = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw error("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c != '\\') { sb.append(c); continue; }
            if (i >= s.length()) throw error("unterminated escape");
            char e = s.charAt(i++);
            switch (e) {
                case 'n' -> sb.append('\n');
                case 't' -> sb.append('\t');
                case 'r' -> sb.append('\r');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case '"', '\\', '/' -> sb.append(e);
                case 'u' -> {
                    if (i + 4 > s.length()) throw error("bad unicode escape");
                    sb.append((char) Integer.parseInt(s, i, i + 4, 16));
                    i += 4;
                }
                default -> throw error("bad escape");
            }
        }
    }

    private Number number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String t = s.substring(start, i);
        if (t.isEmpty()) throw error("unexpected character");
        try {
            if (t.indexOf('.') >= 0 || t.indexOf('e') >= 0 || t.indexOf('E') >= 0) return Double.parseDouble(t);
            return Long.parseLong(t);
        } catch (NumberFormatException e) {
            try { return new java.math.BigDecimal(t); } catch (NumberFormatException _) { throw error("bad number"); }
        }
    }

    public static String write(Object o) {
        var sb = new StringBuilder();
        write(o, sb, 0);
        return sb.append('\n').toString();
    }

    private static void write(Object o, StringBuilder sb, int indent) {
        switch (o) {
            case null -> sb.append("null");
            case String str -> quote(str, sb);
            case Boolean b -> sb.append(b);
            case Number n -> sb.append(n);
            case Map<?, ?> m -> {
                if (m.isEmpty()) { sb.append("{}"); return; }
                sb.append("{\n");
                var it = m.entrySet().iterator();
                while (it.hasNext()) {
                    var e = it.next();
                    sb.append("  ".repeat(indent + 1));
                    quote(String.valueOf(e.getKey()), sb);
                    sb.append(": ");
                    write(e.getValue(), sb, indent + 1);
                    sb.append(it.hasNext() ? ",\n" : "\n");
                }
                sb.append("  ".repeat(indent)).append('}');
            }
            case Collection<?> c -> {
                if (c.isEmpty()) { sb.append("[]"); return; }
                sb.append("[\n");
                var it = c.iterator();
                while (it.hasNext()) {
                    sb.append("  ".repeat(indent + 1));
                    write(it.next(), sb, indent + 1);
                    sb.append(it.hasNext() ? ",\n" : "\n");
                }
                sb.append("  ".repeat(indent)).append(']');
            }
            default -> quote(o.toString(), sb);
        }
    }

    private static void quote(String s, StringBuilder sb) {
        sb.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
