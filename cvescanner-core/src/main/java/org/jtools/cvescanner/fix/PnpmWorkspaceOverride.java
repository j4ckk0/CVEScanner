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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An override written into pnpm-workspace.yaml, where pnpm 10 and later read them: under its "overrides" key, made
 * when missing, the file made when there is none; the rest of the file left as written.
 */
record PnpmWorkspaceOverride(Path file, String key, String value) implements Step.Edit {

    private static final Pattern OVERRIDES = Pattern.compile("(?m)^overrides:[ \\t]*(\\{[ \\t]*\\})?[ \\t]*(\\r?\\n|$)");

    @Override
    public String shown() {
        return file.getFileName() + ": overrides " + entry();
    }

    private String entry() {
        return "'" + key.replace("'", "''") + "': " + value;
    }

    @Override
    public String apply(String text) {
        String nl = text.contains("\r\n") ? "\r\n" : "\n";
        Matcher m = OVERRIDES.matcher(text);
        if (!m.find()) {
            String sep = text.isEmpty() || text.endsWith("\n") ? "" : nl;
            return text + sep + "overrides:" + nl + "  " + entry() + nl;
        }
        int after = m.end();
        String rest = text.substring(after);
        // the entries' indentation: the next line's, when it is one of them
        Matcher next = Pattern.compile("^([ \\t]+)\\S").matcher(rest);
        String indent = m.group(1) == null && next.find() ? next.group(1) : "  ";
        String line = indent + entry() + nl;
        if (m.group(1) != null) return text.substring(0, m.start()) + "overrides:" + nl + line + rest;   // "overrides: {}"
        return text.substring(0, after) + (m.group(2).isEmpty() ? nl : "") + line + rest;
    }
}
