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
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A version pinned in a pom's own dependencyManagement, a direct child of its project (neither a profile's nor one in a
 * comment): an entry added, its elements made when missing; the rest of the pom left as written, its indentation and
 * line ends followed. A pom that already manages the artifact is left alone.
 */
record PomManagedEntry(Path file, String group, String artifact, String version) implements Step.Edit {

    private static final Pattern TAG = Pattern.compile("<!--.*?-->|<!\\[CDATA\\[.*?]]>|<\\?.*?\\?>|<(/?)([A-Za-z_][\\w.\\-:]*)[^>]*?(/?)>",
            Pattern.DOTALL);

    @Override
    public String shown() {
        return file.getFileName() + ": dependencyManagement " + group + ":" + artifact + " " + version;
    }

    @Override
    public String apply(String text) {
        String nl = text.contains("\r\n") ? "\r\n" : "\n";
        int project = -1, projectEnd = -1, management = -1, managementEnd = -1, dependencies = -1, dependenciesEnd = -1;
        int projectDependencies = -1;
        Deque<String> stack = new ArrayDeque<>();
        Matcher m = TAG.matcher(text);
        while (m.find()) {
            if (m.group(2) == null) continue;   // a comment, CDATA, a declaration
            String name = local(m.group(2));
            boolean closing = !m.group(1).isEmpty(), empty = !m.group(3).isEmpty();
            if (!closing) {
                String path = String.join("/", stack.reversed()) + (stack.isEmpty() ? "" : "/") + name;
                switch (path) {
                    case "project" -> project = m.end();
                    case "project/dependencyManagement" -> management = m.end();
                    case "project/dependencyManagement/dependencies" -> dependencies = m.end();
                    case "project/dependencies" -> projectDependencies = m.start();
                    default -> { }
                }
                if (!empty) stack.push(name);
            } else {
                String path = String.join("/", stack.reversed());
                switch (path) {
                    case "project" -> projectEnd = m.start();
                    case "project/dependencyManagement" -> managementEnd = m.start();
                    case "project/dependencyManagement/dependencies" -> dependenciesEnd = m.start();
                    default -> { }
                }
                if (!stack.isEmpty()) stack.pop();
            }
        }
        if (project < 0 || projectEnd < 0) return null;   // not a pom
        if (dependencies >= 0 && dependenciesEnd > dependencies && manages(text.substring(dependencies, dependenciesEnd))) return text;
        String unit = unit(text, project);
        String base = indentOf(text, project);   // the project's own indentation: none, usually
        String dep = String.join(nl, base + unit + unit + unit + "<dependency>",
                base + unit + unit + unit + unit + "<groupId>" + group + "</groupId>",
                base + unit + unit + unit + unit + "<artifactId>" + artifact + "</artifactId>",
                base + unit + unit + unit + unit + "<version>" + version + "</version>",
                base + unit + unit + unit + "</dependency>");
        if (dependenciesEnd >= 0) return insertBefore(text, dependenciesEnd, dep, nl, base + unit + unit);
        String deps = base + unit + unit + "<dependencies>" + nl + dep + nl + base + unit + unit + "</dependencies>";
        if (managementEnd >= 0) return insertBefore(text, managementEnd, deps, nl, base + unit);
        String block = base + unit + "<dependencyManagement>" + nl + deps + nl + base + unit + "</dependencyManagement>";
        // before the project's own dependencies, as poms usually order them; else last in the project
        return projectDependencies >= 0 ? insertBefore(text, projectDependencies, block, nl, base + unit)
                : insertBefore(text, projectEnd, block, nl, base);
    }

    /** Whether these managed dependencies already name the artifact. */
    private boolean manages(String dependencies) {
        var dep = Pattern.compile("<dependency>(.*?)</dependency>", Pattern.DOTALL).matcher(dependencies.replaceAll("(?s)<!--.*?-->", ""));
        while (dep.find()) {
            String body = dep.group(1);
            if (body.matches("(?s).*<groupId>\\s*" + Pattern.quote(group) + "\\s*</groupId>.*")
                    && body.matches("(?s).*<artifactId>\\s*" + Pattern.quote(artifact) + "\\s*</artifactId>.*")) return true;
        }
        return false;
    }

    /**
     * The block, its lines indented already, inserted before the tag at this index: on lines of their own above it when
     * the tag begins its line; else the tag's line broken, the tag put back at this indentation.
     */
    private static String insertBefore(String text, int index, String block, String nl, String tagIndent) {
        int lineStart = text.lastIndexOf('\n', index - 1) + 1;
        if (text.substring(lineStart, index).isBlank()) return text.substring(0, lineStart) + block + nl + text.substring(lineStart);
        return text.substring(0, index) + nl + block + nl + tagIndent + text.substring(index);
    }

    /** One level of indentation: what the project's first child line adds to the project's own. */
    private static String unit(String text, int projectContentStart) {
        var child = Pattern.compile("\\R([ \\t]+)<").matcher(text);
        String base = indentOf(text, projectContentStart);
        if (child.find(projectContentStart) && child.group(1).length() > base.length()) return child.group(1).substring(base.length());
        return "  ";
    }

    private static String indentOf(String text, int index) {
        int lineStart = text.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
        int i = lineStart;
        while (i < text.length() && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) i++;
        return text.substring(lineStart, Math.min(i, index));
    }

    private static String local(String name) {
        int colon = name.indexOf(':');
        return colon < 0 ? name : name.substring(colon + 1);
    }
}
