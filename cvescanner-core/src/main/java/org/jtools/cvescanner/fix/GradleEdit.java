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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.project.MavenReader;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * Where a Gradle build writes a dependency's version, to change it (Gradle has no command for it): a literal
 * 'group:artifact:version', a variable it names (ext, val, gradle.properties), the named form (group:, name:,
 * version:), or a version catalog's entry and its [versions] reference. Only a version written as the one the scan
 * read is changed; anything else gives no edit, and the fix is not applied.
 */
final class GradleEdit {

    private GradleEdit() {}

    static Step.TextEdit of(Path file, String scope, String group, String artifact, String from, String to) throws IOException {
        String text = ProjectFiles.readText(file);
        return file.getFileName().toString().endsWith(".versions.toml") ? catalog(file, text, scope, group, artifact, from, to)
                : build(file, text, group, artifact, from, to);
    }

    private static Step.TextEdit build(Path file, String text, String group, String artifact, String from, String to) throws IOException {
        String coordinates = Pattern.quote(group + ":" + artifact + ":");
        Matcher literal = Pattern.compile("(['\"])" + coordinates + Pattern.quote(from) + "\\1").matcher(text);
        if (literal.find()) return new Step.TextEdit(file, literal.group(), literal.group().replace(":" + from, ":" + to));
        Matcher named = Pattern.compile("group\\s*:\\s*(['\"])" + Pattern.quote(group) + "\\1\\s*,\\s*name\\s*:\\s*(['\"])"
                + Pattern.quote(artifact) + "\\2\\s*,\\s*version\\s*:\\s*(['\"])" + Pattern.quote(from) + "\\3").matcher(text);
        if (named.find()) return new Step.TextEdit(file, named.group(), replaceLast(named.group(), from, to));
        Matcher variable = Pattern.compile("(['\"])" + coordinates + "\\$\\{?(\\w+)\\}?\\1").matcher(text);
        if (variable.find()) {
            String name = variable.group(2);
            Matcher assigned = Pattern.compile("\\b" + Pattern.quote(name) + "\\s*=\\s*(['\"])" + Pattern.quote(from) + "\\1").matcher(text);
            if (assigned.find()) return new Step.TextEdit(file, assigned.group(), replaceLast(assigned.group(), from, to));
            for (Path props : List.of(file.resolveSibling("gradle.properties"))) {
                if (!Files.isRegularFile(props)) continue;
                Matcher line = Pattern.compile("(?m)^\\s*" + Pattern.quote(name) + "\\s*[=:]\\s*" + Pattern.quote(from) + "\\s*$")
                        .matcher(ProjectFiles.readText(props));
                if (line.find()) return new Step.TextEdit(props, line.group(), replaceLast(line.group(), from, to));
            }
        }
        return null;
    }

    private static Step.TextEdit catalog(Path file, String text, String scope, String group, String artifact, String from, String to) {
        String alias = scope.startsWith("catalog:") ? scope.substring("catalog:".length()) : null;
        for (String line : text.lines().toList()) {
            boolean names = line.contains("\"" + group + ":" + artifact)
                    || (line.matches(".*group\\s*=\\s*\"" + Pattern.quote(group) + "\".*") && line.matches(".*name\\s*=\\s*\"" + Pattern.quote(artifact) + "\".*"));
            if (!names || (alias != null && !line.strip().startsWith(alias))) continue;
            Matcher ref = Pattern.compile("version\\.ref\\s*=\\s*\"([^\"]+)\"").matcher(line);
            if (ref.find()) {
                Matcher version = Pattern.compile("(?m)^\\s*" + Pattern.quote(ref.group(1)) + "\\s*=\\s*\"" + Pattern.quote(from) + "\"").matcher(text);
                return version.find() ? new Step.TextEdit(file, version.group(), replaceLast(version.group(), from, to)) : null;
            }
            if (line.contains(group + ":" + artifact + ":" + from + "\""))
                return new Step.TextEdit(file, line, line.replace(group + ":" + artifact + ":" + from + "\"", group + ":" + artifact + ":" + to + "\""));
            Matcher version = Pattern.compile("version\\s*=\\s*\"" + Pattern.quote(from) + "\"").matcher(line);
            if (version.find()) return new Step.TextEdit(file, line, line.substring(0, version.start()) + replaceLast(version.group(), from, to)
                    + line.substring(version.end()));
        }
        return null;
    }

    private static String replaceLast(String s, String from, String to) {
        int i = s.lastIndexOf(from);
        return s.substring(0, i) + to + s.substring(i + from.length());
    }

    private static final List<Pattern> JAVA = List.of(
            Pattern.compile("JavaLanguageVersion\\.of\\(\\s*(\\d+)\\s*\\)"),
            Pattern.compile("jvmToolchain\\(\\s*(\\d+)\\s*\\)"),
            Pattern.compile("options\\.release(?:\\.set\\(\\s*|\\s*=\\s*)(\\d+)"),
            Pattern.compile("targetCompatibility\\s*=\\s*(?:JavaVersion\\.VERSION_)?['\"]?(1[._]\\d+|\\d+)"),
            Pattern.compile("sourceCompatibility\\s*=\\s*(?:JavaVersion\\.VERSION_)?['\"]?(1[._]\\d+|\\d+)"));

    /** The Java a Gradle project is built for (its toolchain, release, target or source compatibility); empty when none says. */
    static OptionalInt javaTarget(Path project) throws IOException {
        for (String name : List.of("build.gradle", "build.gradle.kts")) {
            Path build = project.resolve(name);
            if (!Files.isRegularFile(build)) continue;
            String text = ProjectFiles.readText(build);
            for (Pattern p : JAVA) {
                Matcher m = p.matcher(text);
                if (m.find()) return MavenReader.javaVersion(m.group(1).replace('_', '.'));
            }
        }
        return OptionalInt.empty();
    }
}
