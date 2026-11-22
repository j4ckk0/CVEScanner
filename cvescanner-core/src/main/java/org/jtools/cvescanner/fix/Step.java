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
import java.util.List;
import java.util.Map;

/**
 * One thing done to apply a fix: a text edit first, if any (Gradle, which has no command for it), then a command of
 * the project's build tool, in its offline mode.
 *
 * @param touched the files the step may change: kept before it runs, put back should it fail
 */
public record Step(TextEdit edit, List<String> command, Path directory, Map<String, String> environment, List<Path> touched) {

    /** In this file, this exact text, once, becomes that one. */
    public record TextEdit(Path file, String before, String after) {}

    public Step {
        command = List.copyOf(command);
        environment = Map.copyOf(environment);
        touched = List.copyOf(touched);
    }

    /** The step as a person would type it: the command, after the edit it needs. */
    public String shown() {
        return withEdit(String.join(" ", command));
    }

    /** The step in short, to read at a glance: the program by its name (npm, not /usr/local/bin/npm.cmd). */
    public String brief() {
        if (command.isEmpty()) return withEdit("");
        Path program = Path.of(command.getFirst()).getFileName();
        String name = program == null ? command.getFirst() : program.toString().replaceFirst("(?i)\\.(cmd|bat|exe)$", "");
        var rest = command.subList(1, command.size());
        return withEdit(rest.isEmpty() ? name : name + " " + String.join(" ", rest));
    }

    private String withEdit(String cmd) {
        return edit == null ? cmd : edit.file().getFileName() + ": " + edit.before() + " → " + edit.after() + "; " + cmd;
    }
}
