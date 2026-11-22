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
 * One thing done to apply a fix: an edit of a file first, if any (Gradle's build file, which no command changes; a pin
 * in a pom's dependencyManagement; an override in package.json or pnpm-workspace.yaml), then a command of the
 * project's build tool, in its offline mode.
 *
 * @param touched the files the step may change: kept before it runs, put back should it fail
 */
public record Step(Edit edit, List<String> command, Path directory, Map<String, String> environment, List<Path> touched) {

    /**
     * An edit of a file, worked out on its text as it is when the step runs: another fix of the same project may have
     * changed it since the plans were made.
     */
    public interface Edit {
        Path file();

        /** The text the edit gives; null when it can no longer be made (what it replaces is gone). */
        String apply(String text);

        /** As a person reads it: the file, what changes. */
        String shown();

        /**
         * The file the tool must change for the step to have done anything, its lockfile: an override the tool
         * ignores changes package.json and nothing else. Null when the edit is the change itself.
         */
        default Path proof() {
            return null;
        }
    }

    /** In this file, this exact text becomes that one. */
    public record TextEdit(Path file, String before, String after) implements Edit {
        @Override
        public String apply(String text) {
            return text.contains(before) ? text.replace(before, after) : null;
        }

        @Override
        public String shown() {
            return file.getFileName() + ": " + before + " → " + after;
        }
    }

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
        return edit == null ? cmd : edit.shown() + "; " + cmd;
    }
}
