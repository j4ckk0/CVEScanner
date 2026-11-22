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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * Runs the steps of the fixes confirmed: the one place the program starts another one, and only a build tool of the
 * scanned project, in its offline mode, once the user has seen the command (README, "No network"). Each step's files
 * are kept before it runs and put back should it fail, time out or not start; its output is kept for the log. The
 * tool reads no input: its standard input is closed, so that one asking a question fails rather than waits.
 */
public final class ToolRunner {

    private final Duration timeout;

    public ToolRunner(Duration timeout) {
        this.timeout = timeout;
    }

    public FixOutcome run(FixPlan plan, Consumer<String> progress) {
        var log = new StringBuilder();
        var kept = new LinkedHashMap<Path, byte[]>();   // every step's files, the first time seen: a fix is undone whole
        for (Step step : plan.steps()) {
            progress.accept(step.brief());
            log.append("$ ").append(step.shown()).append('\n');
            try {
                keep(step.touched(), kept);
            } catch (IOException e) {
                restore(kept, log);
                return new FixOutcome(plan, false, Phrase.of("fix.outcome.error", program(step), e.getMessage()), log.toString());
            }
            Phrase failure = runStep(step, log);
            if (failure != null) {
                restore(kept, log);
                return new FixOutcome(plan, false, failure, log.toString());
            }
        }
        if (unchanged(kept)) return new FixOutcome(plan, false, Phrase.of("fix.outcome.unchanged"), log.toString());
        return new FixOutcome(plan, true, Phrase.of("fix.outcome.applied"), log.toString());
    }

    /** The step done: null when it went well, else why not. */
    private Phrase runStep(Step step, StringBuilder log) {
        Path output = null;
        try {
            if (step.edit() != null) {
                var e = step.edit();
                String text = Files.isRegularFile(e.file()) ? ProjectFiles.readText(e.file()) : "";   // a file it makes
                String edited = e.apply(text);
                if (edited == null) return Phrase.of("fix.outcome.editGone", e.file().getFileName());
                Files.writeString(e.file(), edited, StandardCharsets.UTF_8);
            }
            output = Files.createTempFile("cvescanner-fix", ".log");
            var builder = new ProcessBuilder(command(step.command())).directory(step.directory().toFile())
                    .redirectErrorStream(true).redirectOutput(output.toFile());
            builder.environment().putAll(step.environment());
            Process process = builder.start();
            process.getOutputStream().close();
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                process.waitFor(10, TimeUnit.SECONDS);
            }
            log.append(new String(Files.readAllBytes(output), Charset.defaultCharset())).append('\n');   // leniently: a console's bytes
            if (!finished) return Phrase.of("fix.outcome.timeout", program(step), timeout.toMinutes());
            if (process.exitValue() != 0) return Phrase.of("fix.outcome.failed", program(step), process.exitValue());
            return null;
        } catch (IOException e) {
            return Phrase.of("fix.outcome.error", program(step), e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Phrase.of("fix.outcome.error", program(step), e.getMessage());
        } finally {
            if (output != null) {
                try {
                    Files.deleteIfExists(output);
                } catch (IOException _) {
                    // a temporary file left behind
                }
            }
        }
    }

    /** A Windows batch file (mvn.cmd, gradlew.bat) is run through cmd.exe, as Windows starts it. */
    static List<String> command(List<String> command) {
        String exe = command.getFirst().toLowerCase(java.util.Locale.ROOT);
        if (!exe.endsWith(".cmd") && !exe.endsWith(".bat")) return command;
        var out = new ArrayList<>(List.of("cmd.exe", "/c"));
        out.addAll(command);
        return out;
    }

    private static String program(Step step) {
        return Path.of(step.command().getFirst()).getFileName().toString();
    }

    /** The files as they are before their first step, null for one not there (to delete should a step make it). */
    private static void keep(List<Path> files, Map<Path, byte[]> kept) throws IOException {
        for (Path f : files) if (!kept.containsKey(f)) kept.put(f, Files.isRegularFile(f) ? Files.readAllBytes(f) : null);
    }

    /** Every file as it was: the tool ended well yet changed nothing (a version it does not manage, as in a plugin). */
    private static boolean unchanged(Map<Path, byte[]> kept) {
        for (var e : kept.entrySet()) {
            try {
                byte[] now = Files.isRegularFile(e.getKey()) ? Files.readAllBytes(e.getKey()) : null;
                if (!java.util.Arrays.equals(now, e.getValue())) return false;
            } catch (IOException _) {
                return false;
            }
        }
        return true;
    }

    private static void restore(Map<Path, byte[]> kept, StringBuilder log) {
        kept.forEach((file, bytes) -> {
            try {
                if (bytes == null) Files.deleteIfExists(file);
                else Files.write(file, bytes);
            } catch (IOException e) {
                log.append("! ").append(file).append(": ").append(e.getMessage()).append('\n');
            }
        });
    }
}
