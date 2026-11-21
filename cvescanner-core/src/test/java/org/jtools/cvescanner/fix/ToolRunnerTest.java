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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jtools.cvescanner.model.Ecosystem;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The steps run by made-up tools (shell scripts): done, failed or stopped, the files put back whenever a step does
 * not end well, a fix undone whole. Not on Windows, where these tools would be batch files.
 */
@DisabledOnOs(OS.WINDOWS)
class ToolRunnerTest {

    @TempDir
    Path dir;

    private FixPlan plan(Step... steps) {
        return new FixPlan(new FixRequest(Ecosystem.NPM, "lodash", "4.17.15", "4.17.21", List.of()), List.of(steps), null, null, false, List.of());
    }

    private Path tool(String name, String script) throws IOException {
        return new FakeMachine(dir).program(name, script);
    }

    @Test
    void aStepThatEndsWellLeavesItsChangesItsOutputLogged() throws IOException {
        Path file = Files.writeString(dir.resolve("package.json"), "old");
        Path npm = tool("npm", "read answer; echo installing \"$1\" \"$npm_config_offline\"; printf new > package.json");
        var progress = new ArrayList<String>();
        var outcome = new ToolRunner(Duration.ofSeconds(30)).run(plan(new Step(null, List.of(npm.toString(), "install"), dir,
                Map.of("npm_config_offline", "true"), List.of(file))), progress::add);
        assertTrue(outcome.applied(), outcome.log());
        assertEquals("new", Files.readString(file));
        assertTrue(outcome.log().contains("installing install true"), outcome.log());
        assertEquals(1, progress.size());
    }

    @Test
    void aFailingStepPutsBackEveryFileOfTheFixAndRemovesThoseItMade() throws IOException {
        Path a = Files.writeString(dir.resolve("a.txt"), "a"), b = Files.writeString(dir.resolve("b.txt"), "b"), made = dir.resolve("made.lock");
        Path ok = tool("ok", "printf A > a.txt"), bad = tool("bad", "printf B > b.txt; printf x > made.lock; echo broken; exit 3");
        var outcome = new ToolRunner(Duration.ofSeconds(30)).run(plan(new Step(null, List.of(ok.toString()), dir, Map.of(), List.of(a)),
                new Step(null, List.of(bad.toString()), dir, Map.of(), List.of(b, made))), _ -> { });
        assertFalse(outcome.applied());
        assertEquals("fix.outcome.failed", outcome.reason().key());
        assertEquals(List.of("bad", 3), outcome.reason().arguments());
        assertEquals("a", Files.readString(a), "the first step, done, is undone too");
        assertEquals("b", Files.readString(b));
        assertFalse(Files.exists(made));
        assertTrue(outcome.log().contains("broken"));
    }

    @Test
    void aStepTooLongIsStoppedItsFilesPutBack() throws IOException {
        Path file = Files.writeString(dir.resolve("pom.xml"), "<old/>");
        Path slow = tool("mvn", "printf '<new/>' > pom.xml; sleep 30");
        long start = System.nanoTime();
        var outcome = new ToolRunner(Duration.ofSeconds(1)).run(plan(new Step(null, List.of(slow.toString()), dir, Map.of(), List.of(file))), _ -> { });
        assertTrue(System.nanoTime() - start < 20_000_000_000L, "stopped, not waited for");
        assertEquals("fix.outcome.timeout", outcome.reason().key());
        assertEquals("<old/>", Files.readString(file));
    }

    @Test
    void aGradleEditIsUndoneWhenGradleCannotResolveIt() throws IOException {
        Path build = Files.writeString(dir.resolve("build.gradle"), "implementation 'g:a:1.0'\n");
        Path gradle = tool("gradle", "grep -q 'g:a:2.0' build.gradle && exit 1");
        var edit = new Step.TextEdit(build, "'g:a:1.0'", "'g:a:2.0'");
        var outcome = new ToolRunner(Duration.ofSeconds(30)).run(plan(new Step(edit, List.of(gradle.toString()), dir, Map.of(), List.of(build))), _ -> { });
        assertFalse(outcome.applied());
        assertEquals("implementation 'g:a:1.0'\n", Files.readString(build));
        var gone = new ToolRunner(Duration.ofSeconds(30)).run(plan(new Step(new Step.TextEdit(build, "'g:a:9.9'", "'g:a:10'"),
                List.of(gradle.toString()), dir, Map.of(), List.of(build))), _ -> { });
        assertEquals("fix.outcome.editGone", gone.reason().key());
    }
}
