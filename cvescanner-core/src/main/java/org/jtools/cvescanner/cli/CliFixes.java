package org.jtools.cvescanner.cli;

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

import java.io.File;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.jtools.cvescanner.fix.FixOutcome;
import org.jtools.cvescanner.fix.FixPlan;
import org.jtools.cvescanner.fix.FixPlanner;
import org.jtools.cvescanner.fix.FixRequest;
import org.jtools.cvescanner.fix.Machine;
import org.jtools.cvescanner.fix.Step;
import org.jtools.cvescanner.fix.ToolRunner;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;

/**
 * --apply-fixes: the window's Apply fixes, on the command line. Every Maven or npm package the report keeps (those of
 * them --fix-packages names) that a project declares and a version fixes is planned, each plan said: its command, what
 * was checked, or why it cannot be applied. Nothing changes without --yes; a major version change needs --allow-major
 * too.
 */
final class CliFixes {

    /** A step longer than this is stopped, its files put back: an offline tool that waits is waiting for the network. */
    private static final Duration STEP_TIMEOUT = Duration.ofMinutes(5);

    /** What was done: how many fixes were applied, how many confirmed ones failed. */
    record Result(int applied, int failed) {}

    private CliFixes() {}

    static Result run(Options o, Path root, List<Finding> reported, PrintStream out) {
        return run(o, root, reported, out, Machine.current());
    }

    static Result run(Options o, Path root, List<Finding> reported, PrintStream out, Machine machine) {
        var requests = new ArrayList<FixRequest>();
        for (PackageSummary p : PackageSummary.of(reported)) {
            if (!o.fixPackages.isEmpty() && !o.fixPackages.contains(p.pkg())) continue;
            if ((p.ecosystem() != Ecosystem.MAVEN && p.ecosystem() != Ecosystem.NPM) || p.installed() || p.fixedIn().isEmpty()) continue;
            requests.add(FixRequest.of(p, reported, root));
        }
        out.println();
        out.println(I18n.text(o.yes ? "cli.fixes.title" : "cli.fixes.dryRun"));
        if (requests.isEmpty()) {
            out.println("  " + I18n.text("cli.fixes.none"));
            return new Result(0, 0);
        }
        String prefix = root.toAbsolutePath().normalize() + File.separator;
        var plans = new FixPlanner(root, machine).plan(requests);
        var runner = new ToolRunner(STEP_TIMEOUT);
        int applied = 0, failed = 0;
        for (FixPlan plan : plans) {
            var r = plan.request();
            out.println("  " + r.pkg() + "  " + r.from() + " -> " + r.to());
            if (!plan.applicable()) {
                out.println("      " + I18n.text("cli.fixes.notApplied", plan.notApplicable().text()));
                continue;
            }
            for (Step step : plan.steps()) out.println("      " + step.shown().replace(prefix, "").replace("→", "->"));
            if (plan.requirement() != null) out.println("      " + plan.requirement().text());
            plan.notes().forEach(note -> out.println("      " + note.text()));
            if (plan.majorJump() && !o.allowMajor) {
                out.println("      " + I18n.text(plan.majorVersionChange() ? "cli.fixes.majorJump" : "cli.fixes.askFirst"));
                continue;
            }
            if (!o.yes) continue;
            FixOutcome outcome = runner.run(plan, _ -> { });
            out.println("      => " + outcome.reason().text());
            if (outcome.applied()) applied++;
            else {
                failed++;
                outcome.log().lines().filter(line -> !line.isBlank()).forEach(line -> out.println("         " + line));
            }
        }
        if (o.yes && applied > 0) out.println("  " + I18n.text("cli.fixes.rescan"));
        return new Result(applied, failed);
    }
}
