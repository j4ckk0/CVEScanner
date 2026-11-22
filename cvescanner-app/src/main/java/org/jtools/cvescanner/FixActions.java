package org.jtools.cvescanner;

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

import java.awt.Component;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import org.jtools.cvescanner.fix.FixOutcome;
import org.jtools.cvescanner.fix.FixPlan;
import org.jtools.cvescanner.fix.FixPlanner;
import org.jtools.cvescanner.fix.FixRequest;
import org.jtools.cvescanner.fix.Machine;
import org.jtools.cvescanner.fix.ToolRunner;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanResult;

/**
 * Apply fixes: the package versions ticked in the Packages tab upgraded by each project's own build tool, offline. The
 * plans are made in the background and shown (FixDialog); those confirmed run one after another (ToolRunner); then
 * what they gave is shown and the folder scanned again.
 */
final class FixActions {

    /** A step longer than this is stopped, its files put back: an offline tool that waits is waiting for the network. */
    private static final Duration STEP_TIMEOUT = Duration.ofMinutes(5);

    /** What the window gives: the scan shown, its findings reported, its status line, a new scan, its busy state. */
    interface Host {
        ScanResult result();

        List<Finding> reported();

        void say(Supplier<String> message);

        void rescan();

        void busy(boolean busy);

        /** A scan runs: nothing is applied meanwhile. */
        boolean scanning();
    }

    private final Component owner;
    private final FindingTables tables;
    private final Host host;
    private final JButton button = new JButton();
    private boolean running;

    FixActions(Component owner, I18nLabels labels, FindingTables tables, Host host) {
        this.owner = owner;
        this.tables = tables;
        this.host = host;
        button.setName("applyFixes");
        button.addActionListener(_ -> apply());
        tables.onTicked = this::update;
        labels.on(this::update);
    }

    JButton button() {
        return button;
    }

    /** The button says how many package versions are ticked; it acts once a scan is shown and nothing runs. */
    void update() {
        int n = tables.ticked.size();
        button.setText(I18n.text("toolbar.applyFixes", n));
        button.setEnabled(n > 0 && host.result() != null && !running && !host.scanning());
    }

    private void apply() {
        ScanResult result = host.result();
        if (result == null || running || host.scanning()) return;
        var reported = host.reported();
        var requests = new ArrayList<FixRequest>();
        for (PackageSummary p : PackageSummary.of(reported))   // all the findings, whatever the filters show
            if (tables.ticked.contains(FindingTables.PackageKey.of(p))) requests.add(FixRequest.of(p, reported, result.root()));
        if (requests.isEmpty()) return;
        setRunning(true);
        host.say(() -> I18n.text("fixDialog.checking", requests.size()));
        new SwingWorker<List<FixPlan>, Void>() {
            @Override
            protected List<FixPlan> doInBackground() {
                return new FixPlanner(result.root(), Machine.current()).plan(requests);
            }

            @Override
            protected void done() {
                List<FixPlan> plans;
                try {
                    plans = get();
                } catch (InterruptedException | ExecutionException e) {
                    failed(e);
                    return;
                }
                host.busy(false);   // the checks are done: no progress shown while the user chooses
                host.say(() -> I18n.text("fixDialog.checked", plans.size()));
                var chosen = FixDialog.confirm(owner, plans, result.root());
                if (chosen.isEmpty()) {
                    setRunning(false);
                    host.say(() -> I18n.text("fixDialog.cancelled"));
                    return;
                }
                runFixes(chosen);
            }
        }.execute();
    }

    private void runFixes(List<FixPlan> plans) {
        host.busy(true);
        new SwingWorker<List<FixOutcome>, String>() {
            @Override
            protected List<FixOutcome> doInBackground() {
                var runner = new ToolRunner(STEP_TIMEOUT);
                var outcomes = new ArrayList<FixOutcome>();
                for (FixPlan plan : plans) {
                    var r = plan.request();
                    outcomes.add(runner.run(plan, step -> publish(I18n.text("fixDialog.running", r.pkg(), r.to(), step))));
                }
                return outcomes;
            }

            @Override
            protected void process(List<String> steps) {
                String last = steps.getLast();
                host.say(() -> last);
            }

            @Override
            protected void done() {
                List<FixOutcome> outcomes;
                try {
                    outcomes = get();
                } catch (InterruptedException | ExecutionException e) {
                    failed(e);
                    return;
                }
                for (FixOutcome o : outcomes)
                    if (o.applied()) {
                        var r = o.plan().request();
                        tables.ticked.remove(new FindingTables.PackageKey(r.ecosystem(), r.pkg(), r.from()));
                    }
                setRunning(false);
                long applied = outcomes.stream().filter(FixOutcome::applied).count();
                host.say(() -> I18n.text("fixDialog.results.count", applied, outcomes.size() - applied));
                FixDialog.results(owner, outcomes);
                host.rescan();
            }
        }.execute();
    }

    private void setRunning(boolean running) {
        this.running = running;
        host.busy(running);
        update();
    }

    private void failed(Exception e) {
        setRunning(false);
        Throwable cause = e instanceof ExecutionException && e.getCause() != null ? e.getCause() : e;
        JOptionPane.showMessageDialog(owner, SwingText.plain(String.valueOf(cause.getMessage())), I18n.text("fixDialog.title"),
                JOptionPane.ERROR_MESSAGE);
    }
}
