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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.project.MavenReader;
import org.jtools.cvescanner.project.NpmReader;
import org.jtools.cvescanner.project.ProjectFiles;

/**
 * How each fix asked for would be applied, by the project's own build tool in its offline mode, or why it cannot be:
 * the tool is not installed (nothing is installed), the new version needs a newer Java or Node than the project
 * targets or that cannot be checked offline, the dependency is transitive, the version is written in a way no tool
 * changes. Nothing is run here: the plans are shown first, and run (ToolRunner) once confirmed.
 */
public final class FixPlanner {

    private static final Map<String, String> NPM_OFFLINE = Map.of("npm_config_offline", "true");
    private static final Map<String, String> YARN_BERRY_OFFLINE = Map.of("YARN_ENABLE_NETWORK", "0", "YARN_ENABLE_SCRIPTS", "0");
    private static final Pattern LEADING_NUMBER = Pattern.compile("^\\D*(\\d+)");

    private final Path root;
    private final Machine machine;
    private MavenReader.Tree poms;

    public FixPlanner(Path root, Machine machine) {
        this.root = root.toAbsolutePath().normalize();
        this.machine = machine;
    }

    /**
     * The plans of these requests. Packages whose version is one shared place (a Maven property, a Gradle variable:
     * the Spring modules' spring.version) are all raised to the highest of their fixes, each planned and checked again
     * for it: applied one after another, they would otherwise leave the place at the last one's, below another's fix.
     */
    public List<FixPlan> plan(List<FixRequest> requests) {
        var plans = new ArrayList<FixPlan>(requests.stream().map(this::plan).toList());
        var bySite = new LinkedHashMap<String, List<Integer>>();
        for (int i = 0; i < plans.size(); i++)
            for (String site : sharedSites(plans.get(i))) bySite.computeIfAbsent(site, _ -> new ArrayList<>()).add(i);
        for (var group : bySite.values()) {
            if (group.size() < 2) continue;
            String highest = group.stream().map(i -> plans.get(i).request().to()).max(Ecosystem.MAVEN.versionOrder()).orElseThrow();
            String names = String.join(", ", group.stream().map(i -> plans.get(i).request().pkg()).toList());
            for (int i : group) {
                var r = plans.get(i).request();
                FixPlan p = r.to().equals(highest) ? plans.get(i)
                        : plan(new FixRequest(r.ecosystem(), r.pkg(), r.from(), highest, r.declarations()));
                plans.set(i, p.withNote(Phrase.of("fix.note.shared", names, highest)));
            }
        }
        return List.copyOf(plans);
    }

    /** The places a plan changes that other packages' versions may come from: a Maven property, a Gradle variable. */
    private static List<String> sharedSites(FixPlan plan) {
        var sites = new ArrayList<String>();
        for (Step step : plan.steps()) {
            for (String arg : step.command())
                if (arg.startsWith("-Dproperty=")) sites.add(step.touched().getFirst() + " " + arg);
            var e = step.edit();
            if (e != null && !e.before().contains(plan.request().pkg())) sites.add(e.file() + " " + e.before());
        }
        return sites;
    }

    FixPlan plan(FixRequest r) {
        if (r.to() == null || r.to().isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.noFix"));
        if (r.ecosystem() == Ecosystem.COTS) return FixPlan.not(r, Phrase.of("fix.reason.cots"));
        if (r.declarations().isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notDeclared"));
        try {
            return r.ecosystem() == Ecosystem.NPM ? npm(r) : java(r);
        } catch (IOException e) {
            return FixPlan.not(r, Phrase.of("fix.reason.unreadable", e.getMessage()));
        }
    }

    // ---------------------------------------------------------------------------------------- Maven, Gradle
    private FixPlan java(FixRequest r) throws IOException {
        int colon = r.pkg().indexOf(':');
        String group = r.pkg().substring(0, colon), artifact = r.pkg().substring(colon + 1);
        var steps = new LinkedHashMap<String, Step>();   // one per file and action, two modules sharing one parent's
        OptionalInt target = OptionalInt.empty();
        for (var d : r.declarations()) {
            String name = d.file().getFileName().toString();
            OptionalInt t;
            if (name.equals("pom.xml")) {
                var site = poms().versionSite(d.file(), group, artifact);
                if (site.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.versionNotFound", rel(d.file())));
                Path pom = site.get().pom();
                Optional<Path> mvn = machine.program("mvn", "mvnw", pom.getParent(), root);
                if (mvn.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notInstalled", "mvn"));
                if (!versionsPluginCached()) return FixPlan.not(r, Phrase.of("fix.reason.versionsPlugin"));
                var command = new ArrayList<>(List.of(mvn.get().toString(), "-o", "-B", "-q", "-N", "-f", pom.toString()));
                if (site.get().literal())
                    command.addAll(List.of("versions:use-dep-version", "-Dincludes=" + r.pkg(), "-DdepVersion=" + r.to(),
                            "-DforceVersion=true", "-DprocessDependencyManagement=true", "-DgenerateBackupPoms=false"));
                else
                    command.addAll(List.of("versions:set-property", "-Dproperty=" + site.get().property(), "-DnewVersion=" + r.to(),
                            "-DgenerateBackupPoms=false"));
                steps.putIfAbsent(pom + " " + site.get().property(), new Step(null, command, pom.getParent(), Map.of(), List.of(pom)));
                t = poms().javaTarget(d.file());
            } else {
                Step.TextEdit edit = GradleEdit.of(d.file(), d.scope(), group, artifact, r.from(), r.to());
                if (edit == null) return FixPlan.not(r, Phrase.of("fix.reason.versionNotFound", rel(d.file())));
                Path project = gradleProject(d.file());
                Optional<Path> gradle = machine.program("gradle", "gradlew", project, root);
                if (gradle.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notInstalled", "gradle"));
                var command = List.of(gradle.get().toString(), "--offline", "-q", "-p", project.toString(), "dependencies");
                steps.putIfAbsent(edit.file() + " " + edit.before(), new Step(edit, command, project, Map.of(), List.of(edit.file())));
                t = GradleEdit.javaTarget(project);
            }
            if (t.isPresent() && (target.isEmpty() || t.getAsInt() < target.getAsInt())) target = t;
        }
        Phrase requirement;
        if (target.isEmpty()) {
            requirement = Phrase.of("fix.requirement.noJavaTarget");
        } else {
            OptionalInt needs = ArtifactJava.of(machine, group, artifact, r.to());
            if (needs.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.javaUnknown", r.to()));
            if (needs.getAsInt() > target.getAsInt())
                return FixPlan.not(r, Phrase.of("fix.reason.javaTooNew", r.to(), needs.getAsInt(), target.getAsInt()));
            requirement = Phrase.of("fix.requirement.java", needs.getAsInt(), target.getAsInt());
        }
        return new FixPlan(r, List.copyOf(steps.values()), null, requirement, majorJump(r), List.of());
    }

    private MavenReader.Tree poms() throws IOException {
        if (poms == null) poms = MavenReader.Tree.of(ProjectFiles.find(root).poms);
        return poms;
    }

    private boolean versionsPluginCached() {
        Path plugin = machine.mavenRepository().resolve("org/codehaus/mojo/versions-maven-plugin");
        if (!Files.isDirectory(plugin)) return false;
        try (Stream<Path> versions = Files.list(plugin)) {
            return versions.anyMatch(v -> {
                try (Stream<Path> files = Files.list(v)) {
                    return files.anyMatch(f -> f.getFileName().toString().endsWith(".jar"));
                } catch (IOException _) {
                    return false;
                }
            });
        } catch (IOException _) {
            return false;
        }
    }

    /** The Gradle project a build file or a catalog belongs to: the nearest folder up with a settings file, else its own. */
    private Path gradleProject(Path file) {
        Path own = file.getParent();
        if (file.getFileName().toString().endsWith(".versions.toml") && own.getFileName() != null
                && own.getFileName().toString().equals("gradle")) own = own.getParent();
        for (Path dir = own; dir != null && dir.startsWith(root); dir = dir.getParent())
            if (Files.isRegularFile(dir.resolve("settings.gradle")) || Files.isRegularFile(dir.resolve("settings.gradle.kts"))) return dir;
        return own;
    }

    // ---------------------------------------------------------------------------------------- npm, yarn, pnpm
    private FixPlan npm(FixRequest r) throws IOException {
        var steps = new LinkedHashMap<Path, Step>();
        String projectNode = null;
        for (var d : r.declarations()) {
            if (d.scope().startsWith("transitive")) return FixPlan.not(r, Phrase.of("fix.reason.transitive"));
            if (d.scope().equals("peerDependencies")) return FixPlan.not(r, Phrase.of("fix.reason.peer"));
            Path dir = d.file().getParent();
            Path packageJson = dir.resolve("package.json");
            if (!Files.isRegularFile(packageJson)) return FixPlan.not(r, Phrase.of("fix.reason.versionNotFound", rel(d.file())));
            var json = Json.obj(Json.parse(ProjectFiles.readText(packageJson)));
            boolean dev = Json.obj(json.get("devDependencies")).containsKey(r.pkg()) && !Json.obj(json.get("dependencies")).containsKey(r.pkg());
            String node = Json.str(Json.obj(json.get("engines")), "node");
            if (node != null) projectNode = node;
            String spec = r.pkg() + "@" + r.to();
            Step step;
            if (Files.isRegularFile(dir.resolve("yarn.lock"))) {
                Optional<Path> yarn = machine.program("yarn", null, dir, root);
                if (yarn.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notInstalled", "yarn"));
                var touched = List.of(packageJson, dir.resolve("yarn.lock"));
                if (yarnBerry(dir))
                    step = new Step(null, List.of(yarn.get().toString(), "up", spec), dir, YARN_BERRY_OFFLINE, touched);
                else {
                    var command = new ArrayList<>(List.of(yarn.get().toString(), "add", spec, "--offline", "--ignore-scripts"));
                    if (dev) command.add("--dev");
                    step = new Step(null, command, dir, Map.of(), touched);
                }
            } else if (Files.isRegularFile(dir.resolve("pnpm-lock.yaml"))) {
                Optional<Path> pnpm = machine.program("pnpm", null, dir, root);
                if (pnpm.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notInstalled", "pnpm"));
                var command = new ArrayList<>(List.of(pnpm.get().toString(), "add", spec, "--offline", "--ignore-scripts"));
                if (dev) command.add("-D");
                step = new Step(null, command, dir, Map.of(), List.of(packageJson, dir.resolve("pnpm-lock.yaml")));
            } else {
                Optional<Path> npm = machine.program("npm", null, dir, root);
                if (npm.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.notInstalled", "npm"));
                var command = List.of(npm.get().toString(), "install", spec, "--offline", "--ignore-scripts", dev ? "--save-dev" : "--save");
                step = new Step(null, command, dir, NPM_OFFLINE,
                        List.of(packageJson, dir.resolve("package-lock.json"), dir.resolve("npm-shrinkwrap.json")));
            }
            steps.putIfAbsent(dir, step);
        }
        Phrase requirement = null;
        if (projectNode != null) {
            Optional<String> needs = NodeEngines.of(machine, r.pkg(), r.to());
            if (needs.isEmpty()) return FixPlan.not(r, Phrase.of("fix.reason.nodeUnknown", r.to()));
            String lowestNeeded = needs.get().isEmpty() ? null : NpmReader.minVersion(needs.get()).version();
            String lowestTargeted = NpmReader.minVersion(projectNode).version();
            if (lowestNeeded != null && lowestTargeted != null && Ecosystem.NPM.compare(lowestNeeded, lowestTargeted) > 0)
                return FixPlan.not(r, Phrase.of("fix.reason.nodeTooNew", r.to(), needs.get(), projectNode));
            requirement = needs.get().isEmpty() ? Phrase.of("fix.requirement.nodeAny", projectNode)
                    : Phrase.of("fix.requirement.node", needs.get(), projectNode);
        }
        return new FixPlan(r, List.copyOf(steps.values()), null, requirement, majorJump(r), List.of());
    }

    /** Yarn 2 and later: a .yarnrc.yml beside, or a lockfile of their format. */
    private static boolean yarnBerry(Path dir) throws IOException {
        return Files.isRegularFile(dir.resolve(".yarnrc.yml")) || ProjectFiles.readText(dir.resolve("yarn.lock")).contains("__metadata:");
    }

    // ---------------------------------------------------------------------------------------- common
    /** The major version changes: 2.x to 3.x, the first number of the version. */
    static boolean majorJump(FixRequest r) {
        Matcher a = LEADING_NUMBER.matcher(r.from()), b = LEADING_NUMBER.matcher(r.to());
        return a.find() && b.find() && !a.group(1).equals(b.group(1));
    }

    private String rel(Path p) {
        return (p.startsWith(root) ? root.relativize(p) : p).toString().replace('\\', '/');
    }
}
