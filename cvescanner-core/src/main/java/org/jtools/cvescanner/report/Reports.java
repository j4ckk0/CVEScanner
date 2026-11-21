package org.jtools.cvescanner.report;

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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.engine.Engine;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Severity;
import org.jtools.cvescanner.model.Unresolved;
import org.jtools.cvescanner.version.Versions;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class Reports {
    private Reports() {}

    public static List<PackageSummary> packages(List<Finding> findings) {
        record Key(String eco, String pkg, String version) {}
        final class Agg {
            final Set<String> ids = new HashSet<>(), files = new TreeSet<>(), labels = new TreeSet<>();
            final List<String> fixes = new ArrayList<>();
            Severity worst = Severity.UNKNOWN;
            boolean approximate;
        }
        var map = new LinkedHashMap<Key, Agg>();
        for (var f : findings) {
            var a = map.computeIfAbsent(new Key(f.ecosystem(), f.pkg(), f.version()), _ -> new Agg());
            a.ids.add(f.id());
            if (f.cves().isEmpty()) a.labels.add(f.id()); else a.labels.addAll(f.cves());
            a.files.add(f.file());
            a.fixes.add(f.fixedIn());
            if (f.severity().compareTo(a.worst) > 0) a.worst = f.severity();
            a.approximate |= f.approximate();
        }
        var out = new ArrayList<PackageSummary>();
        map.forEach((k, a) -> {
            var fixed = a.fixes.stream().filter(s -> !s.isEmpty()).max(Versions.comparator(k.eco()));
            boolean someUnfixed = a.fixes.stream().anyMatch(String::isEmpty);
            String target = fixed.map(v -> someUnfixed ? v + " (some unfixed)" : v).orElse("no fix");
            out.add(new PackageSummary(a.worst, k.eco(), k.pkg(), k.version(), a.approximate, target, a.ids.size(),
                    String.join(", ", a.labels), String.join(", ", a.files)));
        });
        out.sort(Comparator.comparing(PackageSummary::worst).reversed()
                .thenComparing(Comparator.comparingInt(PackageSummary::vulnerabilities).reversed())
                .thenComparing(PackageSummary::pkg));
        return out;
    }

    public static Map<Severity, Long> counts(List<Finding> findings) {
        var m = new EnumMap<Severity, Long>(Severity.class);
        for (var s : Severity.values()) m.put(s, 0L);
        findings.forEach(f -> m.merge(f.severity(), 1L, Long::sum));
        return m;
    }

    /** Writes report.md, findings.csv and findings.json; returns the paths written. */
    public static List<Path> writeAll(ScanResult r, List<Finding> findings, Path outDir, String filterNote,
                               Environment env, boolean preferV4) throws IOException {
        Files.createDirectories(outDir);
        Path md = outDir.resolve("report.md"), csv = outDir.resolve("findings.csv"), json = outDir.resolve("findings.json");
        Files.writeString(md, markdown(r, findings, filterNote, env, preferV4), UTF_8);
        Files.writeString(csv, csv(findings, env), UTF_8);
        Files.writeString(json, json(r, findings, env, preferV4), UTF_8);
        return List.of(md, csv, json);
    }

    private static String md(String s) { return s == null ? "" : s.replace("|", "\\|").replaceAll("\\s+", " ").strip(); }

    private static String shorten(String s, int n) {
        s = s.replaceAll("\\s+", " ").strip();
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    static String scoreText(Double score, String version) {
        return score == null ? "—" : "%.1f".formatted(score) + (version != null ? " (v" + version + ")" : "");
    }

    public static String scoringText(boolean preferV4) {
        return preferV4 ? "CVSS 4.0 preferred (CVSS 3.x when an advisory has no 4.0 vector)"
                : "CVSS 3.x preferred (CVSS 4.0 when an advisory has no 3.x vector)";
    }

    static String markdown(ScanResult r, List<Finding> findings, String filterNote, Environment env, boolean preferV4) {
        var sb = new StringBuilder();
        var counts = counts(findings);
        sb.append("# Dependency Vulnerability Report\n\n");
        sb.append("- **Generated:** ").append(Engine.STAMP.format(Instant.now())).append('\n');
        sb.append("- **Scanned directory:** `").append(r.root()).append("`\n");
        r.snapshots().forEach((file, desc) -> sb.append("- **Database:** `").append(file).append("` (").append(desc).append(")\n"));
        sb.append("- **Files scanned:** ").append(r.fileCounts().entrySet().stream().map(e -> e.getValue() + " " + e.getKey())
                .collect(Collectors.joining(", "))).append('\n');
        sb.append("- **Dependencies analysed:** ").append(r.dependencies().size()).append(" (plus ").append(r.unresolved().size())
                .append(" that could not be resolved to a version)\n");
        sb.append("- **Scoring:** ").append(scoringText(preferV4)).append('\n');
        sb.append("- **Environment:** ").append(env.describe())
                .append(env.active() ? ". *Severity* is the environmental severity where a CVSS vector is available." : "").append('\n');
        if (filterNote != null) sb.append("- **Filter:** ").append(filterNote).append('\n');
        sb.append("\n## Summary\n\n| Severity | Findings |\n|---|---|\n");
        for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN))
            sb.append("| ").append(s.name()).append(" | ").append(counts.get(s)).append(" |\n");
        var pkgs = packages(findings);
        sb.append("| **Total** | **").append(findings.size()).append("** (").append(findings.stream().map(Finding::id).distinct().count())
                .append(" unique vulnerabilities in ").append(pkgs.size()).append(" package versions) |\n\n");

        if (findings.isEmpty()) {
            sb.append("No known vulnerabilities were found in the resolved dependencies.\n\n");
        } else {
            sb.append("## Packages to upgrade\n\n*Upgrade to* is the lowest version that fixes every listed advisory.\n\n");
            sb.append("| Worst severity | Ecosystem | Package | Current | Upgrade to | Vulns | Found in |\n|---|---|---|---|---|---|---|\n");
            for (var p : pkgs)
                sb.append("| %s | %s | `%s` | %s | %s | %d | %s |\n".formatted(p.worst().name(), p.ecosystem(), md(p.pkg()),
                        md(p.displayVersion()), md(p.upgradeTo()), p.vulnerabilities(), md(p.files())));
            if (findings.stream().anyMatch(Finding::approximate))
                sb.append("\n> ≈ = lowest version allowed by the range in package.json (no lockfile found). "
                        + "The installed version may be newer; add a lockfile for exact results.\n");
            sb.append("\n## Findings by file\n\n");
            var byFile = new TreeMap<String, List<Finding>>();
            findings.forEach(f -> byFile.computeIfAbsent(f.file(), _ -> new ArrayList<>()).add(f));
            byFile.forEach((file, list) -> {
                sb.append("### `").append(file).append("`\n\n");
                sb.append("| Severity | Base | Env. | Package | Version | Scope | Advisory | Match | CVE | Fixed in | Summary |\n"
                        + "|---|---|---|---|---|---|---|---|---|---|---|\n");
                list.stream().sorted(Finding.ORDER).forEach(f -> sb.append("| %s | %s | %s | `%s` | %s | %s | [%s](%s) | %s | %s | %s | %s |\n".formatted(
                        f.severity().name(), scoreText(f.cvss(), f.score().version()), scoreText(f.envScore(), null), md(f.pkg()), md(f.version()),
                        md(f.scope()), f.id(), f.url(), f.basis().label, f.cves().isEmpty() ? "—" : f.cveText(),
                        f.fixedIn().isEmpty() ? "—" : md(f.fixedIn()), md(shorten(f.summary(), 110)))));
                sb.append('\n');
            });
        }
        if (!r.unresolved().isEmpty()) {
            sb.append("## Dependencies that could not be checked (").append(r.unresolved().size()).append(")\n\n");
            sb.append("| File | Ecosystem | Package | Declared | Reason |\n|---|---|---|---|---|\n");
            r.unresolved().stream().sorted(Comparator.comparing(Unresolved::file).thenComparing(Unresolved::name))
                    .forEach(u -> sb.append("| %s | %s | `%s` | %s | %s |\n".formatted(md(u.file()), u.ecosystem(), md(u.name()),
                            u.declared().isEmpty() ? "—" : md(u.declared()), md(u.reason()))));
            sb.append('\n');
        }
        sb.append("""
                ## Notes and limitations

                - Maven and Gradle results cover **declared** dependencies only. For transitive dependencies run \
                `mvn dependency:tree` / `gradle dependencies`, or enable Gradle dependency locking and re-scan.
                - npm results include transitive dependencies when a lockfile is present.
                - A match means the version is inside an advisory's affected range; whether the vulnerable code is \
                reachable in your application still needs review.
                - *CVE name match ⚠* findings come from CVE List records that describe the product only by name \
                (e.g. product `commons-text`, vendor `Apache Software Foundation`); check that they really refer to your \
                package. The GitHub Advisory Database gives exact package matches.
                - *Base* is computed from the advisory's CVSS vector (version in brackets), or the advisory's rating when \
                there is no vector. *Env.* applies the chosen environment (security requirements and maximum attack vector) \
                as CVSS environmental metrics. `MAL-` advisories are known-malicious packages and are rated CRITICAL.
                """);
        return sb.toString();
    }

    private static String cell(Object o) {
        String s = o == null ? "" : o.toString();
        return s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }

    static String csv(List<Finding> findings, Environment env) {
        var sb = new StringBuilder("severity,base_severity,base_score,cvss_version,base_vector,env_score,env_vector,environment,"
                + "ecosystem,package,version,approximate,scope,file,id,cves,match,fixed_in,summary,url\n");
        for (var f : findings)
            sb.append(Stream.of(f.severity(), f.score().baseSeverity(), f.cvss(), f.score().version(), f.score().baseVector(),
                    f.envScore(), f.score().envVector(), env.name(), f.ecosystem(), f.pkg(), f.version(), f.approximate(), f.scope(), f.file(),
                    f.id(), String.join(" ", f.cves()), f.basis().name(), f.fixedIn(), f.summary(), f.url()).map(Reports::cell)
                    .collect(Collectors.joining(","))).append('\n');
        return sb.toString();
    }

    static String json(ScanResult r, List<Finding> findings, Environment env, boolean preferV4) {
        var root = new LinkedHashMap<String, Object>();
        root.put("generated", Engine.STAMP.format(Instant.now()));
        root.put("scanned_directory", r.root().toString());
        root.put("databases", r.snapshots());
        var scoring = new LinkedHashMap<String, Object>();
        scoring.put("preferred_cvss_version", preferV4 ? "4.0" : "3.x");
        scoring.put("environment", env.name());
        scoring.put("reach", env.reach().name());
        scoring.put("confidentiality_requirement", env.confidentiality().code);
        scoring.put("integrity_requirement", env.integrity().code);
        scoring.put("availability_requirement", env.availability().code);
        root.put("scoring", scoring);
        root.put("findings", findings.stream().map(f -> {
            var m = new LinkedHashMap<String, Object>();
            m.put("severity", f.severity().name());
            m.put("base_severity", f.score().baseSeverity().name());
            m.put("cvss_version", f.score().version());
            m.put("base_score", f.cvss());
            m.put("base_vector", f.score().baseVector());
            m.put("env_score", f.envScore());
            m.put("env_vector", f.score().envVector());
            m.put("ecosystem", f.ecosystem());
            m.put("package", f.pkg());
            m.put("version", f.version());
            m.put("approximate", f.approximate());
            m.put("scope", f.scope());
            m.put("file", f.file());
            m.put("id", f.id());
            m.put("cves", f.cves());
            m.put("aliases", f.aliases());
            m.put("match", f.basis().name());
            m.put("match_note", f.basisNote());
            m.put("fixed_in", f.fixedIn());
            m.put("summary", f.summary());
            m.put("published", f.published());
            m.put("url", f.url());
            return m;
        }).toList());
        // in a fixed order, as every other object of the file: two scans of the same projects write the same JSON
        root.put("unresolved_dependencies", r.unresolved().stream().map(u -> {
            var m = new LinkedHashMap<String, Object>();
            m.put("ecosystem", u.ecosystem());
            m.put("name", u.name());
            m.put("declared", u.declared());
            m.put("file", u.file());
            m.put("reason", u.reason());
            return m;
        }).toList());
        return Json.write(root);
    }
}
