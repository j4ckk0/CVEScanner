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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.i18n.I18nLanguage;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.IgnoredFinding;
import org.jtools.cvescanner.ignore.Ignores;
import org.jtools.cvescanner.json.Json;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.model.ScanMode;
import org.jtools.cvescanner.model.ScanResult;
import org.jtools.cvescanner.model.Unresolved;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class Reports {
    private Reports() {}

    /** The CycloneDX SBOM's file name: .cdx.json, as the tools that read one look for it. */
    public static final String SBOM = "bom.cdx.json";

    /**
     * Writes report.md, in this language, and findings.csv, findings.json and bom.cdx.json (CycloneDX), in English
     * whatever the language: their readers are programs. The findings reported are the split's active ones; those it
     * sets aside have a section of their own in report.md and findings.json, are analysed "not_affected" in the SBOM,
     * and are not in findings.csv. Returns the paths written.
     */
    public static List<Path> writeAll(ScanResult r, Ignores.Split split, Path outDir, List<Phrase> filters,
                               Environment env, boolean preferV4, I18nLanguage language) throws IOException {
        Files.createDirectories(outDir);
        Path md = outDir.resolve("report.md"), csv = outDir.resolve("findings.csv"), json = outDir.resolve("findings.json"),
                bom = outDir.resolve(SBOM);
        Files.writeString(md, markdown(r, split, filters, env, preferV4, language), UTF_8);
        Files.writeString(csv, csv(split.active(), env), UTF_8);
        Files.writeString(json, json(r, split, env, preferV4), UTF_8);
        Files.writeString(bom, CycloneDx.bom(r, split, env), UTF_8);
        return List.of(md, csv, json, bom);
    }

    /**
     * Text of a project or a database, as Markdown shows it and nothing more: its punctuation that Markdown or HTML
     * would read escaped, so that an advisory's summary can hold no tag (an image a viewer would fetch), no link, no
     * table cell of its own.
     */
    static String md(String s) {
        if (s == null) return "";
        return MARKDOWN_SPECIAL.matcher(s.replaceAll("\\s+", " ").strip()).replaceAll("\\\\$0");
    }

    private static final Pattern MARKDOWN_SPECIAL = Pattern.compile("[\\\\`*_\\[\\]<>|&!#~]");

    /** Text of a project or a database in a code span, where HTML is not read: no backquote to end it, no cell's pipe. */
    static String code(String s) {
        if (s == null) return "";
        return s.replaceAll("\\s+", " ").strip().replace('`', '\'').replace("|", "\\|");
    }

    /** A link to an https address made of safe characters only; anything else is said as text, not linked. */
    static String link(String text, String url) {
        return url != null && SAFE_URL.matcher(url).matches() ? "[" + md(text) + "](" + url + ")" : md(text);
    }

    private static final Pattern SAFE_URL = Pattern.compile("https://[A-Za-z0-9._~:/?#@!$&'*+,;=%-]+");

    private static String shorten(String s, int n) {
        s = s.replaceAll("\\s+", " ").strip();
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    /** A score as the language writes numbers: 9.8, 9,8. */
    static String scoreText(Double score, String version, I18nLanguage language) {
        return score == null ? "—" : String.format(language.locale(), "%.1f", score) + (version != null ? " (v" + version + ")" : "");
    }

    public static String scoringText(boolean preferV4, I18nLanguage language) {
        return I18n.text(language, preferV4 ? "scoring.prefer4" : "scoring.prefer3");
    }

    public static String scoringText(boolean preferV4) { return scoringText(preferV4, I18n.language()); }

    /** A severity in a report's table, in capitals: CRITICAL, CRITIQUE. */
    private static String severity(Severity s, I18nLanguage language) {
        return s.label(language).toUpperCase(language.locale());
    }

    static String markdown(ScanResult r, Ignores.Split split, List<Phrase> filters, Environment env, boolean preferV4,
                           I18nLanguage language) {
        var findings = split.active();
        var sb = new StringBuilder();
        var counts = Finding.countBySeverity(findings);
        sb.append("# ").append(I18n.text(language, "markdown.title")).append("\n\n");
        sb.append("- **").append(I18n.text(language, "markdown.generated")).append(":** ").append(ScanResult.TIMESTAMP_UTC.format(Instant.now())).append('\n');
        sb.append("- **").append(I18n.text(language, "markdown.scanned")).append(":** `").append(code(r.root().toString())).append("`\n");
        if (r.mode() == ScanMode.INSTALLED)
            sb.append("- **").append(I18n.text(language, "markdown.scanMode")).append(":** ").append(I18n.text(language, "markdown.scanMode.installed")).append('\n');
        r.snapshots().forEach((file, desc) -> sb.append("- **").append(I18n.text(language, "markdown.database")).append(":** `")
                .append(code(file)).append("` (").append(md(desc.text(language))).append(")\n"));
        sb.append("- **").append(I18n.text(language, "markdown.files")).append(":** ").append(r.fileCounts().entrySet().stream()
                .map(e -> I18n.text(language, e.getKey(), e.getValue())).collect(Collectors.joining(", "))).append('\n');
        sb.append("- **").append(I18n.text(language, "markdown.dependencies")).append(":** ")
                .append(I18n.text(language, "markdown.dependencies.count", r.dependencies().size(), r.unresolved().size())).append('\n');
        sb.append("- **").append(I18n.text(language, "markdown.scoring")).append(":** ").append(scoringText(preferV4, language)).append('\n');
        sb.append("- **").append(I18n.text(language, "markdown.environment")).append(":** ").append(env.describe(language))
                .append(env.active() ? I18n.text(language, "markdown.environment.severity") : "").append('\n');
        if (split.ignores().read())
            sb.append("- **").append(I18n.text(language, "markdown.ignoreFile")).append(":** `").append(code(split.ignores().shown()))
                    .append("` (").append(I18n.text(language, "markdown.ignoreFile.entries", split.ignores().rules().size())).append(")\n");
        if (!split.ignores().vex().isEmpty())
            sb.append("- **").append(I18n.text(language, "markdown.vex")).append(":** ")
                    .append(String.join(", ", split.ignores().vexSources().stream().map(v -> "`" + code(v) + "`").toList()))
                    .append(" (").append(I18n.text(language, "markdown.vex.statements", split.ignores().vex().size())).append(")\n");
        if (!filters.isEmpty()) sb.append("- **").append(I18n.text(language, "markdown.filter")).append(":** ")
                .append(md(String.join("; ", filters.stream().map(f -> f.text(language)).toList()))).append('\n');
        sb.append("\n## ").append(I18n.text(language, "markdown.summary")).append("\n\n").append(I18n.text(language, "markdown.summary.header")).append("\n|---|---|\n");
        for (var s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN))
            sb.append("| ").append(severity(s, language)).append(" | ").append(counts.get(s)).append(" |\n");
        var pkgs = PackageSummary.of(findings);
        sb.append("| **").append(I18n.text(language, "markdown.total")).append("** | **").append(findings.size()).append("** ")
                .append(I18n.text(language, "markdown.total.detail", findings.stream().map(Finding::id).distinct().count(), pkgs.size()))
                .append(" |\n\n");

        if (findings.isEmpty()) {
            sb.append(I18n.text(language, "markdown.none")).append("\n\n");
        } else {
            sb.append("## ").append(I18n.text(language, "markdown.packages")).append("\n\n")
                    .append(I18n.text(language, "markdown.packages.intro")).append("\n\n");
            sb.append(I18n.text(language, "markdown.packages.header")).append("\n|---|---|---|---|---|---|---|\n");
            for (var p : pkgs)
                sb.append("| %s | %s | `%s` | %s | %s | %d | %s |\n".formatted(severity(p.worst(), language), md(p.ecosystem().id()), code(p.pkg()),
                        md(p.displayVersion()), md(p.upgradeTo(language)), p.vulnerabilities(), md(p.files())));
            if (findings.stream().anyMatch(Finding::approximate))
                sb.append("\n> ").append(I18n.text(language, "markdown.approximate")).append('\n');
            sb.append("\n## ").append(I18n.text(language, "markdown.byFile")).append("\n\n");
            var byFile = new TreeMap<String, List<Finding>>();
            findings.forEach(f -> byFile.computeIfAbsent(f.file(), _ -> new ArrayList<>()).add(f));
            byFile.forEach((file, list) -> {
                sb.append("### `").append(code(file)).append("`\n\n");
                sb.append(I18n.text(language, "markdown.findings.header")).append("\n|---|---|---|---|---|---|---|---|---|---|---|\n");
                list.stream().sorted(Finding.ORDER).forEach(f -> sb.append("| %s | %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s |\n".formatted(
                        severity(f.severity(), language), scoreText(f.cvss(), f.score().version(), language),
                        scoreText(f.envScore(), null, language), code(f.pkg()), md(f.version()),
                        md(f.scope()), link(f.id(), f.url()), f.basis().label(language), f.cves().isEmpty() ? "—" : md(f.cveText()),
                        f.fixedIn().isEmpty() ? "—" : md(f.fixedIn()), md(shorten(f.summary(), 110)))));
                sb.append('\n');
            });
        }
        if (!r.unresolved().isEmpty()) {
            sb.append("## ").append(I18n.text(language, "markdown.unresolved", r.unresolved().size())).append("\n\n");
            sb.append(I18n.text(language, "markdown.unresolved.header")).append("\n|---|---|---|---|---|\n");
            r.unresolved().stream().sorted(Comparator.comparing(Unresolved::file).thenComparing(Unresolved::name))
                    .forEach(u -> sb.append("| %s | %s | `%s` | %s | %s |\n".formatted(md(u.file()), md(u.ecosystem().id()), code(u.name()),
                            u.declared().isEmpty() ? "—" : md(u.declared()), md(u.reason().text(language)))));
            sb.append('\n');
        }
        if (split.ignores().said()) ignored(sb, split, language);
        sb.append("## ").append(I18n.text(language, "markdown.notes")).append("\n\n").append(I18n.text(language, "markdown.notes.text")).append('\n');
        // how components off-the-shelf are found and matched: said when the report holds some
        if (findings.stream().anyMatch(f -> f.ecosystem() == Ecosystem.COTS)
                || r.unresolved().stream().anyMatch(u -> u.ecosystem() == Ecosystem.COTS))
            sb.append(I18n.text(language, "markdown.notes.cots")).append('\n');
        return sb.toString();
    }

    /** The findings the ignore file sets aside, why and until when; its entries expired, and those setting none aside. */
    private static void ignored(StringBuilder sb, Ignores.Split split, I18nLanguage language) {
        sb.append("## ").append(I18n.text(language, "markdown.ignored", split.ignored().size())).append("\n\n");
        if (split.ignored().isEmpty()) {
            sb.append(I18n.text(language, "markdown.ignored.none")).append("\n\n");
        } else {
            sb.append(I18n.text(language, "markdown.ignored.intro")).append("\n\n");
            sb.append(I18n.text(language, "markdown.ignored.header")).append("\n|---|---|---|---|---|---|---|---|---|\n");
            split.ignored().stream().sorted(Comparator.comparing(IgnoredFinding::finding, Finding.ORDER)).forEach(i -> {
                var f = i.finding();
                sb.append("| %s | `%s` | %s | %s | %s | %s | %s | %s | %s |\n".formatted(severity(f.severity(), language), code(f.pkg()),
                        md(f.version()), link(f.id(), f.url()), f.cves().isEmpty() ? "—" : md(f.cveText()),
                        i.rule().until() == null ? "—" : i.rule().until(), i.rule().reason().isEmpty() ? "—" : md(i.rule().reason()),
                        md(f.file()), i.rule().fromVex() ? "VEX `" + code(i.rule().source()) + "`"
                                : I18n.text(language, "markdown.ignored.line", i.rule().line())));
            });
            sb.append('\n');
        }
        if (!split.expired().isEmpty()) {
            sb.append(I18n.text(language, "markdown.ignored.expired")).append("\n\n");
            split.expired().forEach(rule -> sb.append("- ").append(entry(rule, language)).append(" — ")
                    .append(I18n.text(language, "markdown.ignored.expiredOn", rule.until().toString())).append('\n'));
            sb.append('\n');
        }
        if (!split.unused().isEmpty()) {
            sb.append(I18n.text(language, "markdown.ignored.unused")).append("\n\n");
            split.unused().forEach(rule -> sb.append("- ").append(entry(rule, language)).append('\n'));
            sb.append('\n');
        }
    }

    /** An entry of the ignore file, said: "line 4: `CVE-2020-36518`, `lodash` 4.17.15". */
    private static String entry(IgnoreRule rule, I18nLanguage language) {
        String what = "`" + code(rule.id()) + "`" + (rule.pkg().isEmpty() ? "" : ", `" + code(rule.pkg()) + "`")
                + (rule.version().isEmpty() ? "" : " " + md(rule.version()));
        return I18n.text(language, "markdown.ignored.line", rule.line()) + ": " + what;
    }

    /**
     * A CSV cell. Text that a spreadsheet would read as a formula (=, +, -, @, a tab or a carriage return first) is
     * written after a quote, as OWASP advises: an advisory's summary opened in Excel runs nothing. Numbers are written
     * as they are.
     */
    private static String cell(Object o) {
        String s = o == null ? "" : o.toString();
        if (o instanceof String && !s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) s = "'" + s;
        return s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }

    static String csv(List<Finding> findings, Environment env) {
        var sb = new StringBuilder("severity,base_severity,base_score,cvss_version,base_vector,env_score,env_vector,environment,"
                + "ecosystem,package,version,approximate,scope,file,id,cves,match,fixed_in,summary,url\n");
        for (var f : findings)
            sb.append(Stream.of(f.severity(), f.score().baseSeverity(), f.cvss(), f.score().version(), f.score().baseVector(),
                    f.envScore(), f.score().envVector(), env.name(I18nLanguage.ENGLISH), f.ecosystem().id(), f.pkg(), f.version(), f.approximate(), f.scope(), f.file(),
                    f.id(), String.join(" ", f.cves()), f.basis().name(), f.fixedIn(), f.summary(), f.url()).map(Reports::cell)
                    .collect(Collectors.joining(","))).append('\n');
        return sb.toString();
    }

    static String json(ScanResult r, Ignores.Split split, Environment env, boolean preferV4) {
        var findings = split.active();
        var root = new LinkedHashMap<String, Object>();
        root.put("generated", ScanResult.TIMESTAMP_UTC.format(Instant.now()));
        root.put("scanned_directory", r.root().toString());
        if (r.mode() == ScanMode.INSTALLED) root.put("scan_mode", "installed");
        var databases = new LinkedHashMap<String, Object>();
        r.snapshots().forEach((file, desc) -> databases.put(file, desc.text(I18nLanguage.ENGLISH)));
        root.put("databases", databases);
        var scoring = new LinkedHashMap<String, Object>();
        scoring.put("preferred_cvss_version", preferV4 ? "4.0" : "3.x");
        scoring.put("environment", env.name(I18nLanguage.ENGLISH));
        scoring.put("reach", env.reach().name());
        scoring.put("confidentiality_requirement", env.confidentiality().code);
        scoring.put("integrity_requirement", env.integrity().code);
        scoring.put("availability_requirement", env.availability().code);
        root.put("scoring", scoring);
        root.put("findings", findings.stream().map(Reports::json).toList());
        // in a fixed order, as every other object of the file: two scans of the same projects write the same JSON
        root.put("unresolved_dependencies", r.unresolved().stream().map(u -> {
            var m = new LinkedHashMap<String, Object>();
            m.put("ecosystem", u.ecosystem().id());
            m.put("name", u.name());
            m.put("declared", u.declared());
            m.put("file", u.file());
            m.put("reason", u.reason().text(I18nLanguage.ENGLISH));
            return m;
        }).toList());
        // the ignore file's, when there is one: what it sets aside, its entries expired and those setting nothing aside
        if (split.ignores().said()) {
            if (split.ignores().read()) root.put("ignore_file", split.ignores().shown());
            if (!split.ignores().vex().isEmpty()) root.put("vex_files", split.ignores().vexSources());
            root.put("ignored_findings", split.ignored().stream().map(i -> {
                var m = json(i.finding());
                m.put("ignore_reason", i.rule().reason());
                m.put("ignore_until", i.rule().until() == null ? null : i.rule().until().toString());
                m.put("ignore_line", i.rule().line());
                if (i.rule().fromVex()) m.put("ignore_vex", i.rule().source());
                return m;
            }).toList());
            root.put("ignore_expired", split.expired().stream().map(Reports::json).toList());
            root.put("ignore_unused", split.unused().stream().map(Reports::json).toList());
        }
        return Json.write(root);
    }

    private static Map<String, Object> json(IgnoreRule rule) {
        var m = new LinkedHashMap<String, Object>();
        m.put("line", rule.line());
        m.put("id", rule.id());
        m.put("package", rule.pkg());
        m.put("version", rule.version());
        m.put("until", rule.until() == null ? null : rule.until().toString());
        m.put("reason", rule.reason());
        return m;
    }

    private static Map<String, Object> json(Finding f) {
        var m = new LinkedHashMap<String, Object>();
        m.put("severity", f.severity().name());
        m.put("base_severity", f.score().baseSeverity().name());
        m.put("cvss_version", f.score().version());
        m.put("base_score", f.cvss());
        m.put("base_vector", f.score().baseVector());
        m.put("env_score", f.envScore());
        m.put("env_vector", f.score().envVector());
        m.put("ecosystem", f.ecosystem().id());
        m.put("package", f.pkg());
        m.put("version", f.version());
        m.put("approximate", f.approximate());
        m.put("scope", f.scope());
        m.put("file", f.file());
        m.put("id", f.id());
        m.put("cves", f.cves());
        m.put("aliases", f.aliases());
        m.put("match", f.basis().name());
        m.put("match_note", f.basisNote().text(I18nLanguage.ENGLISH));
        m.put("fixed_in", f.fixedIn());
        m.put("summary", f.summary());
        m.put("published", f.published());
        m.put("url", f.url());
        return m;
    }
}
