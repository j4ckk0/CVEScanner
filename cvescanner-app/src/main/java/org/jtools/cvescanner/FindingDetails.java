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

import java.awt.Color;
import java.util.Objects;
import java.util.stream.Collectors;
import org.jtools.cvescanner.cvss.Cvss;
import java.util.List;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.ignore.VexStatement;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import javax.swing.UIManager;

/**
 * The details pane's page for a finding, as HTML. Everything a database or a project wrote goes through SwingText.html,
 * so that the page holds no tag of theirs: Swing's HTML would fetch an image or a style sheet it names, and the
 * program never reaches the network (README, "No network"). Its links are https addresses only; a click copies
 * them (MainWindow).
 */
final class FindingDetails {

    private FindingDetails() {
    }

    /** The page shown when no finding is selected. */
    static String placeholder(boolean scanned) {
        return "<html><body style='font-family:sans-serif;color:gray;padding:18px'>"
                + I18n.text(scanned ? "details.select" : "details.scanFirst")
                + "</body></html>";
    }

    static String page(Finding f, Environment environment) {
        return page(f, environment, null, "", List.of());
    }

    /**
     * The page of a finding; for one set aside, first why, until when, and which entry of which file or which VEX
     * document.
     *
     * @param rule the entry setting it aside; null for a finding reported
     * @param vex  what VEX documents state of it (in triage, exploitable…), shown whatever they state
     */
    static String page(Finding f, Environment environment, IgnoreRule rule, String file, List<VexStatement> vex) {
        var sb = new StringBuilder("<html><body style='font-family:sans-serif;padding:10px 16px'>");
        // the headline: the advisory, its severity as a pill, its score; then what it is
        Color colour = SeverityColors.of(f.severity());
        sb.append("<div style='font-size:15pt'><b>").append(SwingText.html(f.id())).append("</b> &nbsp;<span style='background-color:")
                .append(SwingText.hex(colour)).append(";color:").append(SwingText.hex(Pill.textOn(colour))).append("'><b>&nbsp;")
                .append(f.severity().label()).append("&nbsp;</b></span>&nbsp; <font color='").append(SwingText.hex(colour)).append("'><b>");
        if (f.envScore() != null) sb.append(I18n.text("details.headline.environmental", SwingText.score(f.envScore())));
        else if (f.cvss() != null) sb.append(I18n.text("details.headline.cvss", SwingText.score(f.cvss())));
        sb.append("</b></font></div>");
        sb.append("<p style='margin-top:6px'><b>").append(SwingText.html(f.summary())).append("</b></p>");
        var aside = new StringBuilder();
        if (rule != null) {
            aside.append("<b>").append(I18n.text("details.ignored")).append("</b> — ")
                    .append(rule.reason().isEmpty() ? "" : SwingText.html(rule.reason()) + " · ")
                    .append(rule.until() == null ? I18n.text("details.ignored.forEver") : I18n.text("details.ignored.until", rule.until().toString()))
                    .append(" · ").append(rule.fromVex() ? I18n.text("details.ignored.vex", SwingText.html(rule.source()))
                            : I18n.text("details.ignored.entry", rule.line(), SwingText.html(file)));
        }
        for (var v : vex)
            if (rule == null || !rule.fromVex() || !v.source().equals(rule.source()))
                aside.append(aside.isEmpty() ? "" : "<br>").append("<b>").append(I18n.text("details.vex", SwingText.html(v.source())))
                        .append("</b> — ").append(SwingText.html(v.said()));
        if (!aside.isEmpty()) card(sb, null, aside.toString());

        var fix = new StringBuilder();
        row(fix, "details.package", "<b>" + SwingText.html(f.pkg()) + "</b> (" + SwingText.html(f.ecosystem().id()) + ")");
        row(fix, "details.version", SwingText.html(f.version()) + (f.approximate()
                ? " <font color='gray'>" + I18n.text("details.version.approximate") + "</font>" : ""));
        row(fix, "details.fixedIn", f.fixedIn().isEmpty() ? "<font color='" + SwingText.hex(SeverityColors.of(Severity.CRITICAL)) + "'>"
                + I18n.text("details.fixedIn.none") + "</font>" : "<b>" + SwingText.html(f.fixedIn()) + "</b>");
        card(sb, "details.card.fix", table(fix));

        var scores = new StringBuilder();
        var sc = f.score();
        if (sc.base() != null) {
            row(scores, "details.base", "<b>" + SwingText.score(sc.base()) + "</b> " + sc.baseSeverity().label()
                    + (sc.version() != null ? " · CVSS " + SwingText.html(sc.version()) + " <font color='gray'>" + SwingText.html(sc.baseVector()) + "</font>"
                                            : " <font color='gray'>" + I18n.text("details.base.reported") + "</font>"));
        } else {
            row(scores, "details.base", "<font color='gray'>" + I18n.text("details.base.none", sc.baseSeverity().label()) + "</font>");
        }
        if (environment.active()) {
            if (sc.env() != null) {
                double delta = sc.env() - sc.base();
                row(scores, "details.environmental", "<b><font color='" + SwingText.hex(SeverityColors.of(Severity.fromScore(sc.env()))) + "'>"
                        + SwingText.score(sc.env()) + " " + Severity.fromScore(sc.env()).label() + "</font></b> ("
                        + (delta == 0 ? I18n.text("details.environmental.unchanged") : String.format(I18n.language().locale(), "%+.1f", delta))
                        + ") · " + SwingText.html(environment.describe())
                        + "<br><font color='gray'>" + SwingText.html(sc.envVector()) + "</font>");
            } else {
                row(scores, "details.environmental", "<font color='gray'>" + I18n.text("details.environmental.none") + "</font>");
            }
        }
        if (f.rating().cvss3() != null && f.rating().cvss4() != null) {
            String other = Objects.equals(sc.baseVector(), f.rating().cvss4()) ? f.rating().cvss3() : f.rating().cvss4();
            Double otherScore = Cvss.baseScore(other);
            row(scores, "details.other", I18n.text("details.other.value", SwingText.html(Cvss.version(other)), otherScore == null ? "—" : SwingText.score(otherScore))
                    + " <font color='gray'>" + SwingText.html(other) + "</font>");
        }
        card(sb, "details.card.scores", table(scores));

        var match = new StringBuilder();
        row(match, "details.match", (f.basis().byName() ? "<font color='#b7791f'><b>⚠ " : "<b>") + SwingText.html(f.basis().label().replace(" ⚠", ""))
                + "</b>" + (f.basis().byName() ? "</font>" : "") + " — " + SwingText.html(f.basisNote().text()));
        row(match, "details.cve", f.cves().isEmpty() ? "—" : f.cves().stream()
                .map(c -> link(nvdUrl(c), c)).collect(Collectors.joining(", ")));
        if (!f.aliases().isEmpty()) row(match, "details.aliases", SwingText.html(String.join(", ", f.aliases())));
        row(match, "details.foundIn", SwingText.html(f.file()) + " · " + SwingText.html(f.scope()));
        if (!f.published().isEmpty()) row(match, "details.published", SwingText.html(f.publishedDate()));
        row(match, f.basis() == MatchBasis.ADVISORY || f.basis() == MatchBasis.ADVISORY_NAME ? "details.advisory" : "details.cveRecord", link(f.url(), f.url()));
        card(sb, "details.card.match", table(match));

        if (!f.details().isBlank()) {
            String d = f.details().length() > 8000 ? f.details().substring(0, 8000) + "…" : f.details();
            card(sb, "details.card.description", SwingText.html(d).replace("\n\n", "<p>").replace("\n", "<br>"));
        }
        return sb.append("</body></html>").toString();
    }

    /**
     * A card: a block in a field's background on the pane's, read-only, which the looks draw in the panels' colour; its
     * title first when it has one; the space above it apart.
     */
    private static void card(StringBuilder sb, String titleKey, String html) {
        Color background = UIManager.getColor("EditorPane.background");
        String tint = SwingText.hex(background == null ? Color.WHITE : background);
        sb.append("<div style='font-size:5pt'>&nbsp;</div><table width='100%' cellspacing='0' cellpadding='10' bgcolor='").append(tint)
                .append("'><tr><td>");
        if (titleKey != null) sb.append("<div style='margin-bottom:4px'><font color='gray'><b>").append(I18n.text(titleKey)).append("</b></font></div>");
        sb.append(html).append("</td></tr></table>");
    }

    private static String table(StringBuilder rows) {
        return "<table cellpadding='3' cellspacing='0'>" + rows + "</table>";
    }

    /** The NVD page of a CVE, an address to copy. */
    static String nvdUrl(String cve) {
        return "https://nvd.nist.gov/vuln/detail/" + cve;
    }

    /** A link to an https address, its text and address escaped; any other address is shown as text, not a link. */
    static String link(String url, String text) {
        if (url == null || !url.startsWith("https://")) return SwingText.html(text);
        return "<a href='" + SwingText.html(url) + "'>" + SwingText.html(text) + "</a>";
    }

    /** A row of the table: its label's key, its value as HTML. */
    private static void row(StringBuilder sb, String labelKey, String valueHtml) {
        sb.append("<tr><td valign='top' width='130'><font color='gray'>").append(I18n.text(labelKey)).append("</font></td><td>").append(valueHtml).append("</td></tr>");
    }
}
