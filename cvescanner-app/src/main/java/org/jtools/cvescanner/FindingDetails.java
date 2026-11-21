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

import java.util.Objects;
import java.util.stream.Collectors;
import org.jtools.cvescanner.cvss.Cvss;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;

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
        return page(f, environment, null, "");
    }

    /**
     * The page of a finding the ignore file sets aside: why, until when, which entry of which file, before the rest.
     *
     * @param rule the entry setting it aside; null for a finding reported
     */
    static String page(Finding f, Environment environment, IgnoreRule rule, String file) {
        var sb = new StringBuilder("<html><body style='font-family:sans-serif;padding:12px 18px'>");
        sb.append("<div style='font-size:15pt'><b>").append(SwingText.html(f.id())).append("</b> &nbsp;<font color='")
                .append(SwingText.hex(SeverityColors.of(f.severity()))).append("'><b>").append(f.severity().label());
        if (f.envScore() != null) sb.append(" · ").append(I18n.text("details.headline.environmental", SwingText.score(f.envScore())));
        else if (f.cvss() != null) sb.append(" · ").append(I18n.text("details.headline.cvss", SwingText.score(f.cvss())));
        sb.append("</b></font></div>");
        if (rule != null) {
            sb.append("<p><font color='gray'><b>").append(I18n.text("details.ignored")).append("</b> — ")
                    .append(rule.reason().isEmpty() ? "" : SwingText.html(rule.reason()) + " · ")
                    .append(rule.until() == null ? I18n.text("details.ignored.forEver") : I18n.text("details.ignored.until", rule.until().toString()))
                    .append(" · ").append(I18n.text("details.ignored.entry", rule.line(), SwingText.html(file))).append("</font></p>");
        }
        sb.append("<p><b>").append(SwingText.html(f.summary())).append("</b></p><table cellpadding='4'>");
        row(sb, "details.package", "<b>" + SwingText.html(f.pkg()) + "</b> (" + SwingText.html(f.ecosystem().id()) + ")");
        row(sb, "details.version", SwingText.html(f.version()) + (f.approximate()
                ? " <font color='gray'>" + I18n.text("details.version.approximate") + "</font>" : ""));
        var sc = f.score();
        if (sc.base() != null) {
            row(sb, "details.base", "<b>" + SwingText.score(sc.base()) + "</b> " + sc.baseSeverity().label()
                    + (sc.version() != null ? " · CVSS " + SwingText.html(sc.version()) + " <font color='gray'>" + SwingText.html(sc.baseVector()) + "</font>"
                                            : " <font color='gray'>" + I18n.text("details.base.reported") + "</font>"));
        } else {
            row(sb, "details.base", "<font color='gray'>" + I18n.text("details.base.none", sc.baseSeverity().label()) + "</font>");
        }
        if (environment.active()) {
            if (sc.env() != null) {
                double delta = sc.env() - sc.base();
                row(sb, "details.environmental", "<b><font color='" + SwingText.hex(SeverityColors.of(Severity.fromScore(sc.env()))) + "'>" + SwingText.score(sc.env())
                        + " " + Severity.fromScore(sc.env()).label() + "</font></b> ("
                        + (delta == 0 ? I18n.text("details.environmental.unchanged") : String.format(I18n.language().locale(), "%+.1f", delta))
                        + ") · " + SwingText.html(environment.describe())
                        + "<br><font color='gray'>" + SwingText.html(sc.envVector()) + "</font>");
            } else {
                row(sb, "details.environmental", "<font color='gray'>" + I18n.text("details.environmental.none") + "</font>");
            }
        }
        if (f.rating().cvss3() != null && f.rating().cvss4() != null) {
            String other = Objects.equals(sc.baseVector(), f.rating().cvss4()) ? f.rating().cvss3() : f.rating().cvss4();
            Double otherScore = Cvss.baseScore(other);
            row(sb, "details.other", I18n.text("details.other.value", SwingText.html(Cvss.version(other)), otherScore == null ? "—" : SwingText.score(otherScore))
                    + " <font color='gray'>" + SwingText.html(other) + "</font>");
        }
        row(sb, "details.fixedIn", f.fixedIn().isEmpty() ? "<font color='#b00020'>" + I18n.text("details.fixedIn.none") + "</font>"
                : "<b>" + SwingText.html(f.fixedIn()) + "</b>");
        row(sb, "details.cve", f.cves().isEmpty() ? "—" : f.cves().stream()
                .map(c -> link(nvdUrl(c), c)).collect(Collectors.joining(", ")));
        if (!f.aliases().isEmpty()) row(sb, "details.aliases", SwingText.html(String.join(", ", f.aliases())));
        row(sb, "details.foundIn", SwingText.html(f.file()) + " · " + SwingText.html(f.scope()));
        row(sb, "details.match", (f.basis().byName() ? "<font color='#b7791f'><b>⚠ " : "<b>") + SwingText.html(f.basis().label().replace(" ⚠", ""))
                + "</b>" + (f.basis().byName() ? "</font>" : "") + " — " + SwingText.html(f.basisNote().text()));
        if (!f.published().isEmpty()) row(sb, "details.published", SwingText.html(f.publishedDate()));
        row(sb, f.basis() == MatchBasis.ADVISORY || f.basis() == MatchBasis.ADVISORY_NAME ? "details.advisory" : "details.cveRecord", link(f.url(), f.url()));
        sb.append("</table>");
        if (!f.details().isBlank()) {
            String d = f.details().length() > 8000 ? f.details().substring(0, 8000) + "…" : f.details();
            sb.append("<hr><div>").append(SwingText.html(d).replace("\n\n", "<p>").replace("\n", "<br>")).append("</div>");
        }
        return sb.append("</body></html>").toString();
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
        sb.append("<tr><td valign='top'><font color='gray'>").append(I18n.text(labelKey)).append("</font></td><td>").append(valueHtml).append("</td></tr>");
    }
}
