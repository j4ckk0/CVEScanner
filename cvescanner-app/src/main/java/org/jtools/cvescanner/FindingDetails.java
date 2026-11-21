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
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;

/**
 * The details pane's page for a finding, as HTML. Everything a database or a project wrote goes through Gui.html,
 * so that the page holds no tag of theirs: Swing's HTML would fetch an image or a style sheet it names, and the
 * program never reaches the network (README, "No network"). Its links are https addresses only; a click copies
 * them (MainWindow).
 */
final class FindingDetails {

    private FindingDetails() {
    }

    /** The page shown when no finding is selected. */
    static String placeholder(boolean scanned) {
        return "<html><body style='font-family:sans-serif;color:gray;padding:12px'>"
                + (scanned ? "Select a finding to see its details." : "Scan a folder to see vulnerable dependencies.")
                + "</body></html>";
    }

    static String page(Finding f, Environment environment) {
        var sb = new StringBuilder("<html><body style='font-family:sans-serif;padding:6px 10px'>");
        sb.append("<div style='font-size:15pt'><b>").append(Gui.html(f.id())).append("</b> &nbsp;<font color='")
                .append(Gui.hex(SeverityColors.of(f.severity()))).append("'><b>").append(f.severity().label());
        if (f.envScore() != null) sb.append(" · environmental ").append("%.1f".formatted(f.envScore()));
        else if (f.cvss() != null) sb.append(" · CVSS ").append("%.1f".formatted(f.cvss()));
        sb.append("</b></font></div><p><b>").append(Gui.html(f.summary())).append("</b></p><table cellpadding='2'>");
        row(sb, "Package", "<b>" + Gui.html(f.pkg()) + "</b> (" + Gui.html(f.ecosystem()) + ")");
        row(sb, "Version in use", Gui.html(f.version()) + (f.approximate()
                ? " <font color='gray'>≈ lowest version allowed by the declared range; add a lockfile for an exact check</font>" : ""));
        var sc = f.score();
        if (sc.base() != null) {
            row(sb, "Base score", "<b>" + "%.1f".formatted(sc.base()) + "</b> " + sc.baseSeverity().label()
                    + (sc.version() != null ? " · CVSS " + Gui.html(sc.version()) + " <font color='gray'>" + Gui.html(sc.baseVector()) + "</font>"
                                            : " <font color='gray'>(reported by the advisory, no vector)</font>"));
        } else {
            row(sb, "Base score", "<font color='gray'>no CVSS score; severity from the advisory rating ("
                    + sc.baseSeverity().label() + ")</font>");
        }
        if (environment.active()) {
            if (sc.env() != null) {
                double delta = sc.env() - sc.base();
                row(sb, "Environmental", "<b><font color='" + Gui.hex(SeverityColors.of(Severity.fromScore(sc.env()))) + "'>" + "%.1f".formatted(sc.env())
                        + " " + Severity.fromScore(sc.env()).label() + "</font></b>"
                        + (delta == 0 ? " (unchanged)" : " (%+.1f)".formatted(delta)) + " · " + Gui.html(environment.describe())
                        + "<br><font color='gray'>" + Gui.html(sc.envVector()) + "</font>");
            } else {
                row(sb, "Environmental", "<font color='gray'>not computed: the advisory has no CVSS vector</font>");
            }
        }
        if (f.rating().cvss3() != null && f.rating().cvss4() != null) {
            String other = Objects.equals(sc.baseVector(), f.rating().cvss4()) ? f.rating().cvss3() : f.rating().cvss4();
            Double otherScore = Cvss.baseScore(other);
            row(sb, "Other version", "CVSS " + Gui.html(Cvss.version(other)) + " base " + (otherScore == null ? "—" : "%.1f".formatted(otherScore))
                    + " <font color='gray'>" + Gui.html(other) + "</font>");
        }
        row(sb, "Fixed in", f.fixedIn().isEmpty() ? "<font color='#b00020'>no fixed version published</font>" : "<b>" + Gui.html(f.fixedIn()) + "</b>");
        row(sb, "CVE", f.cves().isEmpty() ? "—" : f.cves().stream()
                .map(c -> link(nvdUrl(c), c)).collect(Collectors.joining(", ")));
        if (!f.aliases().isEmpty()) row(sb, "Aliases", Gui.html(String.join(", ", f.aliases())));
        row(sb, "Found in", Gui.html(f.file()) + " · " + Gui.html(f.scope()));
        row(sb, "Match", (f.basis() == MatchBasis.CVE_NAME ? "<font color='#b7791f'><b>⚠ " : "<b>") + Gui.html(f.basis().label.replace(" ⚠", ""))
                + "</b>" + (f.basis() == MatchBasis.CVE_NAME ? "</font>" : "") + " — " + Gui.html(f.basisNote()));
        if (!f.published().isEmpty()) row(sb, "Published", Gui.html(f.publishedDate()));
        row(sb, f.basis() == MatchBasis.ADVISORY ? "Advisory" : "CVE record", link(f.url(), f.url()));
        sb.append("</table>");
        if (!f.details().isBlank()) {
            String d = f.details().length() > 8000 ? f.details().substring(0, 8000) + "…" : f.details();
            sb.append("<hr><div>").append(Gui.html(d).replace("\n\n", "<p>").replace("\n", "<br>")).append("</div>");
        }
        return sb.append("</body></html>").toString();
    }

    /** The NVD page of a CVE, an address to copy. */
    static String nvdUrl(String cve) {
        return "https://nvd.nist.gov/vuln/detail/" + cve;
    }

    /** A link to an https address, its text and address escaped; any other address is shown as text, not a link. */
    static String link(String url, String text) {
        if (url == null || !url.startsWith("https://")) return Gui.html(text);
        return "<a href='" + Gui.html(url) + "'>" + Gui.html(text) + "</a>";
    }

    private static void row(StringBuilder sb, String label, String valueHtml) {
        sb.append("<tr><td valign='top'><font color='gray'>").append(label).append("</font></td><td>").append(valueHtml).append("</td></tr>");
    }
}
