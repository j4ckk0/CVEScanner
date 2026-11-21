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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.StringReader;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import org.jtools.cvescanner.cvss.Environment;
import org.jtools.cvescanner.cvss.Rating;
import org.jtools.cvescanner.cvss.Score;
import org.jtools.cvescanner.i18n.Phrase;
import org.jtools.cvescanner.ignore.IgnoreRule;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.MatchBasis;
import org.jtools.cvescanner.model.Severity;
import org.junit.jupiter.api.Test;

/**
 * What a database writes cannot make the window reach the network (README, "No network"): Swing's HTML fetches the
 * image or the style sheet a page names, so an advisory's text must reach the details pane as text, every field of
 * it; and a table cell, a label, shows what it is given as text even when it begins with &lt;html&gt;.
 */
class HostileAdvisoryTest {

    private static final String TAGS = "<img src='http://attacker.example/x.png'><base href='http://attacker.example/'>"
            + "<link rel=stylesheet href='http://attacker.example/s.css'><a href='file:///etc/passwd'>x</a>";
    private static final String BREAKOUT = "x'><img src='http://attacker.example/y.png'>";

    /** The tags the page writes itself; any other came from the data. */
    private static final Set<String> PAGE_TAGS = Set.of("html", "head", "body", "div", "b", "font", "p", "table", "tr",
            "td", "a", "br", "hr", "i");

    private static Finding hostile() {
        Score score = new Score("3.1", BREAKOUT, 9.8, Severity.CRITICAL, BREAKOUT, 9.0);
        Rating rating = new Rating(Severity.CRITICAL, null, BREAKOUT, BREAKOUT + "4");
        return new Finding(Severity.CRITICAL, score, "npm" + TAGS, "pkg" + TAGS, "1.0" + TAGS, false, "direct" + TAGS,
                "file" + TAGS, "GHSA" + BREAKOUT, List.of("CVE-1" + BREAKOUT, "CVE-2" + TAGS), List.of("alias" + TAGS),
                "2.0" + TAGS, "summary" + TAGS, "details" + TAGS + "\n\nmore" + TAGS, "2026-01-01" + TAGS,
                "file:///etc/passwd", MatchBasis.ADVISORY, Phrase.of("match.note.name", "note" + TAGS), rating);
    }

    private record Tag(String name, String href) {
    }

    private static List<Tag> tags(String html) throws IOException {
        List<Tag> tags = new ArrayList<>();
        new ParserDelegator().parse(new StringReader(html), new HTMLEditorKit.ParserCallback() {
            @Override
            public void handleStartTag(HTML.Tag t, MutableAttributeSet a, int pos) {
                tags.add(new Tag(t.toString(), (String) a.getAttribute(HTML.Attribute.HREF)));
            }

            @Override
            public void handleSimpleTag(HTML.Tag t, MutableAttributeSet a, int pos) {
                if (!a.isDefined(HTML.Attribute.ENDTAG)) {
                    tags.add(new Tag(t.toString(), (String) a.getAttribute(HTML.Attribute.HREF)));
                }
            }
        }, true);
        return tags;
    }

    @Test
    void theDetailsPaneHoldsNoTagOfTheDatabase() throws IOException {
        for (Environment environment : List.of(Environment.NONE, Environment.preset("airgapped"))) {
            String page = FindingDetails.page(hostile(), environment);
            Set<String> foreign = new TreeSet<>();
            for (Tag tag : tags(page)) {
                if (!PAGE_TAGS.contains(tag.name())) foreign.add(tag.name());
            }
            assertEquals(Set.of(), foreign, page);
            assertTrue(page.contains("&lt;img src=&#39;http://attacker.example/x.png&#39;&gt;"), page);
        }
    }

    @Test
    void theIgnoredBlockHoldsNoTagOfTheIgnoreFile() throws IOException {
        var rule = new IgnoreRule("CVE-1", "", "", LocalDate.of(2030, 1, 1), "reason" + TAGS + BREAKOUT, 3);
        String page = FindingDetails.page(hostile(), Environment.NONE, rule, "dir" + TAGS + "/cvescanner-ignore.csv");
        Set<String> foreign = new TreeSet<>();
        for (Tag tag : tags(page)) {
            if (!PAGE_TAGS.contains(tag.name())) foreign.add(tag.name());
        }
        assertEquals(Set.of(), foreign, page);
        assertTrue(page.contains("reason&lt;img"), page);
    }

    @Test
    void itsLinksAreHttpsOnly() throws IOException {
        List<String> hrefs = tags(FindingDetails.page(hostile(), Environment.NONE)).stream()
                .filter(tag -> tag.name().equals("a")).map(Tag::href).toList();
        assertEquals(2, hrefs.size(), "the CVEs' NVD pages, not the file: advisory: " + hrefs);
        for (String href : hrefs) {
            assertTrue(href.startsWith("https://nvd.nist.gov/vuln/detail/CVE-"), href);
        }
    }

    @Test
    void aCellShowsHtmlAsText() {
        var renderer = new TextRenderer();
        var label = (JLabel) renderer.getTableCellRendererComponent(new JTable(), "<html>" + TAGS, false, false, 0, 0);
        assertNull(label.getClientProperty(BasicHTML.propertyKey), "the cell renders its text as HTML");
        assertEquals("<html>" + TAGS, label.getText());
    }

    @Test
    void aLabelOfDataShowsHtmlAsText() {
        JLabel label = Gui.noHtml(new JLabel());
        label.setText("<html>" + TAGS);
        assertNull(label.getClientProperty(BasicHTML.propertyKey), "the label renders its text as HTML");
    }
}
