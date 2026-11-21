package org.jtools.cvescanner.ignore;

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

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;

/**
 * One line of an ignore file: the findings of this vulnerability, for this package and this version, are set aside, for
 * this reason, up to this day. An empty package or version is any; no date is for ever. The id is an advisory's, a CVE,
 * or an alias: a CVE sets aside the GitHub or OSV advisory that names it as well as the CVE record. A VEX statement
 * that the vulnerability does not apply sets findings aside the same way (VexStatement.asRule).
 *
 * @param line   the line of the file it was read from, 0 for an entry not read from a file
 * @param source the VEX document it comes from, as shown; null for an entry of the ignore file
 */
public record IgnoreRule(String id, String pkg, String version, LocalDate until, String reason, int line, String source) {

    public IgnoreRule(String id, String pkg, String version, LocalDate until, String reason, int line) {
        this(id, pkg, version, until, reason, line, null);
    }

    /** Set aside by a VEX document, not by the ignore file: edited there, not by Stop ignoring. */
    public boolean fromVex() {
        return source != null;
    }

    /** What an entry made from a finding covers: its version of its package, every version of it, every package. */
    public enum Scope { VERSION, PACKAGE, EVERYWHERE }

    public IgnoreRule {
        id = Objects.requireNonNullElse(id, "").strip();
        pkg = Objects.requireNonNullElse(pkg, "").strip();
        version = Objects.requireNonNullElse(version, "").strip();
        reason = Objects.requireNonNullElse(reason, "").strip();
    }

    /** Whether it names this finding: its id, one of its CVEs or aliases, and its package and version when it gives them. */
    public boolean matches(Finding f) {
        boolean named = id.equalsIgnoreCase(f.id()) || f.cves().stream().anyMatch(id::equalsIgnoreCase)
                || f.aliases().stream().anyMatch(id::equalsIgnoreCase);
        return named && (pkg.isEmpty() || samePackage(f)) && (version.isEmpty() || version.equals(f.version()));
    }

    /**
     * The finding's package, whatever the case; a Python one as PEP 503 normalizes names (Zope.Interface is
     * zope-interface); a component off-the-shelf by its vendor:product or its product alone (gdal for osgeo:gdal).
     */
    private boolean samePackage(Finding f) {
        if (pkg.equalsIgnoreCase(f.pkg())) return true;
        if (f.ecosystem() == Ecosystem.PYPI) return Ecosystem.pep503(pkg).equals(Ecosystem.pep503(f.pkg()));
        return f.ecosystem() == Ecosystem.COTS && pkg.equalsIgnoreCase(Ecosystem.product(f.pkg()));
    }

    /** Past its last day: it sets nothing aside any more. */
    public boolean expired(LocalDate today) {
        return until != null && today.isAfter(until);
    }

    /** The same entry, wherever it is in its file. */
    public boolean sameEntry(IgnoreRule other) {
        return id.equalsIgnoreCase(other.id) && pkg.equalsIgnoreCase(other.pkg) && version.equals(other.version)
                && Objects.equals(until, other.until) && reason.equals(other.reason);
    }

    /**
     * The last day an entry applies, as the window and the command line take it: none when the text is empty; today or
     * later, written yyyy-MM-dd. Throws IllegalArgumentException, saying why, otherwise.
     */
    public static LocalDate until(String text, LocalDate today) {
        String s = Objects.requireNonNullElse(text, "").strip();
        if (s.isEmpty()) return null;
        LocalDate date;
        try {
            date = LocalDate.parse(s);
        } catch (DateTimeParseException _) {
            throw new IllegalArgumentException(I18n.text("ignore.until.notADate", s));
        }
        if (date.isBefore(today)) throw new IllegalArgumentException(I18n.text("ignore.until.past", s));
        return date;
    }

    /**
     * The entry that sets this finding aside, at this scope. It names the finding by its first CVE when it has one: a
     * CVE is the same in every database, so the entry still applies once the scan uses another one.
     */
    public static IgnoreRule forFinding(Finding f, Scope scope, String reason, LocalDate until) {
        String id = f.cves().isEmpty() ? f.id() : f.cves().getFirst();
        return new IgnoreRule(id, scope == Scope.EVERYWHERE ? "" : f.pkg(), scope == Scope.VERSION ? f.version() : "",
                until, reason, 0);
    }
}
