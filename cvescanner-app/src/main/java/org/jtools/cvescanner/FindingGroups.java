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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import javax.swing.table.AbstractTableModel;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Finding;
import org.jtools.cvescanner.model.PackageSummary;
import org.jtools.cvescanner.version.Versions;

/**
 * The findings grouped by package version, as the findings' table shows them: a row for each package version (its
 * worst severity, the version fixing all its findings, its tick for Apply fixes, how many advisories), and below it,
 * when opened, a row for each of its findings. Sorted here, not by a RowSorter: a package's findings stay below it
 * whatever the order, the packages ordered by their own value of the column (the first of their findings' for a
 * finding's column).
 */
final class FindingGroups extends AbstractTableModel {

    /** A row of the table: a package version or one of its findings. */
    sealed interface Row permits Group, Child {}

    /** A package version and its findings that the filters let through. */
    record Group(PackageSummary summary, FindingTables.PackageKey key, List<Finding> findings) implements Row {
        Finding worst() {
            return findings.stream().max(Comparator.comparing(Finding::severity)).orElseThrow();
        }

        Double most(Function<Finding, Double> score) {
            return findings.stream().map(score).filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);
        }
    }

    record Child(Finding finding, Group group) implements Row {}

    /**
     * A column: its key, type and width; its value on a package's row and on a finding's (null shows nothing); the
     * order of its values; the value of a finding its header's ▾ filters by (null: no ▾).
     */
    record GColumn(String key, Class<?> type, int width, Function<Group, ?> ofGroup, Function<Finding, ?> ofFinding,
                   Comparator<Object> order, Function<Finding, ?> filter) {}

    static final int EXPAND = 0, PACKAGE = 1, VERSION = 2, COUNT = 3, CVE = 4, SEVERITY = 5, BASE = 6, ENV = 7,
            CVSS = 8, FIXED_IN = 9, PUBLISHED = 10, SUMMARY = 11, ADVISORY = 12, FIX = 13, ECOSYSTEM = 14,
            UPGRADE_TO = 15, MATCH = 16, SCOPE = 17, PATH = 18, FILE = 19;

    @SuppressWarnings("unchecked")
    private static Comparator<Object> natural() {
        return (a, b) -> ((Comparable<Object>) a).compareTo(b);
    }

    private static final Comparator<Object> TEXT = (a, b) -> String.CASE_INSENSITIVE_ORDER.compare(a.toString(), b.toString());
    private static final Comparator<Object> VERSION_ORDER = (a, b) -> Versions.compareMaven(clean(a), clean(b));

    private static String clean(Object version) {
        return version.toString().replace(" ≈", "").replace("—", "");
    }

    private final List<GColumn> columns;
    private final Set<FindingTables.PackageKey> ticked;
    private final Runnable onTicked;
    /** The package versions opened, their findings shown below them; kept through the filters and a new scoring. */
    private final Set<FindingTables.PackageKey> expanded = new HashSet<>();
    private List<Group> groups = List.of();
    private List<Row> rows = List.of();
    private boolean expandAll;
    private int sortColumn = SEVERITY;
    private boolean ascending;

    FindingGroups(Set<FindingTables.PackageKey> ticked, Runnable onTicked) {
        this.ticked = ticked;
        this.onTicked = onTicked;
        Function<Finding, ?> none = null;
        columns = List.of(
                new GColumn("column.expand", String.class, 34, g -> expanded(g) ? "▾" : "▸", f -> "", TEXT, none),
                new GColumn("column.package", String.class, 300, g -> g.summary().pkg(), f -> "", TEXT, Finding::pkg),
                new GColumn("column.version", String.class, 95, g -> g.summary().displayVersion(), f -> "", VERSION_ORDER, Finding::displayVersion),
                new GColumn("column.vulnerabilities", Integer.class, 115, g -> g.summary().vulnerabilities(), f -> null, natural(), none),
                new GColumn("column.cve", String.class, 130, g -> "", Finding::cveText, TEXT, Finding::cveText),
                new GColumn("column.severity", Severity.class, 120, g -> g.summary().worst(), Finding::severity, natural(), Finding::severity),
                new GColumn("column.base", Double.class, 130, g -> g.most(Finding::cvss), Finding::cvss, natural(), Finding::cvss),
                new GColumn("column.env", Double.class, 120, g -> g.most(Finding::envScore), Finding::envScore, natural(), Finding::envScore),
                new GColumn("column.cvss", String.class, 90, g -> "", f -> Objects.requireNonNullElse(f.score().version(), ""), TEXT,
                        f -> Objects.requireNonNullElse(f.score().version(), "")),
                new GColumn("column.fixedIn", String.class, 95, g -> "", f -> f.fixedIn().isEmpty() ? "—" : f.fixedIn(), VERSION_ORDER,
                        f -> f.fixedIn().isEmpty() ? "—" : f.fixedIn()),
                new GColumn("column.published", String.class, 85, g -> "", Finding::publishedDate, TEXT, Finding::publishedDate),
                new GColumn("column.summary", String.class, 380, g -> "", Finding::summary, TEXT, Finding::summary),
                new GColumn("column.advisory", String.class, 150, g -> "", Finding::id, TEXT, Finding::id),
                new GColumn("column.apply", Boolean.class, 50, g -> FindingTables.fixable(g.summary()) ? ticked.contains(g.key()) : null,
                        f -> null, natural(), none),
                new GColumn("column.ecosystem", String.class, 90, g -> g.summary().ecosystem().id(), f -> "", TEXT, f -> f.ecosystem().id()),
                new GColumn("column.upgradeTo", String.class, 140, g -> g.summary().upgradeTo(), f -> "", VERSION_ORDER, none),
                new GColumn("column.match", String.class, 125, g -> "", f -> f.basis().label(), TEXT, f -> f.basis().label()),
                new GColumn("column.scope", String.class, 160, g -> "", Finding::scope, TEXT, Finding::scope),
                new GColumn("column.path", String.class, 180, g -> String.join(", ", new TreeSet<>(g.findings().stream()
                        .map(f -> FindingTables.folderOf(f.file())).toList())), f -> FindingTables.folderOf(f.file()), TEXT,
                        f -> FindingTables.folderOf(f.file())),
                new GColumn("column.file", String.class, 220, g -> g.summary().files(), Finding::file, TEXT, Finding::file));
    }

    List<GColumn> columns() {
        return columns;
    }

    /** These findings, those the filters let through, grouped anew; every group opened while searching. */
    void show(List<Finding> findings, boolean expandAll) {
        this.expandAll = expandAll;
        var byKey = new LinkedHashMap<FindingTables.PackageKey, List<Finding>>();
        for (Finding f : findings)
            byKey.computeIfAbsent(new FindingTables.PackageKey(f.ecosystem(), f.pkg(), f.version()), _ -> new ArrayList<>()).add(f);
        var out = new ArrayList<Group>();
        for (PackageSummary s : PackageSummary.of(findings)) {
            var key = FindingTables.PackageKey.of(s);
            out.add(new Group(s, key, List.copyOf(byKey.get(key))));
        }
        groups = out;
        layout();
    }

    /** The package versions opened that this scan does not report, forgotten. */
    void retainOpened(Set<FindingTables.PackageKey> reported) {
        expanded.retainAll(reported);
    }

    boolean expanded(Group g) {
        return expandAll || expanded.contains(g.key());
    }

    /** A package version opened or closed. */
    void toggle(Group g, boolean open) {
        if (open) expanded.add(g.key());
        else expanded.remove(g.key());
        layout();
    }

    int sortColumn() {
        return sortColumn;
    }

    boolean ascending() {
        return ascending;
    }

    /** Sorted by this column, or the other way when it is the one sorted by; a severity, a score or a count the highest first. */
    void sortBy(int column) {
        if (column == EXPAND) return;
        if (column == sortColumn) ascending = !ascending;
        else {
            sortColumn = column;
            Class<?> type = columns.get(column).type();
            ascending = !(type == Severity.class || type == Double.class || type == Integer.class);
        }
        layout();
    }

    /** The groups sorted, each followed by its findings sorted when it is opened. */
    private void layout() {
        GColumn c = columns.get(sortColumn);
        Comparator<Finding> byFinding = (a, b) -> compare(c.ofFinding().apply(a), c.ofFinding().apply(b), c.order());
        // ties: the most severe, then the highest scores, first
        byFinding = byFinding.thenComparing(Finding::severity, Comparator.reverseOrder())
                .thenComparing(f -> f.envScore() == null ? -1 : f.envScore(), Comparator.reverseOrder())
                .thenComparing(f -> f.cvss() == null ? -1 : f.cvss(), Comparator.reverseOrder());
        var sorted = new ArrayList<Group>();
        for (Group g : groups) {
            var findings = new ArrayList<>(g.findings());
            findings.sort(byFinding);
            sorted.add(new Group(g.summary(), g.key(), List.copyOf(findings)));
        }
        Function<Group, Object> groupValue = g -> {
            Object own = c.ofGroup().apply(g);
            boolean blank = own == null || own.equals("");
            return blank ? c.ofFinding().apply(g.findings().getFirst()) : own;
        };
        sorted.sort((a, b) -> compare(groupValue.apply(a), groupValue.apply(b), c.order()));
        groups = sorted;
        var flat = new ArrayList<Row>();
        for (Group g : groups) {
            flat.add(g);
            if (expanded(g)) for (Finding f : g.findings()) flat.add(new Child(f, g));
        }
        rows = flat;
        fireTableDataChanged();
    }

    /** Two values in the column's order, the way sorted; nothing ("", null) last either way. */
    private int compare(Object a, Object b, Comparator<Object> order) {
        boolean noA = a == null || a.equals(""), noB = b == null || b.equals("");
        if (noA || noB) return noA == noB ? 0 : noA ? 1 : -1;
        int c = order.compare(a, b);
        return ascending ? c : -c;
    }

    /** Every finding the filters let through, package by package, in the table's order: opened or not. */
    List<Finding> findings() {
        return groups.stream().flatMap(g -> g.findings().stream()).toList();
    }

    int packages() {
        return groups.size();
    }

    Row row(int index) {
        return rows.get(index);
    }

    /** The row of this finding, its package opened for it; -1 when it is not let through. */
    int rowOf(Finding f) {
        for (Group g : groups)
            for (Finding x : g.findings())
                if (same(x, f)) {
                    if (!expanded(g)) toggle(g, true);
                    for (int i = 0; i < rows.size(); i++) if (rows.get(i) instanceof Child c && same(c.finding(), f)) return i;
                }
        return -1;
    }

    /** The row of this package version; -1 when it is not let through. */
    int rowOf(FindingTables.PackageKey key) {
        for (int i = 0; i < rows.size(); i++) if (rows.get(i) instanceof Group g && g.key().equals(key)) return i;
        return -1;
    }

    static boolean same(Finding a, Finding b) {
        return a.id().equals(b.id()) && a.file().equals(b.file()) && a.scope().equals(b.scope()) && a.pkg().equals(b.pkg())
                && a.version().equals(b.version());
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return columns.size(); }
    @Override public String getColumnName(int c) { return I18n.text(columns.get(c).key()); }
    @Override public Class<?> getColumnClass(int c) { return columns.get(c).type(); }

    @Override
    public Object getValueAt(int r, int c) {
        return switch (rows.get(r)) {
            case Group g -> columns.get(c).ofGroup().apply(g);
            case Child ch -> columns.get(c).ofFinding().apply(ch.finding());
        };
    }

    @Override
    public boolean isCellEditable(int r, int c) {
        return c == FIX && rows.get(r) instanceof Group g && FindingTables.fixable(g.summary());
    }

    @Override
    public void setValueAt(Object value, int r, int c) {
        if (!isCellEditable(r, c)) return;
        var key = ((Group) rows.get(r)).key();
        if (Boolean.TRUE.equals(value)) ticked.add(key);
        else ticked.remove(key);
        fireTableCellUpdated(r, c);
        onTicked.run();
    }
}
