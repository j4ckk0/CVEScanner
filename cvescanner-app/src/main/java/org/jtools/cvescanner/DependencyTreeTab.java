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
import java.awt.Component;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import org.jtools.cvescanner.cvss.Severity;
import org.jtools.cvescanner.i18n.I18n;
import org.jtools.cvescanner.model.Dependency;
import org.jtools.cvescanner.model.DependencyTree;
import org.jtools.cvescanner.model.Ecosystem;
import org.jtools.cvescanner.model.Finding;

/**
 * The Dependencies tab: each file's dependencies as a tree, each declared one with what it brings below it, each with
 * the dot of its worst finding. The ecosystem filter, the search and Hide indirect dependencies apply; the severity
 * filters do not: it lists every dependency, not only those with findings.
 */
final class DependencyTreeTab {

    /** A file of the scan, and how many dependencies it holds. */
    record FileEntry(String file, int count) {}

    /** A dependency, its findings and the worst of their severities (null for none). */
    record DependencyEntry(Dependency dependency, List<Finding> findings, Severity worst) {}

    /** The indirect dependencies of a file that does not record what brings them. */
    record UnrecordedEntry(int count) {}

    private static final int DOT = 10;
    private static final Color NO_FINDING = new Color(0, 0, 0, 0);

    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode();
    private final DefaultTreeModel model = new DefaultTreeModel(root);
    private final JTree tree = new JTree(model);
    private final JScrollPane scroll = new JScrollPane(tree);
    private List<DependencyTree> trees = List.of();
    private Map<String, List<Finding>> findings = Map.of();
    private int total, shown;

    DependencyTreeTab(Runnable selectionChanged) {
        tree.setName("dependencyTree");   // for the window test (WindowDriver)
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.addTreeSelectionListener(_ -> selectionChanged.run());
        tree.setCellRenderer(new DefaultTreeCellRenderer() {
            @Override
            public Component getTreeCellRendererComponent(JTree t, Object value, boolean selected, boolean expanded, boolean leaf,
                                                          int row, boolean focus) {
                super.getTreeCellRendererComponent(t, value, selected, expanded, leaf, row, focus);
                Object entry = ((DefaultMutableTreeNode) value).getUserObject();
                switch (entry) {
                    case FileEntry f -> setText(I18n.text("tree.file", f.file(), f.count()));
                    case UnrecordedEntry u -> setText(I18n.text("tree.unrecorded", u.count()));
                    case DependencyEntry d -> {
                        setText(text(d));
                        setIcon(new DotIcon(d.worst() == null ? NO_FINDING : SeverityColors.of(d.worst()), DOT));
                    }
                    case null, default -> { }
                }
                return this;
            }
        });
    }

    JScrollPane component() {
        return scroll;
    }

    /** "lodash 4.17.15 · direct · 2 findings": its scope without the Maven walk's "via", which the tree shows. */
    private static String text(DependencyEntry d) {
        Dependency dep = d.dependency();
        String scope = dep.scope().replaceFirst(" via .*$", "");
        String text = dep.name() + " " + dep.version() + "  ·  " + scope;
        return d.findings().isEmpty() ? text : text + "  ·  " + I18n.text("tree.findings", d.findings().size());
    }

    /** A new scan's dependencies, with the findings reported (the ignore file's set aside). */
    void show(List<Dependency> dependencies, List<Finding> active) {
        trees = DependencyTree.of(dependencies);
        findings = DependencyTree.findingsBy(active);
        total = dependencies.size();
    }

    /** The tree rebuilt for these filters; the paths down to a finding opened, every path while searching. */
    void filter(Ecosystem ecosystem, List<String> terms, boolean hideTransitive) {
        root.removeAllChildren();
        shown = 0;
        for (DependencyTree t : trees) {
            var file = new DefaultMutableTreeNode();
            int count = 0;
            for (DependencyTree.Node n : t.roots()) {
                if (hideTransitive && n.dependency().transitive()) continue;
                var child = node(n, ecosystem, terms, hideTransitive);
                if (child != null) {
                    file.add(child);
                    count += countOf(child);
                }
            }
            if (!hideTransitive && !t.unrecorded().isEmpty()) {
                var group = new DefaultMutableTreeNode();
                for (Dependency d : t.unrecorded())
                    if (kept(d, ecosystem, terms)) group.add(new DefaultMutableTreeNode(entry(d), false));
                if (group.getChildCount() > 0) {
                    group.setUserObject(new UnrecordedEntry(group.getChildCount()));
                    file.add(group);
                    count += group.getChildCount();
                }
            }
            if (file.getChildCount() == 0) continue;
            file.setUserObject(new FileEntry(t.file(), count));
            root.add(file);
            shown += count;
        }
        model.reload();
        expand(root, !terms.isEmpty());
    }

    /** A node and what it brings, those the filters keep; null when neither it nor anything below it is kept. */
    private DefaultMutableTreeNode node(DependencyTree.Node n, Ecosystem ecosystem, List<String> terms, boolean hideTransitive) {
        var node = new DefaultMutableTreeNode(entry(n.dependency()));
        if (!hideTransitive)
            for (DependencyTree.Node c : n.children()) {
                var child = node(c, ecosystem, terms, false);
                if (child != null) node.add(child);
            }
        return node.getChildCount() > 0 || kept(n.dependency(), ecosystem, terms) ? node : null;
    }

    private static int countOf(DefaultMutableTreeNode node) {
        int count = 0;
        for (var e = node.preorderEnumeration(); e.hasMoreElements(); ) {
            if (((DefaultMutableTreeNode) e.nextElement()).getUserObject() instanceof DependencyEntry) count++;
        }
        return count;
    }

    private static boolean kept(Dependency d, Ecosystem ecosystem, List<String> terms) {
        if (ecosystem != null && d.ecosystem() != ecosystem) return false;
        String text = String.join("\u0001", d.name(), d.version(), d.scope(), d.file()).toLowerCase(Locale.ROOT);
        return terms.stream().allMatch(text::contains);
    }

    private DependencyEntry entry(Dependency d) {
        var own = findings.getOrDefault(DependencyTree.key(d), List.of());
        return new DependencyEntry(d, own, own.stream().map(Finding::severity).max(Comparator.naturalOrder()).orElse(null));
    }

    /** Opens each node with a finding below it, or every node. */
    private boolean expand(DefaultMutableTreeNode node, boolean all) {
        boolean open = false;
        for (int i = 0; i < node.getChildCount(); i++) {
            var child = (DefaultMutableTreeNode) node.getChildAt(i);
            boolean below = expand(child, all);
            if (below || all) tree.expandPath(new TreePath(child.getPath()));
            open |= below || child.getUserObject() instanceof DependencyEntry d && !d.findings().isEmpty();
        }
        return open;
    }

    /** The tab's title: how many dependencies it shows, of how many. */
    String title() {
        return shown == total ? I18n.text("tab.dependencies", total) : I18n.text("tab.dependencies.filtered", shown, total);
    }

    /** The worst finding of the dependency selected; null when none is, or it has none. */
    Finding selectedWorstFinding() {
        var path = tree.getSelectionPath();
        if (path == null || !(((DefaultMutableTreeNode) path.getLastPathComponent()).getUserObject() instanceof DependencyEntry d))
            return null;
        return d.findings().stream().max(Comparator.comparing(Finding::severity)).orElse(null);
    }

    JTree tree() {
        return tree;
    }

    /** The rows shown, two spaces per level then the file or "name version" ("?" for the unrecorded group): for the window test. */
    static List<String> rows(JTree tree) {
        var out = new ArrayList<String>();
        var root = (DefaultMutableTreeNode) tree.getModel().getRoot();
        for (var e = root.preorderEnumeration(); e.hasMoreElements(); ) {
            var node = (DefaultMutableTreeNode) e.nextElement();
            if (node == root) continue;
            String text = switch (node.getUserObject()) {
                case FileEntry f -> f.file();
                case UnrecordedEntry _ -> "?";
                case DependencyEntry d -> d.dependency().name() + " " + d.dependency().version();
                case null, default -> String.valueOf(node.getUserObject());
            };
            out.add("  ".repeat(node.getLevel() - 1) + text);
        }
        return out;
    }
}
