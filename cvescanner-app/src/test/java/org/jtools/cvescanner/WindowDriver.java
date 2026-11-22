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

import java.awt.AWTException;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.KeyboardFocusManager;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JComboBox;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import org.jtools.cvescanner.cli.Options;

/**
 * Drives the real window as a person would, for the window test and the README's screenshots: started in this JVM,
 * clicked with a Robot, its components found by their test name (MainWindow.nameForTests) or by type and text. Run
 * on a virtual display only (xvfb-run): it moves the pointer and types.
 */
final class WindowDriver implements AutoCloseable {

    /** How long a step may take: a scan of real databases takes minutes (-Dcvescanner.windowWait, in seconds). */
    private static final Duration WAIT = Duration.ofSeconds(Integer.getInteger("cvescanner.windowWait", 60));

    private final Robot robot;
    final MainWindow window;

    private WindowDriver(MainWindow window) throws AWTException {
        this.window = window;
        this.robot = new Robot();
        robot.setAutoDelay(30);
    }

    /** The window on these arguments, its settings in that folder, shown and its first scan (if any) done. */
    static WindowDriver start(Path settingsFolder, String... args) throws Exception {
        Settings settings = Settings.in(settingsFolder);
        // the counts the same on every machine: no local Maven repository read, unless a test says otherwise
        if (settings.get(Settings.MAVEN_TRANSITIVE, null) == null) settings.set(Settings.MAVEN_TRANSITIVE, "false");
        Options opts = Options.parse(args);
        var window = new AtomicReference<MainWindow>();
        SwingUtilities.invokeAndWait(() -> {
            Looks.use(settings.get(Settings.LOOK, Looks.DEFAULT));
            var w = new MainWindow(opts, settings);
            w.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
            w.setLocation(0, 0);
            w.setVisible(true);
            window.set(w);
        });
        var driver = new WindowDriver(window.get());
        driver.waitUntil("the window shown", () -> driver.window.isShowing());
        if (opts.dirGiven) driver.waitUntil("the first scan", () -> driver.window.scanned() && driver.named("scan").isEnabled());
        driver.robot.waitForIdle();
        return driver;
    }

    @Override
    public void close() throws Exception {
        for (Window w : onEdt(Window::getWindows)) SwingUtilities.invokeAndWait(w::dispose);
    }

    // ------------------------------------------------------------------------------------------- finding

    static <T> T onEdt(Callable<T> c) throws Exception {
        var result = new AtomicReference<T>();
        var failure = new AtomicReference<Exception>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(c.call());
            } catch (Exception e) {
                failure.set(e);
            }
        });
        if (failure.get() != null) throw failure.get();
        return result.get();
    }

    /** The windows showing, the active one (a dialog over the frame) first. */
    private static List<Window> windows() {
        var out = new ArrayList<Window>();
        for (Window w : Window.getWindows()) if (w.isShowing()) out.add(w);
        out.sort(Comparator.comparing((Window w) -> !(w instanceof Dialog)).thenComparing(w -> !w.isActive()));
        return out;
    }

    private static List<Component> all(Container c) {
        var out = new ArrayList<Component>();
        for (Component k : c.getComponents()) {
            if (!k.isShowing()) continue;
            out.add(k);
            if (k instanceof Container cc) out.addAll(all(cc));
        }
        return out;
    }

    <T extends Component> T find(Class<T> type, Predicate<T> test) throws Exception {
        return onEdt(() -> {
            for (Window w : windows())
                for (Component k : all(w))
                    if (type.isInstance(k) && test.test(type.cast(k))) return type.cast(k);
            return null;
        });
    }

    /** The component of that test name, waited for. */
    Component named(String name) throws Exception {
        return awaitFound("the component " + name, () -> find(Component.class, k -> name.equals(k.getName())));
    }

    @SuppressWarnings("unchecked")
    <T extends Component> T named(String name, Class<T> type) throws Exception {
        return (T) named(name);
    }

    /** The dialog showing whose title starts so, waited for. */
    Dialog dialog(String title) throws Exception {
        return awaitFound("the dialog " + title, () -> onEdt(() -> {
            for (Window w : windows()) if (w instanceof Dialog d && d.getTitle() != null && d.getTitle().startsWith(title)) return d;
            return null;
        }));
    }

    boolean dialogShowing() throws Exception {
        return onEdt(() -> windows().stream().anyMatch(w -> w instanceof Dialog));
    }

    /** Every text the window (or the dialog over it) shows: labels, buttons, text, tab titles. */
    String text(Container in) throws Exception {
        return onEdt(() -> {
            var sb = new StringBuilder();
            for (Component k : all(in)) {
                if (k instanceof AbstractButton b && b.getText() != null) sb.append(b.getText()).append('\n');
                else if (k instanceof JLabel l && l.getText() != null) sb.append(l.getText()).append('\n');
                else if (k instanceof JEditorPane p) sb.append(p.getDocument().getText(0, p.getDocument().getLength())).append('\n');
                else if (k instanceof JTextComponent t) sb.append(t.getText()).append('\n');
                else if (k instanceof JTabbedPane tp) for (int i = 0; i < tp.getTabCount(); i++) sb.append(tp.getTitleAt(i)).append('\n');
            }
            return sb.toString();
        });
    }

    String text(String name) throws Exception {
        Component k = named(name);
        return onEdt(() -> k instanceof JLabel l ? l.getText() : k instanceof JTextComponent t ? t.getText()
                : k instanceof AbstractButton b ? b.getText() : String.valueOf(k));
    }

    String details() throws Exception {
        var pane = named("details", JEditorPane.class);
        return onEdt(() -> pane.getDocument().getText(0, pane.getDocument().getLength()));
    }

    String tabTitle(int index) throws Exception {
        var tabs = named("tabs", JTabbedPane.class);
        return onEdt(() -> tabs.getTitleAt(index));
    }

    /** The table showing in the selected tab. */
    JTable table() throws Exception {
        var tabs = named("tabs", JTabbedPane.class);
        return onEdt(() -> {
            for (Component k : all((Container) tabs.getSelectedComponent())) if (k instanceof JTable t) return t;
            return null;
        });
    }

    // ------------------------------------------------------------------------------------------- acting

    void clickAt(Component k, int x, int y) throws Exception {
        Point p = onEdt(() -> {
            Point s = k.getLocationOnScreen();
            return new Point(s.x + x, s.y + y);
        });
        robot.mouseMove(p.x, p.y);
        robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        robot.waitForIdle();
    }

    void click(Component k) throws Exception {
        Dimension d = onEdt(k::getSize);
        clickAt(k, d.width / 2, d.height / 2);
    }

    /** Clicks the button showing whose text starts so, in the dialog over the window first. */
    void clickButton(String text) throws Exception {
        click(awaitFound("the button " + text, () -> find(AbstractButton.class,
                b -> !(b instanceof JMenuItem) && b.getText() != null && b.getText().startsWith(text))));
    }

    void clickTab(int index) throws Exception {
        var tabs = named("tabs", JTabbedPane.class);
        Rectangle r = onEdt(() -> tabs.getBoundsAt(index));
        clickAt(tabs, r.x + r.width / 2, r.y + r.height / 2);
    }

    /** Clicks a column of the first row of the table showing that holds this text. */
    void clickRow(String text, int column) throws Exception {
        JTable t = table();
        Rectangle r = onEdt(() -> {
            for (int row = 0; row < t.getRowCount(); row++)
                for (int c = 0; c < t.getColumnCount(); c++)
                    if (String.valueOf(t.getValueAt(row, c)).contains(text)) {
                        t.scrollRectToVisible(t.getCellRect(row, column, true));
                        return t.getCellRect(row, column, true);
                    }
            return null;
        });
        if (r == null) throw new AssertionError("no row holding " + text);
        clickAt(t, r.x + r.width / 2, r.y + r.height / 2);
    }

    /** Clicks each menu of the path in turn, by the start of its text: "View", "Database age". */
    void menu(String... path) throws Exception {
        for (String part : path) {
            click(awaitFound("the menu " + part, () -> find(JMenuItem.class, m -> m.getText() != null && m.getText().startsWith(part))));
            Thread.sleep(200);
        }
    }

    /** Picks the item whose text starts so in this combo box, as a person would: opening it, clicking the item. */
    void choose(JComboBox<?> combo, String item) throws Exception {
        click(combo);
        JList<?> list = awaitFound("the item " + item, () -> find(JList.class, l -> index(l, item) >= 0));
        Rectangle r = onEdt(() -> list.getCellBounds(index(list, item), index(list, item)));
        clickAt(list, r.x + r.width / 2, r.y + r.height / 2);
    }

    private static int index(JList<?> list, String item) {
        for (int i = 0; i < list.getModel().getSize(); i++) if (String.valueOf(list.getModel().getElementAt(i)).startsWith(item)) return i;
        return -1;
    }

    /** Types into this text field, its text replaced. */
    void type(JTextField field, String text) throws Exception {
        click(field);
        onEdt(() -> {
            field.selectAll();
            field.replaceSelection(text);
            return null;
        });
    }

    /** Types into the component that has the focus (a file chooser's name field), its text replaced. */
    void typeInFocus(String text) throws Exception {
        waitUntil("a text field focused", () -> onEdt(() ->
                KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner() instanceof JTextComponent));
        onEdt(() -> {
            var t = (JTextComponent) KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
            t.selectAll();
            t.replaceSelection(text);
            return null;
        });
    }

    void key(int keyCode) {
        robot.keyPress(keyCode);
        robot.keyRelease(keyCode);
        robot.waitForIdle();
    }

    void tab() {
        key(KeyEvent.VK_TAB);
    }

    /** Clicks Scan and waits for the scan to end: the button disabled, then enabled again. */
    void scan() throws Exception {
        Component button = named("scan");
        var ended = new CountDownLatch(1);
        java.beans.PropertyChangeListener listener = e -> {
            if (Boolean.TRUE.equals(e.getNewValue())) ended.countDown();
        };
        SwingUtilities.invokeAndWait(() -> button.addPropertyChangeListener("enabled", listener));
        try {
            click(button);
            if (!ended.await(WAIT.toSeconds(), TimeUnit.SECONDS)) throw new AssertionError("the scan did not end");
        } finally {
            SwingUtilities.invokeAndWait(() -> button.removePropertyChangeListener("enabled", listener));
        }
        robot.waitForIdle();
    }

    // ------------------------------------------------------------------------------------------- waiting, pictures

    interface Check {
        boolean holds() throws Exception;
    }

    interface Lookup<T> {
        T find() throws Exception;
    }

    void waitUntil(String what, Check check) throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        while (System.nanoTime() < end) {
            if (check.holds()) return;
            Thread.sleep(100);
        }
        throw new AssertionError("waited in vain for " + what);
    }

    <T> T awaitFound(String what, Lookup<T> lookup) throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        while (System.nanoTime() < end) {
            T found = lookup.find();
            if (found != null) return found;
            Thread.sleep(100);
        }
        throw new AssertionError("waited in vain for " + what);
    }

    /** The window as shown, any dialog over it included, into this PNG. */
    void screenshot(Path file) throws Exception {
        robot.waitForIdle();
        Thread.sleep(300);
        Rectangle r = onEdt(() -> new Rectangle(window.getLocationOnScreen(), window.getSize()));
        try {
            ImageIO.write(robot.createScreenCapture(r), "png", file.toFile());
        } catch (IOException e) {
            throw new IOException("cannot write " + file, e);
        }
    }

    static String title(Window w) {
        return w instanceof Frame f ? f.getTitle() : w instanceof Dialog d ? d.getTitle() : "";
    }
}
