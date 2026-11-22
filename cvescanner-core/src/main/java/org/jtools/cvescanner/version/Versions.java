package org.jtools.cvescanner.version;

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
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class Versions {
    private record Tok(int kind, long num, String qualifier) implements Comparable<Tok> {
        public int compareTo(Tok o) {
            int c = Integer.compare(kind, o.kind);
            if (c == 0) c = Long.compare(num, o.num);
            return c != 0 ? c : qualifier.compareTo(o.qualifier);
        }
    }

    // kind 1 = known qualifier, 2 = unknown qualifier (sorts after release), 3 = number
    private static final Map<String, Integer> QUALIFIERS = Map.ofEntries(
            Map.entry("alpha", 1), Map.entry("a", 1), Map.entry("beta", 2), Map.entry("b", 2),
            Map.entry("milestone", 3), Map.entry("m", 3), Map.entry("rc", 4), Map.entry("cr", 4),
            Map.entry("snapshot", 5), Map.entry("", 6), Map.entry("ga", 6), Map.entry("final", 6),
            Map.entry("release", 6), Map.entry("sp", 7));
    private static final Tok NUM_PAD = new Tok(3, 0, ""), RELEASE_PAD = new Tok(1, 6, "");
    private static final Pattern TOKEN = Pattern.compile("\\d+|[a-z]+");
    private static final Pattern SEMVER =
            Pattern.compile("^[=v]*(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:-([0-9A-Za-z.\\-]+))?(?:\\+.*)?$");

    private Versions() {}

    private static List<Tok> mavenTokens(String v) {
        var out = new ArrayList<Tok>();
        var run = new ArrayList<Long>();
        var m = TOKEN.matcher(v.toLowerCase(Locale.ROOT));
        while (m.find()) {
            String t = m.group();
            if (Character.isDigit(t.charAt(0))) {
                run.add(t.length() > 18 ? Long.MAX_VALUE : Long.parseLong(t));
            } else {
                flush(run, out);
                Integer q = QUALIFIERS.get(t);
                out.add(q != null ? new Tok(1, q, "") : new Tok(2, 0, t));
            }
        }
        flush(run, out);
        return out;
    }

    private static void flush(List<Long> run, List<Tok> out) {
        while (run.size() > 1 && run.getLast() == 0L) run.removeLast();   // 1.0.0 == 1.0 == 1
        for (long n : run) out.add(new Tok(3, n, ""));
        run.clear();
    }

    public static int compareMaven(String a, String b) {
        var x = mavenTokens(a);
        var y = mavenTokens(b);
        for (int k = 0; k < Math.max(x.size(), y.size()); k++) {
            Tok p = k < x.size() ? x.get(k) : null;
            Tok q = k < y.size() ? y.get(k) : null;
            if (p == null) p = q.kind() == 3 ? NUM_PAD : RELEASE_PAD;
            if (q == null) q = p.kind() == 3 ? NUM_PAD : RELEASE_PAD;
            int c = p.compareTo(q);
            if (c != 0) return c < 0 ? -1 : 1;
        }
        return 0;
    }

    public static boolean isSemver(String v) { return SEMVER.matcher(v.strip()).matches(); }

    private static final Pattern PEP440 = Pattern.compile(
            "v?(?:(\\d+)!)?(\\d+(?:\\.\\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\\d*))?"
                    + "(?:-(\\d+)|[-_.]?(?:post|rev|r)[-_.]?(\\d*))?(?:[-_.]?dev[-_.]?(\\d*))?(?:\\+.*)?");

    /**
     * Two Python versions in PEP 440's order: the epoch, the release, then a pre-release (a, b, rc) before the
     * release, a post-release after it, a development release before what it leads to. A version PEP 440 does not
     * describe is compared as Maven's.
     */
    public static int comparePep440(String a, String b) {
        long[] x = pep440(a), y = pep440(b);
        if (x == null || y == null) return compareMaven(a, b);
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int c = Long.compare(i < x.length ? x[i] : 0, i < y.length ? y[i] : 0);
            if (c != 0) return c;
        }
        return 0;
    }

    /**
     * A PEP 440 version as numbers to compare in order: its epoch, its release (32 numbers, zeros after), its
     * pre-release phase and number, its post-release, its development release. Null for anything else. An optional
     * part that is absent is null in the match, one present without a number is "".
     */
    private static long[] pep440(String version) {
        var m = PEP440.matcher(version.strip().toLowerCase(Locale.ROOT));
        if (!m.matches()) return null;
        long absentAfter = Long.MAX_VALUE, absentBefore = Long.MIN_VALUE;
        String phase = m.group(3), post = m.group(5) != null ? m.group(5) : m.group(6), dev = m.group(7);
        long[] key = new long[1 + 32 + 4];
        key[0] = m.group(1) == null ? 0 : num(m.group(1));
        String[] release = m.group(2).split("\\.");
        for (int i = 0; i < release.length && i < 32; i++) key[1 + i] = num(release[i]);
        key[33] = phase == null ? (post == null && dev != null ? absentBefore : absentAfter)   // 1.0.dev1 before 1.0a1
                : switch (phase) {
                    case "a", "alpha" -> 0;
                    case "b", "beta" -> 1;
                    default -> 2;
                };
        key[34] = phase == null ? 0 : num(m.group(4));
        key[35] = post == null ? absentBefore : num(post);
        key[36] = dev == null ? absentAfter : num(dev);
        return key;
    }

    public static Integer compareSemver(String a, String b) {
        var ma = SEMVER.matcher(a.strip());
        var mb = SEMVER.matcher(b.strip());
        if (!ma.matches() || !mb.matches()) return null;
        for (int g = 1; g <= 3; g++) {
            int c = Long.compare(num(ma.group(g)), num(mb.group(g)));
            if (c != 0) return c;
        }
        String pa = ma.group(4), pb = mb.group(4);
        if (pa == null || pb == null) return pa == null ? (pb == null ? 0 : 1) : -1;   // release > pre-release
        String[] xa = pa.split("\\."), xb = pb.split("\\.");
        for (int k = 0; k < Math.min(xa.length, xb.length); k++) {
            boolean na = xa[k].chars().allMatch(Character::isDigit), nb = xb[k].chars().allMatch(Character::isDigit);
            int c = na && nb ? Long.compare(num(xa[k]), num(xb[k])) : na != nb ? (na ? -1 : 1) : xa[k].compareTo(xb[k]);
            if (c != 0) return c;
        }
        return Integer.compare(xa.length, xb.length);
    }

    private static long num(String s) {
        if (s == null || s.isEmpty()) return 0;
        return s.length() > 18 ? Long.MAX_VALUE : Long.parseLong(s);
    }

    /**
     * The fix to upgrade to: the lowest of these versions above the one in use, of its flavour when there is one —
     * 32.0.0-jre for 31.1-jre, not 32.0.0-android, which Maven's order puts first —, else the lowest of any; empty
     * when none is above. A fix given in another flavour word only (an advisory naming 32.0.0-android for every Guava)
     * is said in the version's own: a library released in flavours releases each fix in all of them.
     */
    public static String nearestFix(Comparator<String> order, String version, Collection<String> fixes) {
        List<String> above = fixes.stream().filter(f -> f != null && order.compare(f, version) > 0).toList();
        String flavour = flavour(version);
        if (!isPreRelease(flavour)) {
            var same = above.stream().filter(f -> flavour(f).equals(flavour)).min(order);
            if (same.isPresent()) return same.get();
        }
        String lowest = above.stream().min(order).orElse("");
        if (isFlavourWord(flavour) && isFlavourWord(flavour(lowest)))
            return lowest.substring(0, lowest.length() - flavour(lowest).length()) + version.strip().substring(version.strip().length() - flavour.length());
        return lowest;
    }

    private static final Pattern WORD_AFTER_DASH = Pattern.compile("-([a-z]+)");

    /** A flavour that is a word after a dash: "-jre", "-android"; not a pre-release ("-rc", "-beta1") nor ".Final". */
    private static boolean isFlavourWord(String flavour) {
        var m = WORD_AFTER_DASH.matcher(flavour);
        return m.matches() && !QUALIFIERS.containsKey(m.group(1));
    }

    private static final Pattern WORD_AND_NUMBER_AFTER_DASH = Pattern.compile("-([a-z]+)[.-]?\\d*");

    /** A version's suffix that is one of Maven's pre-release qualifiers: "-beta", "-rc2", "-beta.1", "-snapshot". */
    private static boolean isPreRelease(String flavour) {
        var m = WORD_AND_NUMBER_AFTER_DASH.matcher(flavour);
        return m.matches() && QUALIFIERS.getOrDefault(m.group(1), 6) < 6;
    }

    /** What follows a version's numbers: "-jre", "-android", ".final", or nothing. */
    static String flavour(String version) {
        return version.strip().replaceFirst("^[0-9.]+", "").toLowerCase(Locale.ROOT);
    }
}
