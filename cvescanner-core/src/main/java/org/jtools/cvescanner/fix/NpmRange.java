package org.jtools.cvescanner.fix;

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
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jtools.cvescanner.version.Versions;

/**
 * Whether a version is within an npm range, as npm reads one: "^1.2.5", "~1.2", "1.x", "*", ">=1.0.0 <2", "1.2 - 1.4",
 * "a || b". A prerelease (1.2.4-beta) is within a range only when one of its comparators names a prerelease of the same
 * version (^1.2.4-alpha), as npm has it. A range written some other way (a tag, a URL, a path) says nothing: empty.
 */
final class NpmRange {

    private static final Pattern VERSION = Pattern.compile("v?(\\d+|[xX*])(?:\\.(\\d+|[xX*]))?(?:\\.(\\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?");
    private static final Pattern COMPARATOR = Pattern.compile("(\\^|~>?|>=|<=|>|<|=)?(\\S+)");

    private NpmRange() {}

    /** Whether the version satisfies the range; empty when either cannot be read. */
    static Optional<Boolean> satisfies(String version, String range) {
        Exact v = exact(version);
        if (v == null || range == null) return Optional.empty();
        String r = range.strip();
        int alias = r.startsWith("npm:") ? r.lastIndexOf('@') : -1;   // npm:name@^1.2: the range after the name
        if (alias > 0) r = r.substring(alias + 1);
        if (r.isEmpty() || r.equals("latest")) return r.isEmpty() ? Optional.of(v.pre() == null) : Optional.empty();
        for (String set : r.split("\\|\\|")) {
            Optional<Boolean> one = satisfiesSet(v, set.strip());
            if (one.isEmpty()) return Optional.empty();
            if (one.get()) return Optional.of(true);
        }
        return Optional.of(false);
    }

    /** A space-separated set of comparators, each to hold; a hyphen range "a - b". */
    private static Optional<Boolean> satisfiesSet(Exact v, String set) {
        if (set.isEmpty() || set.equals("*")) return Optional.of(v.pre() == null);
        var hyphen = Pattern.compile("(\\S+)\\s+-\\s+(\\S+)").matcher(set);
        if (hyphen.matches()) {
            Bound low = bound(hyphen.group(1)), high = bound(hyphen.group(2));
            if (low == null || high == null) return Optional.empty();
            return Optional.of(compare(v, low) >= 0 && (high.wild() == 0 ? compare(v, high) <= 0 : below(v, high.next()))
                    && prereleaseAllowed(v, List.of(low, high)));
        }
        // each word a comparator, its operator joined to its version (">= 1.0.0" is ">=1.0.0")
        var bounds = new ArrayList<Bound>();
        for (String word : set.replaceAll("(>=|<=|>|<|=|\\^|~>?)\\s+", "$1").split("\\s+")) {
            Matcher m = COMPARATOR.matcher(word);
            if (!m.matches()) return Optional.empty();
            Bound b = bound(m.group(2));
            if (b == null) return Optional.empty();
            if (!comparator(v, m.group(1) == null ? "" : m.group(1), b)) return Optional.of(false);
            bounds.add(b);
        }
        return Optional.of(prereleaseAllowed(v, bounds));
    }

    /**
     * Whether v holds this comparator. A ceiling npm writes X.Y.Z-0 (^, ~, x, "<1.2"): below it is below X.Y.Z's
     * numbers, X.Y.Z's own prereleases (2.0.0-rc.1 for ^1.0.0) left out too.
     */
    private static boolean comparator(Exact v, String op, Bound b) {
        int low = compare(v, b);
        return switch (op) {
            case "^" -> low >= 0 && below(v, caretCeiling(b));
            case "~", "~>" -> low >= 0 && below(v, b.wild() > 0 ? b.next() : new int[]{b.min()[0], b.min()[1] + 1, 0});
            case ">=" -> low >= 0;
            case ">" -> b.wild() > 0 ? compare(v, new Bound(b.next(), 0, null)) >= 0 : low > 0;
            case "<=" -> b.wild() > 0 ? below(v, b.next()) : low <= 0;
            case "<" -> b.wild() > 0 ? below(v, b.min()) : low < 0;
            default -> b.wild() > 0 ? low >= 0 && below(v, b.next()) : low == 0;   // "1.2.x", "1.2.3", "=1.2.3"
        };
    }

    /** A release is always considered; a prerelease only when a bound names one of the same numbers. */
    private static boolean prereleaseAllowed(Exact v, List<Bound> bounds) {
        return v.pre() == null || bounds.stream().anyMatch(b -> b.pre() != null && Arrays.equals(b.min(), v.numbers()));
    }

    /** ^1.2.3 below 2.0.0, ^0.2.3 below 0.3.0, ^0.0.3 below 0.0.4; with x, the part written decides. */
    private static int[] caretCeiling(Bound b) {
        int[] m = b.min();
        if (m[0] > 0 || b.wild() == 2) return new int[]{m[0] + 1, 0, 0};
        if (m[1] > 0 || b.wild() == 1) return new int[]{0, m[1] + 1, 0};
        return new int[]{0, 0, m[2] + 1};
    }

    /** An exact version: its numbers, its prerelease (null for a release); a build suffix is not read. */
    private record Exact(int[] numbers, String pre) {}

    /**
     * A version as a range bound: its lowest version, how many of its last parts are x or missing (2 for "1", 1 for
     * "1.2"), its prerelease when it is exact, and the version just above what it covers.
     */
    private record Bound(int[] min, int wild, String pre) {
        int[] next() {
            return wild == 3 ? new int[]{Integer.MAX_VALUE, 0, 0}
                    : wild == 2 ? new int[]{min[0] + 1, 0, 0} : wild == 1 ? new int[]{min[0], min[1] + 1, 0} : min;
        }
    }

    private static Bound bound(String text) {
        Matcher m = VERSION.matcher(text);
        if (!m.matches()) return null;
        int[] parts = new int[3];
        int wild = 0;
        for (int i = 0; i < 3; i++) {
            String p = m.group(i + 1);
            if (p == null || p.equalsIgnoreCase("x") || p.equals("*")) {
                wild = 3 - i;
                break;
            }
            parts[i] = Integer.parseInt(p);
        }
        return new Bound(parts, wild, wild == 0 ? m.group(4) : null);
    }

    private static Exact exact(String version) {
        if (version == null) return null;
        Matcher m = VERSION.matcher(version.strip());
        if (!m.matches() || m.group(3) == null || m.group(1).matches("[xX*]") || m.group(2).matches("[xX*]") || m.group(3).matches("[xX*]"))
            return null;
        return new Exact(new int[]{Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))}, m.group(4));
    }

    /** Semver's order: the numbers, then a prerelease below its release, prereleases by their dot-separated parts. */
    private static int compare(Exact v, Bound b) {
        int c = compareNumbers(v.numbers(), b.min());
        if (c != 0 || (v.pre() == null && b.pre() == null)) return c;
        if (v.pre() == null || b.pre() == null) return v.pre() == null ? 1 : -1;
        return Versions.compareSemver("0.0.0-" + v.pre(), "0.0.0-" + b.pre());
    }

    private static boolean below(Exact v, int[] ceiling) {
        return compareNumbers(v.numbers(), ceiling) < 0;
    }

    private static int compareNumbers(int[] a, int[] b) {
        for (int i = 0; i < 3; i++) if (a[i] != b[i]) return Integer.compare(a[i], b[i]);
        return 0;
    }
}
