package org.jtools.cvescanner.cvss;

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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * CVSS scoring: v3.0 / v3.1 (base, temporal, environmental formulas from the FIRST specification) and v4.0
 * (macrovector lookup + severity-distance interpolation, ported from the FIRST/Red Hat reference calculator,
 * https://github.com/RedHatProductSecurity/cvss-v4-calculator, Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and
 * contributors, BSD-2-Clause; see NOTICE).
 */
public final class Cvss {
    private Cvss() {}

    static boolean isV4(String v) { return v != null && v.startsWith("CVSS:4.0/"); }

    static boolean isV3(String v) { return v != null && (v.startsWith("CVSS:3.1/") || v.startsWith("CVSS:3.0/")); }

    public static String version(String v) { return v.substring(5, 8); }

    /** Parses "CVSS:x.y/K:V/..." into an ordered map; null if malformed or a metric is repeated. */
    static Map<String, String> parse(String vector) {
        if (vector == null) return null;
        String[] parts = vector.strip().split("/");
        if (parts.length < 2 || !parts[0].startsWith("CVSS:")) return null;
        var m = new LinkedHashMap<String, String>();
        for (int i = 1; i < parts.length; i++) {
            int c = parts[i].indexOf(':');
            if (c <= 0 || m.put(parts[i].substring(0, c), parts[i].substring(c + 1)) != null) return null;
        }
        return m;
    }

    /** Base score only (threat/temporal and environmental metrics _); null if the vector is invalid. */
    public static Double baseScore(String vector) {
        var m = parse(vector);
        if (m == null) return null;
        if (isV4(vector)) {
            var base = new LinkedHashMap<String, String>();
            for (String k : V4_BASE) if (m.containsKey(k)) base.put(k, m.get(k));
            return v4Score(base);
        }
        return isV3(vector) ? v3Base(m, version(vector).equals("3.0")) : null;
    }

    /** Score of the full vector including environmental (and threat/temporal) metrics. */
    static Double environmentalScore(String vector) {
        var m = parse(vector);
        if (m == null) return null;
        if (isV4(vector)) return v4Score(m);
        return isV3(vector) ? v3Environmental(m, version(vector).equals("3.0")) : null;
    }

    private static final List<String> V3_ORDER = List.of("AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL", "RC",
            "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA");
    private static final List<String> AV_ORDER = List.of("N", "A", "L", "P");   // most to least exposed

    /** Returns the vector with the environment's security requirements and attack-vector cap applied. */
    static String applyEnvironment(String vector, Environment env) {
        var m = parse(vector);
        if (m == null) return null;
        for (String k : List.of("CR", "IR", "AR")) m.remove(k);
        if (env.confidentiality() != Requirement.NOT_DEFINED) m.put("CR", env.confidentiality().code);
        if (env.integrity() != Requirement.NOT_DEFINED) m.put("IR", env.integrity().code);
        if (env.availability() != Requirement.NOT_DEFINED) m.put("AR", env.availability().code);
        String cap = env.reach().attackVectorCap;
        if (cap != null) {
            String current = m.getOrDefault("MAV", "X").equals("X") ? m.get("AV") : m.get("MAV");
            if (current != null && AV_ORDER.indexOf(current) >= 0 && AV_ORDER.indexOf(current) < AV_ORDER.indexOf(cap)) m.put("MAV", cap);
        }
        var order = isV4(vector) ? new ArrayList<>(V4_VALUES.keySet()) : V3_ORDER;
        var sb = new StringBuilder(vector.substring(0, vector.indexOf('/')));
        for (String k : order) if (m.containsKey(k)) sb.append('/').append(k).append(':').append(m.remove(k));
        m.forEach((k, v) -> sb.append('/').append(k).append(':').append(v));
        return sb.toString();
    }

    // ------------------------------------------------------------------------------------------ v3.x
    private static final Map<String, Double> AV = Map.of("N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2),
            AC = Map.of("L", 0.77, "H", 0.44), UI = Map.of("N", 0.85, "R", 0.62),
            PR_UNCHANGED = Map.of("N", 0.85, "L", 0.62, "H", 0.27), PR_CHANGED = Map.of("N", 0.85, "L", 0.68, "H", 0.5),
            CIA = Map.of("H", 0.56, "L", 0.22, "N", 0.0), REQ = Map.of("X", 1.0, "L", 0.5, "M", 1.0, "H", 1.5),
            E = Map.of("X", 1.0, "U", 0.91, "P", 0.94, "F", 0.97, "H", 1.0),
            RL = Map.of("X", 1.0, "O", 0.95, "T", 0.96, "W", 0.97, "U", 1.0),
            RC = Map.of("X", 1.0, "U", 0.92, "R", 0.96, "C", 1.0);
    private static final Map<String, Map<String, Double>> V3_METRICS = Map.ofEntries(
            Map.entry("AV", AV), Map.entry("AC", AC), Map.entry("PR", PR_UNCHANGED), Map.entry("UI", UI),
            Map.entry("S", Map.of("U", 0.0, "C", 0.0)), Map.entry("C", CIA), Map.entry("I", CIA), Map.entry("A", CIA));

    /** CVSS "Roundup". The v3.1 definition is used for v3.0 too: it gives the same results without the floating-point
     *  artefacts of a plain ceil (e.g. 2.5 x 0.92 must round up to 2.3, not 2.4). */
    private static double roundUp(double x, boolean v30) {
        long i = Math.round(x * 100000);
        return i % 10000 == 0 ? i / 100000.0 : (Math.floorDiv(i, 10000) + 1) / 10.0;
    }

    private static boolean validV3(Map<String, String> m) {
        for (var e : V3_METRICS.entrySet()) {
            String v = m.get(e.getKey());
            if (v == null || !e.getValue().containsKey(v)) return false;
        }
        for (var e : Map.of("E", E, "RL", RL, "RC", RC, "CR", REQ, "IR", REQ, "AR", REQ).entrySet())
            if (m.containsKey(e.getKey()) && !e.getValue().containsKey(m.get(e.getKey()))) return false;
        for (String k : List.of("AV", "AC", "PR", "UI", "S", "C", "I", "A")) {
            String v = m.get("M" + k);
            if (v != null && !v.equals("X") && !V3_METRICS.get(k).containsKey(v)) return false;
        }
        return true;
    }

    static Double v3Base(Map<String, String> m, boolean v30) {
        if (!validV3(m)) return null;
        boolean changed = m.get("S").equals("C");
        double iss = 1 - (1 - CIA.get(m.get("C"))) * (1 - CIA.get(m.get("I"))) * (1 - CIA.get(m.get("A")));
        double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
        if (impact <= 0) return 0.0;
        double expl = 8.22 * AV.get(m.get("AV")) * AC.get(m.get("AC"))
                * (changed ? PR_CHANGED : PR_UNCHANGED).get(m.get("PR")) * UI.get(m.get("UI"));
        return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10), v30);
    }

    static Double v3Environmental(Map<String, String> m, boolean v30) {
        if (!validV3(m)) return null;
        Function<String, String> mod = k -> {
            String v = m.getOrDefault("M" + k, "X");
            return v.equals("X") ? m.get(k) : v;
        };
        boolean changed = mod.apply("S").equals("C");
        double miss = Math.min(1 - (1 - REQ.get(m.getOrDefault("CR", "X")) * CIA.get(mod.apply("C")))
                                 * (1 - REQ.get(m.getOrDefault("IR", "X")) * CIA.get(mod.apply("I")))
                                 * (1 - REQ.get(m.getOrDefault("AR", "X")) * CIA.get(mod.apply("A"))), 0.915);
        double impact = !changed ? 6.42 * miss
                : v30 ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss - 0.02, 15)
                : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
        if (impact <= 0) return 0.0;
        double expl = 8.22 * AV.get(mod.apply("AV")) * AC.get(mod.apply("AC"))
                * (changed ? PR_CHANGED : PR_UNCHANGED).get(mod.apply("PR")) * UI.get(mod.apply("UI"));
        double temporal = E.get(m.getOrDefault("E", "X")) * RL.get(m.getOrDefault("RL", "X")) * RC.get(m.getOrDefault("RC", "X"));
        return roundUp(roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10), v30) * temporal, v30);
    }

    // ------------------------------------------------------------------------------------------ v4.0
    private static final List<String> V4_BASE = List.of("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA");
    /** Allowed values per metric (first = default), in specification order. */
    private static final Map<String, List<String>> V4_VALUES = new LinkedHashMap<>();
    static {
        String spec = "AV:N,A,L,P AC:L,H AT:N,P PR:N,L,H UI:N,P,A VC:N,L,H VI:N,L,H VA:N,L,H SC:N,L,H SI:N,L,H SA:N,L,H "
                + "E:X,A,P,U CR:X,H,M,L IR:X,H,M,L AR:X,H,M,L MAV:X,N,A,L,P MAC:X,L,H MAT:X,N,P MPR:X,N,L,H MUI:X,N,P,A "
                + "MVC:X,H,L,N MVI:X,H,L,N MVA:X,H,L,N MSC:X,H,L,N MSI:X,S,H,L,N MSA:X,S,H,L,N "
                + "S:X,N,P AU:X,N,Y R:X,A,U,I V:X,D,C RE:X,L,M,H U:X,Clear,Green,Amber,Red";
        for (String def : spec.split(" ")) {
            int c = def.indexOf(':');
            V4_VALUES.put(def.substring(0, c), List.of(def.substring(c + 1).split(",")));
        }
    }
    private static final Map<String, Double> LOOKUP = new HashMap<>();
    static {
        String table = ""
            + "000000=10,000001=9.9,000010=9.8,000011=9.5,000020=9.5,000021=9.2,000100=10,000101=9.6,000110=9.3,"
            + "000111=8.7,000120=9.1,000121=8.1,000200=9.3,000201=9,000210=8.9,000211=8,000220=8.1,000221=6.8,"
            + "001000=9.8,001001=9.5,001010=9.5,001011=9.2,001020=9,001021=8.4,001100=9.3,001101=9.2,001110=8.9,"
            + "001111=8.1,001120=8.1,001121=6.5,001200=8.8,001201=8,001210=7.8,001211=7,001220=6.9,001221=4.8,"
            + "002001=9.2,002011=8.2,002021=7.2,002101=7.9,002111=6.9,002121=5,002201=6.9,002211=5.5,002221=2.7,"
            + "010000=9.9,010001=9.7,010010=9.5,010011=9.2,010020=9.2,010021=8.5,010100=9.5,010101=9.1,010110=9,"
            + "010111=8.3,010120=8.4,010121=7.1,010200=9.2,010201=8.1,010210=8.2,010211=7.1,010220=7.2,010221=5.3,"
            + "011000=9.5,011001=9.3,011010=9.2,011011=8.5,011020=8.5,011021=7.3,011100=9.2,011101=8.2,011110=8,"
            + "011111=7.2,011120=7,011121=5.9,011200=8.4,011201=7,011210=7.1,011211=5.2,011220=5,011221=3,"
            + "012001=8.6,012011=7.5,012021=5.2,012101=7.1,012111=5.2,012121=2.9,012201=6.3,012211=2.9,012221=1.7,"
            + "100000=9.8,100001=9.5,100010=9.4,100011=8.7,100020=9.1,100021=8.1,100100=9.4,100101=8.9,100110=8.6,"
            + "100111=7.4,100120=7.7,100121=6.4,100200=8.7,100201=7.5,100210=7.4,100211=6.3,100220=6.3,100221=4.9,"
            + "101000=9.4,101001=8.9,101010=8.8,101011=7.7,101020=7.6,101021=6.7,101100=8.6,101101=7.6,101110=7.4,"
            + "101111=5.8,101120=5.9,101121=5,101200=7.2,101201=5.7,101210=5.7,101211=5.2,101220=5.2,101221=2.5,"
            + "102001=8.3,102011=7,102021=5.4,102101=6.5,102111=5.8,102121=2.6,102201=5.3,102211=2.1,102221=1.3,"
            + "110000=9.5,110001=9,110010=8.8,110011=7.6,110020=7.6,110021=7,110100=9,110101=7.7,110110=7.5,"
            + "110111=6.2,110120=6.1,110121=5.3,110200=7.7,110201=6.6,110210=6.8,110211=5.9,110220=5.2,110221=3,"
            + "111000=8.9,111001=7.8,111010=7.6,111011=6.7,111020=6.2,111021=5.8,111100=7.4,111101=5.9,111110=5.7,"
            + "111111=5.7,111120=4.7,111121=2.3,111200=6.1,111201=5.2,111210=5.7,111211=2.9,111220=2.4,111221=1.6,"
            + "112001=7.1,112011=5.9,112021=3,112101=5.8,112111=2.6,112121=1.5,112201=2.3,112211=1.3,112221=0.6,"
            + "200000=9.3,200001=8.7,200010=8.6,200011=7.2,200020=7.5,200021=5.8,200100=8.6,200101=7.4,200110=7.4,"
            + "200111=6.1,200120=5.6,200121=3.4,200200=7,200201=5.4,200210=5.2,200211=4,200220=4,200221=2.2,"
            + "201000=8.5,201001=7.5,201010=7.4,201011=5.5,201020=6.2,201021=5.1,201100=7.2,201101=5.7,201110=5.5,"
            + "201111=4.1,201120=4.6,201121=1.9,201200=5.3,201201=3.6,201210=3.4,201211=1.9,201220=1.9,201221=0.8,"
            + "202001=6.4,202011=5.1,202021=2,202101=4.7,202111=2.1,202121=1.1,202201=2.4,202211=0.9,202221=0.4,"
            + "210000=8.8,210001=7.5,210010=7.3,210011=5.3,210020=6,210021=5,210100=7.3,210101=5.5,210110=5.9,"
            + "210111=4,210120=4.1,210121=2,210200=5.4,210201=4.3,210210=4.5,210211=2.2,210220=2,210221=1.1,"
            + "211000=7.5,211001=5.5,211010=5.8,211011=4.5,211020=4,211021=2.1,211100=6.1,211101=5.1,211110=4.8,"
            + "211111=1.8,211120=2,211121=0.9,211200=4.6,211201=1.8,211210=1.7,211211=0.7,211220=0.8,211221=0.2,"
            + "212001=5.3,212011=2.4,212021=1.4,212101=2.4,212111=1.2,212121=0.5,212201=1,212211=0.3,212221=0.1";
        for (String e : table.split(",")) {
            int eq = e.indexOf('=');
            LOOKUP.put(e.substring(0, eq), Double.parseDouble(e.substring(eq + 1)));
        }
    }
    private static final Map<String, Map<String, Double>> LEVELS = new LinkedHashMap<>();
    static {
        String spec = "AV:N=0.0,A=0.1,L=0.2,P=0.3 PR:N=0.0,L=0.1,H=0.2 UI:N=0.0,P=0.1,A=0.2 AC:L=0.0,H=0.1 AT:N=0.0,P=0.1 "
                + "VC:H=0.0,L=0.1,N=0.2 VI:H=0.0,L=0.1,N=0.2 VA:H=0.0,L=0.1,N=0.2 SC:H=0.1,L=0.2,N=0.3 "
                + "SI:S=0.0,H=0.1,L=0.2,N=0.3 SA:S=0.0,H=0.1,L=0.2,N=0.3 CR:H=0.0,M=0.1,L=0.2 IR:H=0.0,M=0.1,L=0.2 "
                + "AR:H=0.0,M=0.1,L=0.2 E:U=0.2,P=0.1,A=0.0";
        for (String def : spec.split(" ")) {
            int c = def.indexOf(':');
            var values = new HashMap<String, Double>();
            for (String kv : def.substring(c + 1).split(",")) values.put(kv.split("=")[0], Double.parseDouble(kv.split("=")[1]));
            LEVELS.put(def.substring(0, c), values);
        }
    }
    private static final Map<Integer, List<String>> MAX_EQ1 = Map.of(0, List.of("AV:N/PR:N/UI:N/"),
            1, List.of("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"), 2, List.of("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"));
    private static final Map<Integer, List<String>> MAX_EQ2 = Map.of(0, List.of("AC:L/AT:N/"), 1, List.of("AC:H/AT:N/", "AC:L/AT:P/"));
    private static final Map<String, List<String>> MAX_EQ3EQ6 = Map.of(
            "00", List.of("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"),
            "01", List.of("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"),
            "10", List.of("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"),
            "11", List.of("VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                    "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"),
            "21", List.of("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"));
    private static final Map<Integer, List<String>> MAX_EQ4 = Map.of(0, List.of("SC:H/SI:S/SA:S/"), 1, List.of("SC:H/SI:H/SA:H/"),
            2, List.of("SC:L/SI:L/SA:L/"));
    private static final Map<Integer, List<String>> MAX_EQ5 = Map.of(0, List.of("E:A/"), 1, List.of("E:P/"), 2, List.of("E:U/"));
    private static final Map<Integer, Integer> SEV_EQ1 = Map.of(0, 1, 1, 4, 2, 5), SEV_EQ2 = Map.of(0, 1, 1, 2),
            SEV_EQ4 = Map.of(0, 6, 1, 5, 2, 4);
    private static final Map<String, Integer> SEV_EQ3EQ6 = Map.of("00", 7, "01", 6, "10", 8, "11", 8, "21", 10);

    /** Validates and completes a v4.0 metric map with defaults; null if invalid. */
    private static Map<String, String> v4Metrics(Map<String, String> given) {
        for (String k : V4_BASE) if (!given.containsKey(k)) return null;
        var m = new HashMap<String, String>();
        for (var e : V4_VALUES.entrySet()) m.put(e.getKey(), e.getValue().getFirst());
        for (var e : given.entrySet()) {
            var allowed = V4_VALUES.get(e.getKey());
            if (allowed == null || !allowed.contains(e.getValue())) return null;
            m.put(e.getKey(), e.getValue());
        }
        return m;
    }

    private static String effective(Map<String, String> m, String metric) {
        if ("X".equals(m.get(metric))) {
            switch (metric) {
                case "E": return "A";
                case "CR", "IR", "AR": return "H";
                default: break;
            }
        }
        String modified = m.get("M" + metric);
        if (modified != null && !modified.equals("X")) return modified;
        return m.get(metric);
    }

    private static String macroVector(Map<String, String> m) {
        String av = effective(m, "AV"), pr = effective(m, "PR"), ui = effective(m, "UI");
        String eq1 = av.equals("N") && pr.equals("N") && ui.equals("N") ? "0"
                : (av.equals("N") || pr.equals("N") || ui.equals("N")) && !av.equals("P") ? "1" : "2";
        String eq2 = effective(m, "AC").equals("L") && effective(m, "AT").equals("N") ? "0" : "1";
        String vc = effective(m, "VC"), vi = effective(m, "VI"), va = effective(m, "VA");
        String eq3 = vc.equals("H") && vi.equals("H") ? "0" : vc.equals("H") || vi.equals("H") || va.equals("H") ? "1" : "2";
        String eq4 = effective(m, "MSI").equals("S") || effective(m, "MSA").equals("S") ? "0"
                : effective(m, "SC").equals("H") || effective(m, "SI").equals("H") || effective(m, "SA").equals("H") ? "1" : "2";
        String e = effective(m, "E");
        String eq5 = e.equals("A") ? "0" : e.equals("P") ? "1" : "2";
        String eq6 = (effective(m, "CR").equals("H") && vc.equals("H")) || (effective(m, "IR").equals("H") && vi.equals("H"))
                || (effective(m, "AR").equals("H") && va.equals("H")) ? "0" : "1";
        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }

    private static Map<String, String> parseMax(String s) {
        var m = new HashMap<String, String>();
        for (String p : s.split("/")) if (!p.isEmpty()) m.put(p.substring(0, p.indexOf(':')), p.substring(p.indexOf(':') + 1));
        return m;
    }

    static Double v4Score(Map<String, String> given) {
        var m = v4Metrics(given);
        if (m == null) return null;
        if (Stream.of("VC", "VI", "VA", "SC", "SI", "SA").allMatch(k -> effective(m, k).equals("N"))) return 0.0;
        String macro = macroVector(m);
        Double value = LOOKUP.get(macro);
        if (value == null) return null;
        int eq1 = macro.charAt(0) - '0', eq2 = macro.charAt(1) - '0', eq3 = macro.charAt(2) - '0',
                eq4 = macro.charAt(3) - '0', eq5 = macro.charAt(4) - '0', eq6 = macro.charAt(5) - '0';

        Double next1 = LOOKUP.get("" + (eq1 + 1) + eq2 + eq3 + eq4 + eq5 + eq6);
        Double next2 = LOOKUP.get("" + eq1 + (eq2 + 1) + eq3 + eq4 + eq5 + eq6);
        Double next36;
        if (eq3 == 0 && eq6 == 0) {
            Double left = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + eq5 + (eq6 + 1));
            Double right = LOOKUP.get("" + eq1 + eq2 + (eq3 + 1) + eq4 + eq5 + eq6);
            next36 = left == null || right == null ? null : Math.max(left, right);   // JS: Math.max(undefined, x) is NaN
        } else if (eq3 == 1 && eq6 == 0) {
            next36 = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + eq5 + (eq6 + 1));
        } else if ((eq3 == 1 && eq6 == 1) || (eq3 == 0 && eq6 == 1)) {
            next36 = LOOKUP.get("" + eq1 + eq2 + (eq3 + 1) + eq4 + eq5 + eq6);
        } else {
            next36 = LOOKUP.get("" + eq1 + eq2 + (eq3 + 1) + eq4 + eq5 + (eq6 + 1));
        }
        Double next4 = LOOKUP.get("" + eq1 + eq2 + eq3 + (eq4 + 1) + eq5 + eq6);
        Double next5 = LOOKUP.get("" + eq1 + eq2 + eq3 + eq4 + (eq5 + 1) + eq6);

        Map<String, Double> distances = null;
        outer:
        for (String a : MAX_EQ1.get(eq1))
            for (String b : MAX_EQ2.get(eq2))
                for (String c : MAX_EQ3EQ6.get("" + eq3 + eq6))
                    for (String d : MAX_EQ4.get(eq4))
                        for (String e : MAX_EQ5.get(eq5)) {
                            var max = parseMax(a + b + c + d + e);
                            distances = new HashMap<>();
                            boolean allNonNegative = true;
                            for (var lv : LEVELS.entrySet()) {
                                Double mine = lv.getValue().get(effective(m, lv.getKey()));
                                Double top = lv.getValue().get(max.get(lv.getKey()));
                                double dist = mine == null || top == null ? Double.NaN : mine - top;
                                distances.put(lv.getKey(), dist);
                                if (!(dist >= 0)) allNonNegative = false;
                            }
                            if (allNonNegative) break outer;
                        }

        double d = 0.1;
        double cur1 = distances.get("AV") + distances.get("PR") + distances.get("UI");
        double cur2 = distances.get("AC") + distances.get("AT");
        double cur36 = distances.get("VC") + distances.get("VI") + distances.get("VA") + distances.get("CR") + distances.get("IR") + distances.get("AR");
        double cur4 = distances.get("SC") + distances.get("SI") + distances.get("SA");

        int n = 0;
        double n1 = 0, n2 = 0, n36 = 0, n4 = 0, n5 = 0;
        if (next1 != null) { n++; n1 = (value - next1) * (cur1 / (SEV_EQ1.get(eq1) * d)); }
        if (next2 != null) { n++; n2 = (value - next2) * (cur2 / (SEV_EQ2.get(eq2) * d)); }
        if (next36 != null) { n++; n36 = (value - next36) * (cur36 / (SEV_EQ3EQ6.get("" + eq3 + eq6) * d)); }
        if (next4 != null) { n++; n4 = (value - next4) * (cur4 / (SEV_EQ4.get(eq4) * d)); }
        if (next5 != null) { n++; n5 = (value - next5) * 0; }
        double mean = n == 0 ? 0 : (n1 + n2 + n36 + n4 + n5) / n;
        double score = Math.max(0, Math.min(10, value - mean));
        return Math.round((score + 1e-6) * 10) / 10.0;
    }
}
