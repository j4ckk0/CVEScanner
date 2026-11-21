#!/usr/bin/env python3
"""Writes the CVSS scores CvssReferenceTest expects, computed by another implementation than the program's: the
Python library cvss of Red Hat's product security (https://github.com/RedHatProductSecurity/cvss, LGPLv3+), which is
neither shipped nor linked: only the numbers it gives are kept.

    scripts/cvss-reference.py [--lib DIR] OUT

--lib: a folder holding the library (its wheel unpacked) when it is not installed. OUT: a tab-separated file, one
vector a line, its base score and its environmental score (temporal or threat metrics included). The vectors are
random, the seed fixed: the same file at each run. 3,000 CVSS 3.0 / 3.1 vectors, 6,000 CVSS 4.0 ones.
"""
import random
import sys

V3_BASE = [("AV", "NALP"), ("AC", "LH"), ("PR", "NLH"), ("UI", "NR"), ("S", "UC"), ("C", "HLN"), ("I", "HLN"), ("A", "HLN")]
V3_MORE = [("E", "XUPFH"), ("RL", "XOTWU"), ("RC", "XURC"), ("CR", "XLMH"), ("IR", "XLMH"), ("AR", "XLMH"),
           ("MAV", "XNALP"), ("MAC", "XLH"), ("MPR", "XNLH"), ("MUI", "XNR"), ("MS", "XUC"), ("MC", "XNLH"),
           ("MI", "XNLH"), ("MA", "XNLH")]
V4_BASE = [("AV", "NALP"), ("AC", "LH"), ("AT", "NP"), ("PR", "NLH"), ("UI", "NPA"), ("VC", "HLN"), ("VI", "HLN"),
           ("VA", "HLN"), ("SC", "HLN"), ("SI", "HLN"), ("SA", "HLN")]
V4_MORE = [("E", "XAPU"), ("CR", "XHML"), ("IR", "XHML"), ("AR", "XHML"), ("MAV", "XNALP"), ("MAC", "XLH"),
           ("MAT", "XNP"), ("MPR", "XNLH"), ("MUI", "XNPA"), ("MVC", "XHLN"), ("MVI", "XHLN"), ("MVA", "XHLN"),
           ("MSC", "XHLN"), ("MSI", "XSHLN"), ("MSA", "XSHLN")]


def vector(rng, prefix, base, more):
    parts = [f"{m}:{rng.choice(values)}" for m, values in base]
    # each other metric present one time in two, with any of its values (X, not defined, among them)
    parts += [f"{m}:{rng.choice(values)}" for m, values in more if rng.random() < 0.5]
    return prefix + "/".join(parts)


def main():
    args = sys.argv[1:]
    if args[:1] == ["--lib"]:
        sys.path.insert(0, args[1])
        args = args[2:]
    if len(args) != 1:
        sys.exit(__doc__)
    from cvss import CVSS3, CVSS4

    rng = random.Random(20261121)
    lines = ["# vector\tbase\tenvironmental — written by scripts/cvss-reference.py (Python cvss library)"]
    for i in range(3000):
        v = vector(rng, "CVSS:3.1/" if i % 2 else "CVSS:3.0/", V3_BASE, V3_MORE)
        base, _, environmental = CVSS3(v).scores()
        lines.append(f"{v}\t{base}\t{environmental}")
    for _ in range(6000):
        v = vector(rng, "CVSS:4.0/", V4_BASE, V4_MORE)
        base_only = "/".join(v.split("/")[:12])   # CVSS:4.0 and the 11 base metrics
        lines.append(f"{v}\t{CVSS4(base_only).base_score}\t{CVSS4(v).base_score}")
    with open(args[0], "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
