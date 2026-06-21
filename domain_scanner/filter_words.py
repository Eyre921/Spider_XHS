#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-reference scan results against English dictionaries to surface the
*meaningful* available domains: real dictionary words and "domain hacks"
(where label + TLD spells a word, e.g. jo + sh = "josh").

Reads results/available_<tld>.txt produced by domain_scanner.py and the word
lists in dict/ (run dict/fetch_dict.sh first).

Examples
--------
  # real-word + domain-hack picks for every scanned TLD
  python filter_words.py

  # only .cool, only common words (in the top-10k frequency list)
  python filter_words.py --tld cool --common-only

  # show real words up to 4 letters, common ones first
  python filter_words.py --tld sh --max-len 4
"""

import argparse
import glob
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_words(path):
    out = set()
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip().lower()
            if w.isalpha():
                out.add(w)
    return out


def load_freq(path):
    """Return {word: rank} (rank 0 = most common). Empty if file missing."""
    ranks = {}
    if not os.path.exists(path):
        return ranks
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            w = line.strip().lower()
            if w.isalpha() and w not in ranks:
                ranks[w] = i
    return ranks


def load_available(results_dir, tld):
    path = os.path.join(results_dir, f"available_{tld}.txt")
    labels = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                d = line.strip()
                if d.endswith("." + tld):
                    labels.append(d[: -(len(tld) + 1)])
    return labels


def main(argv=None):
    p = argparse.ArgumentParser(description="Filter scan results by dictionary.")
    p.add_argument("--tld", default="all",
                   help="TLD to filter, or 'all' (default) for every results file")
    p.add_argument("--results", default=os.path.join(HERE, "results"))
    p.add_argument("--dict", default=os.path.join(HERE, "dict", "words_alpha.txt"))
    p.add_argument("--freq", default=os.path.join(HERE, "dict", "google-10000.txt"))
    p.add_argument("--max-len", type=int, default=3,
                   help="max label length to consider (default 3)")
    p.add_argument("--common-only", action="store_true",
                   help="only words present in the frequency (common) list")
    p.add_argument("--no-hacks", action="store_true",
                   help="skip the domain-hack section")
    p.add_argument("--limit", type=int, default=60,
                   help="max items to print per section (default 60)")
    args = p.parse_args(argv)

    words = load_words(args.dict)
    freq = load_freq(args.freq)
    if not words:
        p.error(f"dictionary not found: {args.dict}\n"
                f"run: bash {os.path.join(HERE, 'dict', 'fetch_dict.sh')}")

    if args.tld == "all":
        tlds = sorted(os.path.basename(f).split("_", 1)[1].rsplit(".", 1)[0]
                      for f in glob.glob(os.path.join(args.results, "available_*.txt")))
    else:
        tlds = [args.tld]
    if not tlds:
        p.error(f"no available_*.txt files in {args.results}")

    BIG = 10 ** 9
    for tld in tlds:
        labels = load_available(args.results, tld)
        labset = set(labels)
        if not labels:
            print(f"\n===== .{tld} =====  (no results file)")
            continue

        # Real-word matches: label itself is a dictionary word.
        real = [l for l in labels if 2 <= len(l) <= args.max_len and l in words]
        if args.common_only:
            real = [l for l in real if l in freq]
        # common first (by frequency rank), then shorter, then alpha
        real.sort(key=lambda w: (freq.get(w, BIG), len(w), w))

        # Domain hacks: label + tld together spell a dictionary word.
        hacks = []
        if not args.no_hacks:
            for l in labels:
                combo = l + tld
                if combo in words and (args.max_len == 0 or len(l) <= args.max_len):
                    if not args.common_only or combo in freq:
                        hacks.append((f"{l}.{tld}", combo))
            hacks.sort(key=lambda t: (freq.get(t[1], BIG), len(t[1]), t[1]))

        print(f"\n===== .{tld} =====  "
              f"({len(labset)} available, {len(real)} real words, {len(hacks)} hacks)")

        def mark(w):
            return "*" if w in freq else " "  # * = common (top-10k)

        print(f"  -- real words (max {args.max_len} letters, * = common) --")
        line = "  ".join(f"{mark(w)}{w}.{tld}" for w in real[:args.limit])
        print("   " + (line if line else "(none)"))
        if len(real) > args.limit:
            print(f"   ... +{len(real) - args.limit} more")

        if not args.no_hacks:
            print(f"  -- domain hacks (label+{tld} = word, * = common) --")
            line = "  ".join(f"{mark(w)}{d} (={w})" for d, w in hacks[:args.limit])
            print("   " + (line if line else "(none)"))
            if len(hacks) > args.limit:
                print(f"   ... +{len(hacks) - args.limit} more")


if __name__ == "__main__":
    main()
