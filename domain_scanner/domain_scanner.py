#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unregistered-domain scanner.

Enumerates every 2-letter and 3-letter label (a-z by default, optionally 0-9)
and checks whether the resulting domain is registered for the .sh, .ac and
.cool TLDs, writing the *available* (unregistered) ones to disk.

Detection method per TLD
------------------------
  .cool            RDAP over HTTPS (authoritative).
                   HTTP 200 -> registered, HTTP 404 -> available.
  .sh / .ac        WHOIS over port 43 (authoritative) when reachable.
                   Falls back automatically to DNS-over-HTTPS (heuristic:
                   NXDOMAIN / no NS record => treated as available) when the
                   WHOIS port is blocked by the network.

The WHOIS fallback matters because some sandboxed/cloud networks only allow
outbound HTTPS (443) and block port 43. DoH is a heuristic: a registered but
undelegated domain (no NS) would be reported as "available", so prefer WHOIS
when you can reach it (i.e. run on a normal machine / unrestricted network).

Usage examples
--------------
  # everything (2 + 3 letter, all three TLDs) -> ./results/
  python domain_scanner.py

  # only two-letter .cool domains, more workers
  python domain_scanner.py --tld cool --lengths 2 --workers 40

  # include digits in the alphabet (0-9 a-z)
  python domain_scanner.py --charset alnum

  # force a method for .sh/.ac
  python domain_scanner.py --tld sh --method doh

Results are streamed to results/available_<tld>.txt and a full log to
results/checked_<tld>.csv so an interrupted run can be resumed (already-checked
labels are skipped on restart).
"""

import argparse
import csv
import itertools
import json
import os
import socket
import string
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RDAP_ENDPOINTS = {
    "cool": "https://rdap.identitydigital.services/rdap/domain/{domain}",
}

WHOIS_SERVERS = {
    "sh": "whois.nic.sh",
    "ac": "whois.nic.ac",
}

# Substrings that indicate "this domain is NOT registered" in a WHOIS reply.
WHOIS_AVAILABLE_MARKERS = (
    "not registered",
    "no match",
    "no object found",
    "not found",
    "no entries found",
    "domain not found",
    "is available",
    "status: available",
    "status: free",
)
# Substrings that clearly mean "registered".
WHOIS_REGISTERED_MARKERS = (
    "domain name:",
    "registrant",
    "creation date",
    "registered on",
    "registrar:",
    "name server",
    "nserver",
)

DOH_URL = "https://dns.google/resolve?name={name}&type={rtype}"

USER_AGENT = "domain-scanner/1.0 (+https://github.com/Eyre921/Spider_XHS)"

# Thread-safe print / file writes
_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #
# status is one of: "available", "registered", "unknown"


class Result:
    __slots__ = ("domain", "status", "method", "detail")

    def __init__(self, domain, status, method, detail=""):
        self.domain = domain
        self.status = status
        self.method = method
        self.detail = detail


# --------------------------------------------------------------------------- #
# Checkers
# --------------------------------------------------------------------------- #

def _http_get(url, timeout, accept=None):
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, body
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return None, str(e)


def check_rdap(domain, tld, timeout=20, retries=4):
    """RDAP check. 200 -> registered, 404 -> available."""
    url = RDAP_ENDPOINTS[tld].format(domain=domain)
    backoff = 2.0
    for attempt in range(retries):
        code, body = _http_get(url, timeout, accept="application/rdap+json")
        if code == 200:
            return Result(domain, "registered", "rdap")
        if code == 404:
            return Result(domain, "available", "rdap")
        if code in (429, 503) or code is None:
            # rate limited / network hiccup -> back off and retry
            time.sleep(backoff)
            backoff *= 2
            continue
        # any other code: report unknown but keep the code for debugging
        return Result(domain, "unknown", "rdap", f"http {code}")
    return Result(domain, "unknown", "rdap", "retries exhausted")


def check_whois(domain, server, timeout=15):
    """Raw WHOIS over port 43. Returns Result or None if the port is unreachable."""
    try:
        infos = socket.getaddrinfo(server, 43, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 43))
        sock.sendall((domain + "\r\n").encode())
        chunks = []
        while True:
            b = sock.recv(4096)
            if not b:
                break
            chunks.append(b)
        sock.close()
        text = b"".join(chunks).decode("utf-8", "replace").lower()
    except (socket.timeout, OSError):
        return None  # port 43 blocked / unreachable -> caller should fall back

    if any(m in text for m in WHOIS_AVAILABLE_MARKERS):
        return Result(domain, "available", "whois")
    if any(m in text for m in WHOIS_REGISTERED_MARKERS):
        return Result(domain, "registered", "whois")
    return Result(domain, "unknown", "whois", "unrecognized whois reply")


def check_doh(domain, timeout=15, retries=3):
    """DNS-over-HTTPS heuristic. NXDOMAIN / no NS -> 'available' (heuristic)."""
    url = DOH_URL.format(name=domain, rtype="NS")
    backoff = 1.5
    for attempt in range(retries):
        code, body = _http_get(url, timeout, accept="application/dns-json")
        if code == 200:
            try:
                j = json.loads(body)
            except json.JSONDecodeError:
                return Result(domain, "unknown", "doh", "bad json")
            status = j.get("Status")
            answers = j.get("Answer", [])
            if status == 3:  # NXDOMAIN
                return Result(domain, "available", "doh", "nxdomain")
            if status == 0 and answers:
                return Result(domain, "registered", "doh", "has NS")
            if status == 0 and not answers:
                # delegated zone exists but no NS in answer: treat as registered
                return Result(domain, "registered", "doh", "noerror/no-ns")
            return Result(domain, "unknown", "doh", f"dns status {status}")
        time.sleep(backoff)
        backoff *= 2
    return Result(domain, "unknown", "doh", "retries exhausted")


def make_checker(tld, method, whois_timeout, http_timeout):
    """Return a function label -> Result for the given TLD."""
    if tld == "cool":
        return lambda label: check_rdap(f"{label}.cool", "cool", timeout=http_timeout)

    server = WHOIS_SERVERS[tld]

    # Decide effective method. "auto" tries whois first, then doh.
    if method == "doh":
        return lambda label: check_doh(f"{label}.{tld}", timeout=http_timeout)
    if method == "whois":
        def _whois_only(label):
            r = check_whois(f"{label}.{tld}", server, timeout=whois_timeout)
            return r or Result(f"{label}.{tld}", "unknown", "whois", "port 43 unreachable")
        return _whois_only

    # auto
    state = {"whois_ok": None}  # probe once; if blocked, stick to doh

    def _auto(label):
        domain = f"{label}.{tld}"
        if state["whois_ok"] is not False:
            r = check_whois(domain, server, timeout=whois_timeout)
            if r is not None:
                state["whois_ok"] = True
                return r
            state["whois_ok"] = False
        return check_doh(domain, timeout=http_timeout)

    return _auto


# --------------------------------------------------------------------------- #
# Label generation
# --------------------------------------------------------------------------- #

def gen_labels(lengths, charset):
    alpha = {
        "alpha": string.ascii_lowercase,
        "alnum": string.digits + string.ascii_lowercase,
        "digit": string.digits,
    }[charset]
    for n in lengths:
        for combo in itertools.product(alpha, repeat=n):
            yield "".join(combo)


# --------------------------------------------------------------------------- #
# Resume support
# --------------------------------------------------------------------------- #

def load_done(csv_path):
    done = set()
    if os.path.exists(csv_path):
        with open(csv_path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if row:
                    done.add(row[0])
    return done


# --------------------------------------------------------------------------- #
# Main scan loop for one TLD
# --------------------------------------------------------------------------- #

def scan_tld(tld, lengths, charset, workers, method, outdir,
             whois_timeout, http_timeout, throttle):
    os.makedirs(outdir, exist_ok=True)
    avail_path = os.path.join(outdir, f"available_{tld}.txt")
    csv_path = os.path.join(outdir, f"checked_{tld}.csv")

    done = load_done(csv_path)
    labels = [l for l in gen_labels(lengths, charset) if f"{l}.{tld}" not in done]
    total = len(labels)
    if done:
        log(f"[{tld}] resuming: {len(done)} already checked, {total} remaining")
    else:
        log(f"[{tld}] {total} labels to check")
    if total == 0:
        return

    checker = make_checker(tld, method, whois_timeout, http_timeout)

    avail_f = open(avail_path, "a", encoding="utf-8")
    csv_f = open(csv_path, "a", newline="", encoding="utf-8")
    csv_w = csv.writer(csv_f)
    write_lock = threading.Lock()

    counters = {"available": 0, "registered": 0, "unknown": 0}
    processed = 0
    start = time.time()

    def task(label):
        if throttle:
            time.sleep(throttle)
        return checker(label)

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(task, l): l for l in labels}
            for fut in as_completed(futures):
                r = fut.result()
                processed += 1
                with write_lock:
                    counters[r.status] = counters.get(r.status, 0) + 1
                    csv_w.writerow([r.domain, r.status, r.method, r.detail])
                    if r.status == "available":
                        avail_f.write(r.domain + "\n")
                        avail_f.flush()
                        log(f"  [AVAILABLE] {r.domain}  ({r.method})")
                    csv_f.flush()
                if processed % 200 == 0 or processed == total:
                    rate = processed / max(time.time() - start, 1e-6)
                    log(f"[{tld}] {processed}/{total} "
                        f"avail={counters['available']} reg={counters['registered']} "
                        f"unknown={counters['unknown']} ({rate:.1f}/s)")
    finally:
        avail_f.close()
        csv_f.close()

    log(f"[{tld}] DONE: {counters['available']} available, "
        f"{counters['registered']} registered, {counters['unknown']} unknown "
        f"-> {avail_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Scan 2- and 3-letter .sh/.ac/.cool domains for availability.")
    p.add_argument("--tld", choices=["sh", "ac", "cool", "all"], default="all",
                   help="which TLD(s) to scan (default: all)")
    p.add_argument("--lengths", default="2,3",
                   help="comma list of label lengths, e.g. '2,3' (default)")
    p.add_argument("--charset", choices=["alpha", "alnum", "digit"], default="alpha",
                   help="alpha=a-z (default), alnum=0-9a-z, digit=0-9")
    p.add_argument("--workers", type=int, default=20,
                   help="concurrent workers per TLD (default 20)")
    p.add_argument("--method", choices=["auto", "whois", "doh"], default="auto",
                   help="detection method for .sh/.ac (.cool always uses RDAP)")
    p.add_argument("--outdir", default="results",
                   help="output directory (default ./results)")
    p.add_argument("--whois-timeout", type=int, default=15)
    p.add_argument("--http-timeout", type=int, default=20)
    p.add_argument("--throttle", type=float, default=0.0,
                   help="seconds to sleep before each request (politeness)")
    args = p.parse_args(argv)

    try:
        lengths = [int(x) for x in args.lengths.split(",") if x.strip()]
    except ValueError:
        p.error("--lengths must be a comma-separated list of integers")
    if not lengths:
        p.error("--lengths is empty")

    tlds = ["sh", "ac", "cool"] if args.tld == "all" else [args.tld]

    log(f"Scanning {tlds} | lengths={lengths} | charset={args.charset} "
        f"| workers={args.workers} | method={args.method}")
    for tld in tlds:
        scan_tld(tld, lengths, args.charset, args.workers, args.method,
                 args.outdir, args.whois_timeout, args.http_timeout, args.throttle)


if __name__ == "__main__":
    main()
