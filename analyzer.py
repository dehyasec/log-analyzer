#!/usr/bin/env python3
"""Log analyzer (v0.2): detects SSH brute-force bursts in auth logs.
For educational use only."""
import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
STAMP = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP)
ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from " + IP)


def read_lines(path):
    """Yield lines from a file, or from stdin when path is '-'."""
    if path == "-":
        yield from sys.stdin
    else:
        with open(path, errors="replace") as f:
            yield from f


def parse(lines, year):
    """Return failed-attempt times per IP, usernames tried per IP, successful logins."""
    attempts = defaultdict(list)
    users = defaultdict(set)
    accepted = []
    for line in lines:
        stamp = STAMP.match(line)
        if not stamp:
            continue
        when = datetime.strptime(f"{year} {stamp['ts']}", "%Y %b %d %H:%M:%S")
        if m := FAILED.search(line):
            attempts[m["ip"]].append(when)
            users[m["ip"]].add(m["user"])
        elif m := ACCEPTED.search(line):
            accepted.append((m["user"], m["ip"]))
    return attempts, users, accepted


def burst(times, window):
    """Largest number of events inside any span of `window` seconds."""
    times = sorted(times)  # logs can be out of order
    best = left = 0
    for right, t in enumerate(times):
        while (t - times[left]).total_seconds() > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def main():
    ap = argparse.ArgumentParser(description="Detect SSH brute-force attempts in an auth log")
    ap.add_argument("logfile", help="path to an auth log, or - to read from stdin")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failures that trigger a flag (default 5)")
    ap.add_argument("-w", "--window", type=int, default=60,
                    help="burst window in seconds (default 60)")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year of the log; syslog lines carry none (default: this year)")
    args = ap.parse_args()

    try:
        attempts, users, accepted = parse(read_lines(args.logfile), args.year)
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.logfile}")

    if not attempts:
        raise SystemExit("No failed SSH logins found.")

    total = sum(len(v) for v in attempts.values())
    print(f"Failed logins: {total} from {len(attempts)} IP(s)  "
          f"(window {args.window}s, threshold {args.threshold})\n")

    rows = []
    for ip, times in attempts.items():
        b = burst(times, args.window)
        if b >= args.threshold:
            status = "BRUTE-FORCE"
        elif len(times) >= args.threshold:
            status = "WATCH"
        else:
            status = "ok"
        rows.append((ip, len(times), b, len(users[ip]), status))
    rows.sort(key=lambda r: (-r[2], -r[1]))

    print(f"{'IP':<18}{'FAILED':<9}{'BURST':<8}{'USERS':<8}STATUS")
    for ip, n, b, u, status in rows:
        print(f"{ip:<18}{n:<9}{b:<8}{u:<8}{status}")

    flagged = {r[0] for r in rows if r[4] == "BRUTE-FORCE"}
    for user, ip in accepted:
        if ip in flagged:
            print(f"\nWARNING: successful login for '{user}' from flagged IP {ip}")


if __name__ == "__main__":
    main()
