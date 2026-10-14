#!/usr/bin/env python3
"""Log analyzer (v0.1): flags SSH brute-force attempts in auth logs.
For educational use only."""
import argparse
import re
from collections import Counter

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP)
ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from " + IP)


def parse(path):
    """Return failed-login counts per IP, users tried per IP, and successful logins."""
    failed = Counter()
    users = {}
    accepted = []
    with open(path, errors="replace") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                failed[m["ip"]] += 1
                users.setdefault(m["ip"], set()).add(m["user"])
                continue
            m = ACCEPTED.search(line)
            if m:
                accepted.append((m["user"], m["ip"]))
    return failed, users, accepted


def main():
    ap = argparse.ArgumentParser(description="Flag SSH brute-force attempts in an auth log")
    ap.add_argument("logfile", help="path to the auth log")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failed attempts before an IP is flagged (default 5)")
    args = ap.parse_args()

    try:
        failed, users, accepted = parse(args.logfile)
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.logfile}")

    print(f"Failed logins: {sum(failed.values())} from {len(failed)} IP(s)\n")
    print(f"{'IP':<18}{'FAILED':<10}{'USERS TRIED':<13}STATUS")
    for ip, n in failed.most_common():
        status = "SUSPICIOUS" if n >= args.threshold else "ok"
        print(f"{ip:<18}{n:<10}{len(users[ip]):<13}{status}")

    flagged = {ip for ip, n in failed.items() if n >= args.threshold}
    for user, ip in accepted:
        if ip in flagged:
            print(f"\nWARNING: successful login for '{user}' from flagged IP {ip}")


if __name__ == "__main__":
    main()
