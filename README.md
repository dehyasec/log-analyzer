# log-analyzer

A Python tool that detects SSH brute-force attempts in Linux auth logs, built as a blue-team learning project.

> **Ethical use only.** Analyze logs from systems you own or are authorized to review.

## Features
- Parses failed and successful SSH logins with regular expressions
- Sliding-window burst detection: how many failures happened within N seconds
- Separates fast **BRUTE-FORCE** bursts from slow **WATCH** attackers
- Warns when a flagged IP also logged in successfully
- Reads a file or stdin, so it works with `journalctl` output
- Standard library only, no installs

## Usage
```bash
python3 analyzer.py <logfile | -> [options]
```

| Option | Description | Default |
|---|---|---|
| `-t`, `--threshold` | Failures that trigger a flag | 5 |
| `-w`, `--window` | Burst window in seconds | 60 |
| `--year` | Year of the log (syslog lines have none) | current year |

### Examples
```bash
python3 analyzer.py sample_auth.log
journalctl -u ssh --no-pager | python3 analyzer.py - -t 3 -w 120
```

### Example output
```
Failed logins: 15 from 3 IP(s)  (window 60s, threshold 5)

IP                FAILED   BURST   USERS   STATUS
203.0.113.45      7        7       5       BRUTE-FORCE
198.51.100.7      3        3       2       ok
192.0.2.99        5        1       3       WATCH

WARNING: successful login for 'admin' from flagged IP 203.0.113.45
```

## How it works
1. Regexes extract the username and source IP from `Failed password` and `Accepted` lines.
2. Failure timestamps are grouped per IP.
3. A sliding window finds the largest number of failures inside any `--window` seconds.
4. IPs at or above `--threshold` are flagged; a successful login from a flagged IP raises a warning.

## Sample data
`sample_auth.log` is fake data using reserved documentation IP ranges (RFC 5737). It is safe to share.

## Limitations
- Only OpenSSH password failures are parsed
- Classic syslog timestamps only (no year, so `--year` is assumed)

## Roadmap
- [ ] Detect invalid-user scans and key-based attacks
- [ ] JSON / CSV export
- [ ] IP geolocation and allow-lists

## License
MIT. See [LICENSE](LICENSE).
