# Python Log Analyzer

A log analysis tool that detects four common SOC attack patterns in authentication
and web server logs, without relying on a SIEM. Built to understand detection logic
at the code level — not just configure rules in a GUI.

## Problem

SOC analysts spend a lot of time triaging raw logs for known attack patterns. This
project implements that triage logic from scratch in Python: parsing real log formats,
grouping events by the right key, and applying time-window and content-based detection
rules — the same logic I wrote as SPL rules in my [SIEM Home Lab](https://github.com/Kotechx/cybersecurity-portfolio/tree/main/siem-home-lab), now as code.

## What It Detects

| # | Detection | Logic | MITRE ATT&CK |
|---|-----------|-------|---------------|
| 1 | SSH brute force | ≥ 5 failed logins, same user+IP, within 10 minutes (sliding window) | T1110.001 |
| 2 | Port/path scan | ≥ 10 HTTP 404s from the same IP, within 5 minutes (sliding window) | T1595.002 |
| 3 | Path traversal | Request path contains `../` or its encoded form `%2f`/`%2F` | T1083 |
| 4 | Impossible travel | Same user logs in from two IPs in different countries within 60 minutes | T1078 |

## How to Run

```bash
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt

python generate_logs.py     # creates sample_logs/ with synthetic attacks + ground truth
python analyzer.py          # runs all 4 detections, writes alerts.json
pytest                      # runs the unit tests
```

`analyzer.py` accepts optional arguments to point at different files:

| Argument | Default | Description |
|---|---|---|
| `--auth-log` | `sample_logs/auth.log` | SSH authentication log to analyze |
| `--access-log` | `sample_logs/access.log` | Nginx access log to analyze |
| `--output` | `alerts.json` | Where to write the detected alerts |
| `--ground-truth` | `sample_logs/ground_truth.json` | Ground truth for validation (optional — skipped if missing) |

```bash
python analyzer.py --auth-log /var/log/auth.log --access-log /var/log/nginx/access.log --output report.json
```

Each run of `generate_logs.py` creates fresh synthetic data with a known ground truth
(the exact attack injected), so `analyzer.py`'s output can be checked against it
automatically — not just eyeballed. `validate_coverage()` checks both directions:
every ground truth attack has a matching alert, and every alert matches something
in the ground truth (no unexplained extras).

## Detection Gaps

- **Synthetic data only.** The logs are generated, not captured from a real network —
  no background noise, no legitimate traffic that looks suspicious. Real-world false
  positive rates would be higher.
- **GeoIP is a fixed lookup table, not a real database.** `IP_COUNTRY_MAP` hardcodes
  a handful of IPs to countries. A production version would use a real GeoIP database
  (e.g. MaxMind GeoLite2) instead of a static dictionary.
- **Thresholds are fixed, not adaptive.** Each detection uses a hardcoded threshold
  (5 failed logins, 10 404s, 60-minute travel window). A real SOC tool would likely
  tune these per environment, or learn a baseline over time.
- **Ground truth matching is loose by design.** `validate_coverage()` matches on
  MITRE ID plus *either* IP or user, not a stricter combination — a deliberate
  trade-off to let one validation function handle all four attack types without
  four separate comparison rules.

## What I Learned

- **Grouping logic was the core challenge — and the most rewarding part.** Deciding
  what to group by (user+IP for brute force, IP alone for scans, user alone for
  impossible travel) forced me to think about what actually defines each attack
  pattern, not just how to loop over data.
- **Testing against a known ground truth changes how you trust your own code.**
  Writing `generate_logs.py` to inject attacks with known timestamps, then seeing
  `validate_coverage()` confirm each detection caught exactly what was injected —
  and later catch a stale outlier bug I hadn't noticed — was the moment this stopped
  feeling like "code that probably works" and started feeling like something I
  could defend.
- **The simplest correct loop beats the clever one — until it's wrong.** My first
  attempts at brute force and port scan detection compared only the first and last
  event in a group. It looked right, passed my own manual checks, and still missed
  attacks hidden behind a single stale outlier. A sliding window across every
  possible window, not just the extremes, was the actual fix.

## Example Output

```json
{
  "rule_id": "BRUTE_SSH_LOGIN",
  "severity": "HIGH",
  "user": "root",
  "ip": "203.0.113.45",
  "failed_attempts": 5,
  "mitre_attack_id": "T1110.001"
}
```

Full output: [alerts.json](alerts.json)

## Repository Structure

```
python-log-analyzer/
├── README.md
├── generate_logs.py       # synthetic log + ground truth generator
├── analyzer.py             # parsers, grouping, 4 detections, CLI
├── alerts.json              # example output (committed for reviewers)
├── requirements.txt
├── conftest.py
└── tests/
    └── test_detections.py  # unit tests for parsing + all 4 detections
```