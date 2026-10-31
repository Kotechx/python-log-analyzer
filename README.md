\# Python Log Analyzer



A log analysis tool that detects four common SOC attack patterns in authentication

and web server logs, without relying on a SIEM. Built to understand detection logic

at the code level — not just configure rules in a GUI.



\## Problem



SOC analysts spend a lot of time triaging raw logs for known attack patterns. This

project implements that triage logic from scratch in Python: parsing real log formats,

grouping events by the right key, and applying time-window and content-based detection

rules — the same logic I wrote as SPL rules in my \[SIEM Home Lab](https://github.com/Kotechx/cybersecurity-portfolio/tree/main/siem-home-lab), now as code.



\## What It Detects



| # | Detection | Logic | MITRE ATT\&CK |

|---|-----------|-------|---------------|

| 1 | SSH brute force | ≥ 5 failed logins, same user+IP, within 10 minutes | T1110.001 |

| 2 | Port/path scan | ≥ 10 HTTP 404s from the same IP, within 5 minutes | T1595.002 |

| 3 | Path traversal | Request path contains `../` or its encoded form `%2f` | T1083 |

| 4 | Impossible travel | Same user logs in from two IPs in different countries within 60 minutes | T1078 |



\## How to Run



```bash

python -m venv venv

venv\\Scripts\\activate       # Windows

pip install -r requirements.txt



python generate\_logs.py     # creates sample\_logs/ with synthetic attacks + ground truth

python analyzer.py          # runs all 4 detections, writes alerts.json

pytest                      # runs the unit tests

```



Each run of `generate\_logs.py` creates fresh synthetic data with a known ground truth

(the exact attack injected), so `analyzer.py`'s output can be checked against it

automatically — not just eyeballed.



\## Detection Gaps



\- \*\*Synthetic data only.\*\* The logs are generated, not captured from a real network —

&#x20; no background noise, no legitimate traffic that looks suspicious. Real-world false

&#x20; positive rates would be higher.

\- \*\*GeoIP is a fixed lookup table, not a real database.\*\* `IP\_COUNTRY\_MAP` hardcodes

&#x20; a handful of IPs to countries. A production version would use a real GeoIP database

&#x20; (e.g. MaxMind GeoLite2) instead of a static dictionary.

\- \*\*Thresholds are fixed, not adaptive.\*\* Each detection uses a hardcoded threshold

&#x20; (5 failed logins, 10 404s, 60-minute travel window). A real SOC tool would likely

&#x20; tune these per environment, or learn a baseline over time.



\## What I Learned



\- \*\*Grouping logic was the core challenge — and the most rewarding part.\*\* Deciding

&#x20; what to group by (user+IP for brute force, IP alone for scans, user alone for

&#x20; impossible travel) forced me to think about what actually defines each attack

&#x20; pattern, not just how to loop over data.

\- \*\*Testing against a known ground truth changes how you trust your own code.\*\*

&#x20; Writing `generate\_logs.py` to inject attacks with known timestamps, then seeing

&#x20; `validate\_against\_ground\_truth` confirm each detection caught exactly what was

&#x20; injected, was the moment this stopped feeling like "code that probably works"

&#x20; and started feeling like something I could defend.

\- \*\*The simplest correct loop beats the clever one.\*\* My first attempts at both

&#x20; brute force and port scan detection compared every possible pair of events

&#x20; instead of just the first and last — same result, more complexity. Simpler was

&#x20; usually right.



\## Example Output



```json

{

&#x20; "rule\_id": "BRUTE\_SSH\_LOGIN",

&#x20; "severity": "HIGH",

&#x20; "user": "root",

&#x20; "ip": "203.0.113.45",

&#x20; "failed\_attempts": 5,

&#x20; "mitre\_attack\_id": "T1110.001"

}

```



Full output: \[alerts.json](alerts.json)



\## Repository Structure



```

python-log-analyzer/

├── README.md

├── generate\_logs.py       # synthetic log + ground truth generator

├── analyzer.py             # parsers, grouping, 4 detections, CLI

├── alerts.json              # example output (committed for reviewers)

├── requirements.txt

├── conftest.py

└── tests/

&#x20;   └── test\_detections.py  # unit tests for parsing + all 4 detections

```

