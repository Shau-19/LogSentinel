# LogSentinel: project description

## What it is

LogSentinel is a small Python tool that reads login logs, finds signs of credential attacks, and writes a report. It is a SOC-style log analysis and detection project, built as a learning project, not a production SIEM.

It reads two kinds of input:

- Linux `auth.log` (the sshd lines)
- A CSV export of Windows Security events 4624 (successful logon) and 4625 (failed logon)

Both are converted into one common `Event` format, so the same detection rules work for Linux and Windows.

## Offline by design

LogSentinel makes no network calls and uses only the Python standard library. It can be copied to an isolated or air-gapped machine and run on logs that never leave that machine.

## What it detects

| Rule | What it looks for | Severity | MITRE ATT&CK |
|---|---|---|---|
| `brute_force` | 5 or more failed logins from one IP against one account inside 300 seconds | HIGH | T1110.001 Password Guessing |
| `password_spraying` | One IP failing against 5 or more different usernames inside 300 seconds | HIGH | T1110.003 Password Spraying |
| `success_after_failures` | A successful login from an IP that just produced a burst of failures (likely compromise) | CRITICAL | T1078 Valid Accounts |
| `root_login_success` | Direct login as `root` or `Administrator` | MEDIUM | T1078.003 Local Accounts |
| `off_hours_login` | Successful login outside 08:00 to 20:00 | LOW | T1078 Valid Accounts |

Threshold and window are options on the command line. The other values are in the `Config` class in `logsentinel/rules.py`.

## How to run it locally

You need Python 3.8 or newer (I tested it on Python 3.13). There are no runtime dependencies. Only the tests need `pytest`.

```bash
# 1. go into the project folder
cd LogSentinel

# 2. (optional but recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. install the test dependency
pip install -r requirements-dev.txt

# 4. run the tests (should show 31 passed)
python -m pytest -q

# 5. run the tool on the bundled sample logs
python -m logsentinel analyze --auth-log sample/auth.log \
    --windows-csv sample/windows_events.csv --out report
```

Then open `report/report.md`. The tool also writes `report/findings.json` and `report/findings.csv`.

Other commands:

```bash
# regenerate the synthetic sample logs
python -m logsentinel generate --out sample

# analyze your own auth.log with stricter settings
python -m logsentinel analyze --auth-log /path/to/auth.log --year 2026 \
    --threshold 8 --window 120 --out report
```

Syslog lines do not include a year. By default LogSentinel assumes the log ends before the current date and works the years out backwards, detecting New Year rollovers (a jump back of more than 180 days). Pass `--year` to set the year of the first line yourself.

## Project layout

```
logsentinel/
  events.py           Event dataclass (time, source, outcome, user, ip, valid_user)
  parsers.py          parse_auth_log() and parse_windows_csv()
  rules.py            the five detection rules, Config, Finding, run_all()
  report.py           write_json(), write_csv(), write_markdown()
  generate_sample.py  synthetic logs with known attacks
  cli.py              command line: analyze and generate
  __main__.py         lets you run python -m logsentinel
tests/
  test_parsers.py     parser tests
  test_rules.py       each rule, with passing and failing cases
  test_end_to_end.py  generate, analyze, check the outputs
  test_changes.py     year inference, Windows CSV formats, encodings, spraying detail
sample/               generated logs you can run immediately
docs/example_report.md  an example report
.github/workflows/ci.yml  runs pytest on every push
```

## How the detection works

Reading order for learning the code: `events.py`, then `parsers.py`, then `rules.py`.

- The burst rules keep a sliding window over the events. A `deque` holds the events inside the last N seconds. As each new event arrives, old ones are dropped from the left. The rule records the largest count seen inside any window.
- `brute_force` groups failures by (IP, account). `password_spraying` groups failures by IP and counts distinct usernames in the window.
- `success_after_failures` looks at each successful login and counts failures from the same IP in the window before it.
- The sample data uses reserved documentation IP ranges (RFC 5737), so no real hosts are involved.

## Known limits (be honest about these)

- The sample data is synthetic. It shows the rules work, not how they behave on a busy production log.
- Thresholds are fixed values. Real use needs tuning to reduce false positives, for example shared NAT addresses or monitoring scripts that fail often.
- Batch analysis only. No live tailing, no alerting, no correlation across hosts.
- Only sshd and Windows 4624/4625 events are supported.

## Ideas to extend it

1. GeoIP and known-bad IP enrichment of each finding
2. Parse Windows `.evtx` files directly, without the CSV export step
3. Per-account baselines for the off-hours rule
4. A rule for one account logging in from several countries in a short time
5. Real-time mode that tails a log file

## Working on it with Claude Code

Open the `LogSentinel` folder in your IDE and start Claude Code there. Useful first prompts:

- "Read the project and explain how the sliding window in `rules.py` works."
- "Add a rule that detects one account logging in from three different IPs within ten minutes, with a test."
- "Add a `--format` option to the CLI that writes only JSON."

Run `python -m pytest -q` after every change. Keep the tests passing, and keep the README and this file accurate if you add features.
