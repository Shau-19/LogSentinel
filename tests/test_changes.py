"""Tests for year inference, Windows CSV formats, encodings and the spraying detail."""

import csv
import io
import json
from datetime import datetime, timedelta

from logsentinel.cli import main
from logsentinel.events import Event
from logsentinel.parsers import parse_auth_log, parse_windows_csv
from logsentinel.report import write_csv, write_json, write_markdown
from logsentinel.rules import Config, Finding, password_spraying

FAIL = "web01 sshd[1]: Failed password for root from 203.0.113.7 port 5 ssh2"
NEW_YEAR = [f"Dec 31 23:59:50 {FAIL}", f"Jan  1 00:00:10 {FAIL}"]


# --- auth.log years ---------------------------------------------------------

def test_new_year_with_explicit_year():
    ev = parse_auth_log(NEW_YEAR, year=2025)
    assert [e.ts for e in ev] == [datetime(2025, 12, 31, 23, 59, 50), datetime(2026, 1, 1, 0, 0, 10)]


def test_new_year_with_inferred_year():
    ev = parse_auth_log(NEW_YEAR, now=datetime(2026, 1, 5))
    assert [e.ts for e in ev] == [datetime(2025, 12, 31, 23, 59, 50), datetime(2026, 1, 1, 0, 0, 10)]


def test_new_year_crossing_keeps_burst_together():
    # 3 failures before midnight and 3 after must land in one 5-minute window
    lines = [f"Dec 31 23:59:{s:02d} {FAIL}" for s in (30, 40, 50)] + \
            [f"Jan  1 00:00:{s:02d} {FAIL}" for s in (0, 10, 20)]
    ev = parse_auth_log(lines, now=datetime(2026, 3, 1))
    assert ev[-1].ts - ev[0].ts == timedelta(seconds=50)


def test_year_inferred_from_now():
    line = [f"Nov 10 02:10:03 {FAIL}"]
    assert parse_auth_log(line, now=datetime(2026, 11, 16))[0].ts.year == 2026
    # a date later than "now" in the year must belong to the previous year
    assert parse_auth_log(line, now=datetime(2026, 11, 9))[0].ts.year == 2025
    # same day, later time of day
    assert parse_auth_log(line, now=datetime(2026, 11, 10, 2, 0, 0))[0].ts.year == 2025


def test_feb_29():
    line = [f"Feb 29 12:00:00 {FAIL}"]
    assert parse_auth_log(line, year=2025) == []
    assert parse_auth_log(line, year=2024)[0].ts == datetime(2024, 2, 29, 12, 0, 0)
    # inferred: in March 2025 the latest Feb 29 before now is not in 2025, so skipped
    assert parse_auth_log(line, now=datetime(2025, 3, 1)) == []
    assert parse_auth_log(line, now=datetime(2028, 3, 1))[0].ts.year == 2028


def test_feb_29_skipped_without_losing_other_lines():
    lines = [f"Feb 28 12:00:00 {FAIL}", f"Feb 29 12:00:00 {FAIL}", f"Mar  1 12:00:00 {FAIL}"]
    ev = parse_auth_log(lines, year=2026)
    assert [e.ts.day for e in ev] == [28, 1]


def test_cli_year_default_is_inferred(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(f"Jan  1 00:00:00 {FAIL}\n", encoding="utf-8")
    out = tmp_path / "out"
    assert main(["analyze", "--auth-log", str(log), "--out", str(out)]) == 0


# --- Windows CSV -------------------------------------------------------------

MSG_4625 = (
    "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n"
    "\tAccount Name:\t\tWEB01$\n\tAccount Domain:\t\tCORP\n\n"
    "Account For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n"
    "\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tWEB01\n\n"
    "Network Information:\n\tWorkstation Name:\tKALI\n"
    "\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t51234\n"
)
MSG_4624_LOCAL = MSG_4625.replace("198.51.100.77", "-").replace("Administrator", "SYSTEM")


def _csv(rows, header):
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return io.StringIO(buf.getvalue(), newline="")


def test_windows_local_dates_and_message_text():
    data = _csv([
        ["11/10/2026 3:00:00 AM", "4625", MSG_4625],
        ["11/10/2026 3:00:06 PM", "4625", MSG_4625],
        ["11/10/2026 3:01:00 AM", "4624", MSG_4624_LOCAL],  # local logon, skipped
        ["11/10/2026 3:02:00 AM", "4672", MSG_4625],        # other event id, skipped
    ], ["TimeCreated", "Id", "Message"])
    ev = parse_windows_csv(data)
    assert [(e.ts, e.outcome, e.user, e.ip) for e in ev] == [
        (datetime(2026, 11, 10, 3, 0, 0), "failure", "Administrator", "198.51.100.77"),
        (datetime(2026, 11, 10, 15, 0, 6), "failure", "Administrator", "198.51.100.77"),
    ]


def test_windows_columns_win_over_message():
    data = _csv([["2026-11-10 03:00:00", "4625", "bob", "203.0.113.9", MSG_4625]],
                ["TimeCreated", "EventID", "TargetUserName", "IpAddress", "Message"])
    ev = parse_windows_csv(data)
    assert (ev[0].user, ev[0].ip) == ("bob", "203.0.113.9")


def test_windows_time_formats():
    stamps = ["2026-11-10T03:00:00", "2026-11-10 03:00:00", "11/10/2026 3:00:00 AM",
              "11/10/2026 03:00:00", "25/10/2026 3:00:00 AM", "25/10/2026 03:00:00",
              "25-10-2026 03:00:00", "2026-11-10T03:00:00Z", "not a date"]
    data = _csv([[s, "4625", "bob", "203.0.113.9"] for s in stamps],
                ["TimeCreated", "EventID", "TargetUserName", "IpAddress"])
    assert len(parse_windows_csv(data)) == len(stamps) - 1


def test_windows_csv_with_bom(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("TimeCreated,EventID,TargetUserName,IpAddress\n"
                    + "".join(f"2026-11-10T03:00:{i:02d},4625,Administrator,198.51.100.77\n"
                              for i in range(6)),
                    encoding="utf-8-sig")
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")
    out = tmp_path / "out"
    assert main(["analyze", "--windows-csv", str(path), "--out", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert any(f["rule"] == "brute_force" for f in findings)


# --- reports -----------------------------------------------------------------

def test_reports_with_non_ascii_usernames(tmp_path):
    names = ["jürgen", "管理者", "Ωmega"]
    t = datetime(2026, 11, 10, 3, 0, 0)
    findings = [Finding("brute_force", "HIGH", "T1110.001", "Brute Force: Password Guessing",
                        "203.0.113.9", [n], 6, t, t, f"6 failed logins for '{n}'", "block")
                for n in names]
    write_json(findings, tmp_path / "f.json")
    write_csv(findings, tmp_path / "f.csv")
    write_markdown(findings, tmp_path / "r.md", 18)

    assert [f["users"] for f in json.loads((tmp_path / "f.json").read_text(encoding="utf-8"))] == names
    with (tmp_path / "f.csv").open(encoding="utf-8", newline="") as fh:
        assert [r["users"] for r in csv.DictReader(fh)] == names
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert all(n in md for n in names)


# --- spraying detail ---------------------------------------------------------

def _spray(valid_flags):
    t = datetime(2026, 11, 10, 3, 0, 0)
    return [Event(t + timedelta(seconds=i * 5), "sshd", "failure", f"user{i}", "198.51.100.1", valid_user=v)
            for i, v in enumerate(valid_flags)]


def test_spraying_detail_counts_unknown_users():
    found = password_spraying(_spray([False, False, False, True, True, True]), Config())
    assert found[0].detail == "6 different usernames tried within 300s (3 of them do not exist on the host)"


def test_spraying_detail_when_all_users_exist():
    found = password_spraying(_spray([True] * 6), Config())
    assert found[0].detail == "6 different usernames tried within 300s"
