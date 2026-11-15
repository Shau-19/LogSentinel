from datetime import datetime

from logsentinel.parsers import parse_auth_log, parse_windows_csv


def test_failed_password_valid_user():
    ev = parse_auth_log(["Nov 10 02:10:03 web01 sshd[1]: Failed password for root from 203.0.113.7 port 5 ssh2"], year=2026)
    assert len(ev) == 1
    assert ev[0].outcome == "failure" and ev[0].user == "root" and ev[0].valid_user
    assert ev[0].ts == datetime(2026, 11, 10, 2, 10, 3)


def test_failed_password_invalid_user():
    ev = parse_auth_log(["Nov  9 04:30:00 web01 sshd[1]: Failed password for invalid user admin from 198.51.100.23 port 5 ssh2"], year=2026)
    assert ev[0].user == "admin" and ev[0].valid_user is False


def test_accepted_login():
    ev = parse_auth_log(["Nov 10 12:00:00 web01 sshd[1]: Accepted publickey for alice from 10.0.0.11 port 5 ssh2"], year=2026)
    assert ev[0].outcome == "success" and ev[0].user == "alice"


def test_ignores_other_lines_and_duplicate_invalid_user_line():
    lines = [
        "Nov 10 02:10:03 web01 CRON[5]: session opened for user root",
        "Nov 10 02:10:03 web01 sshd[1]: Invalid user admin from 198.51.100.23 port 5",
        "garbage line",
    ]
    assert parse_auth_log(lines, year=2026) == []


def test_windows_csv_filters_ids_and_local_addresses():
    rows = [
        "TimeCreated,EventID,TargetUserName,IpAddress",
        "2026-11-10T03:00:00,4625,Administrator,198.51.100.77",
        "2026-11-10T03:01:00,4624,alice,10.0.0.11",
        "2026-11-10T03:02:00,4624,SYSTEM,-",
        "2026-11-10T03:03:00,4672,alice,10.0.0.11",
    ]
    ev = parse_windows_csv(rows)
    assert [(e.outcome, e.user) for e in ev] == [("failure", "Administrator"), ("success", "alice")]


def test_message_repeated_counts_every_attempt():
    lines = [
        "Dec 10 07:13:43 LabSZ sshd[1]: Failed password for root from 5.36.59.76 port 42393 ssh2",
        "Dec 10 07:13:56 LabSZ sshd[1]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]",
    ]
    ev = parse_auth_log(lines, year=2026)
    assert len(ev) == 6 and all(e.user == "root" and e.outcome == "failure" for e in ev)


def test_empty_or_spaced_username_is_parsed():
    lines = [
        "Dec 10 08:24:35 LabSZ sshd[1]: Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2",
        "Dec 10 08:24:36 LabSZ sshd[1]: Failed password for invalid user  from 5.188.10.180 port 36279 ssh2",
        "Dec 10 08:24:37 LabSZ sshd[1]: Failed password for invalid user john smith from 5.188.10.180 port 36279 ssh2",
    ]
    assert [e.user for e in parse_auth_log(lines, year=2026)] == ["0101", "", "john smith"]
