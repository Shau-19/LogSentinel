"""Parsers that turn raw logs into normalized Event objects."""

import csv
import re
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from .events import Event

_SSH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)

# Syslog lines carry no year. They are parsed with a leap year so Feb 29 is
# accepted, then moved to the real year once it is known.
_PLACEHOLDER_YEAR = 2000
_NEW_YEAR_JUMP = timedelta(days=180)

# Windows Security log: 4625 = failed logon, 4624 = successful logon
_WIN_FAILURE = "4625"
_WIN_SUCCESS = "4624"
_LOCAL_IPS = {"", "-", "::1", "127.0.0.1"}
_WIN_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
)
_MSG_SOURCE_IP = re.compile(r"Source Network Address:\s*(\S+)")
_MSG_ACCOUNT = re.compile(r"Account Name:\s*(\S+)")


def parse_auth_log(lines: Iterable[str], year: Optional[int] = None,
                   now: Optional[datetime] = None) -> List[Event]:
    """Parse sshd lines from a Linux auth.log.

    Syslog timestamps carry no year. A line more than 180 days earlier than
    the line before it is taken as a New Year rollover.

    year: the year of the first line. If omitted, the log is assumed to end
    before `now` (default: the current time) and the years are worked out
    backwards from there.

    Only "Failed ..." and "Accepted ..." lines are used. The separate
    "Invalid user ..." lines are ignored so one attempt is not counted twice.
    Lines whose date does not exist in their year (Feb 29) are skipped.
    """
    # pass 1: timestamps in the placeholder year, plus a rollover offset per line
    records = []  # (year_offset, ts in placeholder year, outcome, user, ip, valid_user)
    offset, prev = 0, None
    for raw in lines:
        match = _SSH_LINE.match(raw.strip())
        if not match:
            continue
        try:
            ts = datetime.strptime(
                f"{_PLACEHOLDER_YEAR} {match['mon']} {int(match['day'])} {match['time']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            continue
        if prev is not None and prev - ts > _NEW_YEAR_JUMP:
            offset += 1
        prev = ts
        msg = match["msg"]
        failed = _FAILED.search(msg)
        if failed:
            records.append((offset, ts, "failure", failed["user"], failed["ip"],
                            failed["invalid"] is None))
            continue
        accepted = _ACCEPTED.search(msg)
        if accepted:
            records.append((offset, ts, "success", accepted["user"], accepted["ip"], True))

    if not records:
        return []

    # pass 2: decide the year of the first line
    if year is not None:
        start_year = year
    else:
        now = now or datetime.now()
        last_offset, last_ts = records[-1][0], records[-1][1]
        end_year = now.year
        # compare month/day/time only, so a Feb 29 line needs no valid date here
        last_key = (last_ts.month, last_ts.day, last_ts.hour, last_ts.minute, last_ts.second)
        now_key = (now.month, now.day, now.hour, now.minute, now.second)
        if last_key > now_key:  # would be in the future, so it was last year
            end_year -= 1
        start_year = end_year - last_offset

    events: List[Event] = []
    for off, ts, outcome, user, ip, valid_user in records:
        try:
            real_ts = ts.replace(year=start_year + off)
        except ValueError:  # Feb 29 in a non-leap year
            continue
        events.append(Event(real_ts, "sshd", outcome, user, ip, valid_user=valid_user))
    return sorted(events, key=lambda e: e.ts)


def _parse_windows_time(value: str) -> Optional[datetime]:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1]
    for fmt in _WIN_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_windows_csv(lines: Iterable[str]) -> List[Event]:
    """Parse a CSV export of Windows Security events 4624 and 4625.

    Columns used: TimeCreated, EventID (or Id), TargetUserName, IpAddress.
    When IpAddress or TargetUserName is missing or empty, they are read from
    the Message column ("Source Network Address:" and the last
    "Account Name:"), which is what a plain Get-WinEvent export contains.
    Rows with a local or missing source address, or an unknown time format,
    are skipped.
    """
    events: List[Event] = []
    for row in csv.DictReader(lines):
        event_id = (row.get("EventID") or row.get("Id") or "").strip()
        if event_id not in (_WIN_FAILURE, _WIN_SUCCESS):
            continue
        message = row.get("Message") or ""

        ip = (row.get("IpAddress") or "").strip()
        if not ip:
            found = _MSG_SOURCE_IP.search(message)
            ip = found.group(1) if found else ""
        if ip in _LOCAL_IPS:
            continue

        user = (row.get("TargetUserName") or "").strip()
        if not user:
            names = _MSG_ACCOUNT.findall(message)
            user = names[-1] if names else ""

        ts = _parse_windows_time(row.get("TimeCreated") or "")
        if ts is None:
            continue
        outcome = "failure" if event_id == _WIN_FAILURE else "success"
        events.append(Event(ts, "windows", outcome, user, ip))
    return sorted(events, key=lambda e: e.ts)
