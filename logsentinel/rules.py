"""Detection rules. Each rule reads normalized events and returns Findings."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from .events import Event

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

RECOMMENDATIONS = {
    "brute_force": "Block or rate-limit the source IP, enforce key-based login or account lockout.",
    "password_spraying": "Block the source IP, review the targeted accounts, require MFA or keys.",
    "success_after_failures": "Treat the account as compromised: force a password reset, kill sessions, review activity after login.",
    "root_login_success": "Disable direct root login over SSH and use a named account with sudo.",
    "off_hours_login": "Confirm the login with the account owner and review what the session did.",
}


@dataclass
class Config:
    threshold: int = 5  # failures that make a burst
    window_seconds: int = 300  # size of the sliding window
    spray_users: int = 5  # distinct usernames from one IP that look like spraying
    business_start: int = 8  # logins before this hour are off-hours
    business_end: int = 20  # logins at or after this hour are off-hours


@dataclass
class Finding:
    rule: str
    severity: str
    attack_id: str
    attack_name: str
    ip: str
    users: List[str]
    count: int
    first_seen: datetime
    last_seen: datetime
    detail: str
    recommendation: str


def _densest_window(times: List[datetime], window: timedelta) -> Tuple[int, datetime, datetime]:
    """Largest number of events inside any one sliding window, with its bounds."""
    best = (0, None, None)
    dq: deque = deque()
    for t in times:
        dq.append(t)
        while t - dq[0] > window:
            dq.popleft()
        if len(dq) > best[0]:
            best = (len(dq), dq[0], t)
    return best


def brute_force(events: List[Event], cfg: Config) -> List[Finding]:
    """Many failed logins from one IP against one account in a short window."""
    window = timedelta(seconds=cfg.window_seconds)
    groups: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    for e in events:
        if e.outcome == "failure":
            groups[(e.ip, e.user)].append(e.ts)
    findings = []
    for (ip, user), times in groups.items():
        count, first, last = _densest_window(sorted(times), window)
        if count >= cfg.threshold:
            findings.append(Finding(
                "brute_force", "HIGH", "T1110.001", "Brute Force: Password Guessing",
                ip, [user], count, first, last,
                f"{count} failed logins for '{user}' within {cfg.window_seconds}s",
                RECOMMENDATIONS["brute_force"]))
    return findings


def password_spraying(events: List[Event], cfg: Config) -> List[Finding]:
    """One IP failing against many different usernames in a short window."""
    window = timedelta(seconds=cfg.window_seconds)
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.outcome == "failure":
            by_ip[e.ip].append(e)
    findings = []
    for ip, items in by_ip.items():
        items.sort(key=lambda e: e.ts)
        dq: deque = deque()
        best = (0, None, None, set(), set())
        for e in items:
            dq.append(e)
            while e.ts - dq[0].ts > window:
                dq.popleft()
            users = {x.user for x in dq}
            if len(users) > best[0]:
                unknown = {x.user for x in dq if not x.valid_user}
                best = (len(users), dq[0].ts, e.ts, users, unknown)
        distinct, first, last, users, unknown = best
        if distinct >= cfg.spray_users:
            detail = f"{distinct} different usernames tried within {cfg.window_seconds}s"
            if unknown:
                detail += f" ({len(unknown)} of them do not exist on the host)"
            findings.append(Finding(
                "password_spraying", "HIGH", "T1110.003", "Brute Force: Password Spraying",
                ip, sorted(users), distinct, first, last,
                detail, RECOMMENDATIONS["password_spraying"]))
    return findings


def success_after_failures(events: List[Event], cfg: Config) -> List[Finding]:
    """A successful login right after a burst of failures from the same IP."""
    window = timedelta(seconds=cfg.window_seconds)
    failures: Dict[str, List[datetime]] = defaultdict(list)
    for e in events:
        if e.outcome == "failure":
            failures[e.ip].append(e.ts)
    findings, seen = [], set()
    for e in events:
        if e.outcome != "success" or (e.ip, e.user) in seen:
            continue
        recent = [t for t in failures.get(e.ip, []) if e.ts - window <= t <= e.ts]
        if len(recent) >= cfg.threshold:
            seen.add((e.ip, e.user))
            findings.append(Finding(
                "success_after_failures", "CRITICAL", "T1078", "Valid Accounts",
                e.ip, [e.user], len(recent), min(recent), e.ts,
                f"login for '{e.user}' succeeded after {len(recent)} failures from the same IP",
                RECOMMENDATIONS["success_after_failures"]))
    return findings


def root_login_success(events: List[Event], cfg: Config) -> List[Finding]:
    """Successful login as root or Administrator."""
    findings, seen = [], set()
    for e in events:
        if e.outcome == "success" and e.user.lower() in ("root", "administrator"):
            if (e.ip, e.user) in seen:
                continue
            seen.add((e.ip, e.user))
            findings.append(Finding(
                "root_login_success", "MEDIUM", "T1078.003", "Valid Accounts: Local Accounts",
                e.ip, [e.user], 1, e.ts, e.ts,
                f"direct login as '{e.user}'", RECOMMENDATIONS["root_login_success"]))
    return findings


def off_hours_login(events: List[Event], cfg: Config) -> List[Finding]:
    """Successful logins outside business hours."""
    groups: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
    for e in events:
        if e.outcome == "success" and not (cfg.business_start <= e.ts.hour < cfg.business_end):
            groups[(e.ip, e.user)].append(e.ts)
    findings = []
    for (ip, user), times in groups.items():
        findings.append(Finding(
            "off_hours_login", "LOW", "T1078", "Valid Accounts",
            ip, [user], len(times), min(times), max(times),
            f"{len(times)} login(s) outside {cfg.business_start:02d}:00-{cfg.business_end:02d}:00",
            RECOMMENDATIONS["off_hours_login"]))
    return findings


ALL_RULES = [brute_force, password_spraying, success_after_failures,
             root_login_success, off_hours_login]


def run_all(events: List[Event], cfg: Config = None) -> List[Finding]:
    cfg = cfg or Config()
    findings: List[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(events, cfg))
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.first_seen))
    return findings
