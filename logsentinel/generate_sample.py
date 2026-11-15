"""Generate synthetic logs with known attacks, for demos and tests.

All addresses use the reserved documentation ranges (RFC 5737), so none of
this data refers to a real host.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

HOST = "web01"
INTERNAL = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13"}
SPRAY_USERS = ["admin", "test", "oracle", "ubuntu", "guest", "postgres",
               "user", "git", "ftp", "jenkins", "pi", "support"]


def _line(ts: datetime, pid: int, msg: str) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} sshd[{pid}]: {msg}"


def generate_auth_log(base: datetime, seed: int = 7) -> List[Tuple[datetime, str]]:
    rng = random.Random(seed)
    rows: List[Tuple[datetime, str]] = []

    def add(ts: datetime, msg: str) -> None:
        rows.append((ts, _line(ts, rng.randint(1000, 9999), msg)))

    # normal activity: three days of staff logins in business hours
    for day in range(3):
        for user, ip in INTERNAL.items():
            ts = base + timedelta(days=day, hours=rng.randint(9, 17), minutes=rng.randint(0, 59))
            if rng.random() < 0.4:  # one typo before the real login
                add(ts - timedelta(seconds=20), f"Failed password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")
            add(ts, f"Accepted password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")

    # attack 1: brute force against root
    t = base + timedelta(hours=2, minutes=10)
    for i in range(40):
        add(t + timedelta(seconds=i * 4), f"Failed password for root from 203.0.113.7 port {rng.randint(40000, 60000)} ssh2")

    # attack 2: password spraying across many usernames
    t = base + timedelta(days=1, hours=4, minutes=30)
    for i, user in enumerate(SPRAY_USERS):
        for j in range(2):
            add(t + timedelta(seconds=i * 15 + j * 5),
                f"Failed password for invalid user {user} from 198.51.100.23 port {rng.randint(40000, 60000)} ssh2")

    # attack 3: guessing that ends in a successful login at night
    t = base + timedelta(days=2, hours=23, minutes=40)
    for i in range(8):
        add(t + timedelta(seconds=i * 10), f"Failed password for deploy from 192.0.2.44 port {rng.randint(40000, 60000)} ssh2")
    add(t + timedelta(seconds=95), f"Accepted password for deploy from 192.0.2.44 port {rng.randint(40000, 60000)} ssh2")

    # misconfiguration: direct root login from an internal host
    add(base + timedelta(days=1, hours=12), "Accepted password for root from 10.0.0.5 port 50022 ssh2")

    rows.sort(key=lambda r: r[0])
    return rows


def generate_windows_csv(base: datetime) -> List[str]:
    lines = ["TimeCreated,EventID,TargetUserName,IpAddress"]
    t = base + timedelta(hours=3)
    for i in range(12):
        lines.append(f"{(t + timedelta(seconds=i * 6)):%Y-%m-%dT%H:%M:%S},4625,Administrator,198.51.100.77")
    lines.append(f"{(t + timedelta(seconds=90)):%Y-%m-%dT%H:%M:%S},4624,Administrator,198.51.100.77")
    lines.append(f"{(base + timedelta(hours=10)):%Y-%m-%dT%H:%M:%S},4624,alice,10.0.0.11")
    lines.append(f"{(base + timedelta(hours=10)):%Y-%m-%dT%H:%M:%S},4624,SYSTEM,-")
    return lines


def write_samples(out_dir: Path, base: datetime = None) -> Tuple[Path, Path]:
    base = base or datetime(2026, 11, 10)
    out_dir.mkdir(parents=True, exist_ok=True)
    auth = out_dir / "auth.log"
    win = out_dir / "windows_events.csv"
    auth.write_text("\n".join(line for _, line in generate_auth_log(base)) + "\n", encoding="utf-8")
    win.write_text("\n".join(generate_windows_csv(base)) + "\n", encoding="utf-8")
    return auth, win
