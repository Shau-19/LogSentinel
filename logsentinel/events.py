from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    """One normalized logon event, regardless of where it came from."""

    ts: datetime
    source: str  # "sshd" or "windows"
    outcome: str  # "failure" or "success"
    user: str
    ip: str
    valid_user: bool = True  # False when sshd said "invalid user"
