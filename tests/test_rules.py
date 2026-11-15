from datetime import datetime, timedelta

from logsentinel.events import Event
from logsentinel.rules import (Config, brute_force, off_hours_login, password_spraying,
                               root_login_success, run_all, success_after_failures)

T0 = datetime(2026, 11, 10, 10, 0, 0)


def fail(offset, user="bob", ip="203.0.113.9"):
    return Event(T0 + timedelta(seconds=offset), "sshd", "failure", user, ip)


def ok(offset, user="bob", ip="203.0.113.9", hour=None):
    ts = T0 + timedelta(seconds=offset)
    if hour is not None:
        ts = ts.replace(hour=hour)
    return Event(ts, "sshd", "success", user, ip)


def test_brute_force_detected():
    events = [fail(i * 10) for i in range(6)]
    found = brute_force(events, Config())
    assert len(found) == 1 and found[0].count == 6 and found[0].attack_id == "T1110.001"


def test_brute_force_ignores_slow_failures():
    events = [fail(i * 600) for i in range(6)]  # one every 10 minutes
    assert brute_force(events, Config()) == []


def test_brute_force_below_threshold():
    assert brute_force([fail(i) for i in range(4)], Config()) == []


def test_spraying_detected():
    events = [fail(i * 5, user=f"user{i}", ip="198.51.100.1") for i in range(6)]
    found = password_spraying(events, Config())
    assert len(found) == 1 and found[0].count == 6 and found[0].attack_id == "T1110.003"


def test_spraying_not_triggered_by_one_user():
    events = [fail(i * 5, user="alice", ip="198.51.100.1") for i in range(10)]
    assert password_spraying(events, Config()) == []


def test_success_after_failures_is_critical():
    events = [fail(i * 5) for i in range(6)] + [ok(40)]
    found = success_after_failures(events, Config())
    assert len(found) == 1 and found[0].severity == "CRITICAL"


def test_success_from_other_ip_is_not_flagged():
    events = [fail(i * 5) for i in range(6)] + [ok(40, ip="10.0.0.2")]
    assert success_after_failures(events, Config()) == []


def test_root_login_success():
    found = root_login_success([ok(0, user="root", ip="10.0.0.5")], Config())
    assert len(found) == 1 and found[0].severity == "MEDIUM"
    assert root_login_success([fail(0, user="root")], Config()) == []


def test_off_hours_login():
    assert len(off_hours_login([ok(0, hour=2)], Config())) == 1
    assert off_hours_login([ok(0, hour=11)], Config()) == []


def test_findings_sorted_by_severity():
    events = [fail(i * 5) for i in range(6)] + [ok(40), ok(50, user="root", ip="10.0.0.5")]
    severities = [f.severity for f in run_all(events)]
    assert severities == sorted(severities, key=["CRITICAL", "HIGH", "MEDIUM", "LOW"].index)
