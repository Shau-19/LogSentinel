import csv
import json

from logsentinel.cli import main


def test_sample_pipeline(tmp_path):
    sample, out = tmp_path / "sample", tmp_path / "out"
    assert main(["generate", "--out", str(sample)]) == 0
    assert main(["analyze", "--auth-log", str(sample / "auth.log"),
                 "--windows-csv", str(sample / "windows_events.csv"), "--out", str(out)]) == 0

    findings = json.loads((out / "findings.json").read_text())
    pairs = {(f["rule"], f["ip"]) for f in findings}
    assert ("brute_force", "203.0.113.7") in pairs
    assert ("password_spraying", "198.51.100.23") in pairs
    assert ("success_after_failures", "192.0.2.44") in pairs
    assert ("success_after_failures", "198.51.100.77") in pairs  # from the Windows CSV
    assert ("root_login_success", "10.0.0.5") in pairs

    # normal staff logins from internal hosts must not be flagged as attacks
    attack_rules = {"brute_force", "password_spraying", "success_after_failures"}
    assert not [f for f in findings if f["ip"].startswith("10.0.0.") and f["rule"] in attack_rules]

    assert (out / "report.md").read_text().startswith("# LogSentinel Report")
    with (out / "findings.csv").open() as fh:
        assert len(list(csv.DictReader(fh))) == len(findings)


def test_no_events_returns_error(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("nothing useful here\n")
    assert main(["analyze", "--auth-log", str(empty), "--out", str(tmp_path / "o")]) == 1
