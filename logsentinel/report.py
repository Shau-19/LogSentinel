"""Write findings as JSON, CSV and a Markdown report."""

import csv
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import List

from .rules import Finding, SEVERITY_RANK


def _row(f: Finding) -> dict:
    d = asdict(f)
    d["users"] = ", ".join(f.users)
    d["first_seen"] = f.first_seen.isoformat(sep=" ")
    d["last_seen"] = f.last_seen.isoformat(sep=" ")
    return d


def write_json(findings: List[Finding], path: Path) -> None:
    path.write_text(json.dumps([_row(f) for f in findings], indent=2), encoding="utf-8")


def write_csv(findings: List[Finding], path: Path) -> None:
    fields = ["severity", "rule", "attack_id", "attack_name", "ip", "users",
              "count", "first_seen", "last_seen", "detail", "recommendation"]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            row = _row(f)
            writer.writerow({k: row[k] for k in fields})


def write_markdown(findings: List[Finding], path: Path, events_analyzed: int) -> None:
    counts = Counter(f.severity for f in findings)
    lines = ["# LogSentinel Report", "",
             f"Events analyzed: {events_analyzed}  ",
             f"Findings: {len(findings)}", ""]
    lines += ["| Severity | Count |", "|---|---|"]
    for sev in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines += ["", "## Findings", "",
              "| Severity | Rule | ATT&CK | Source IP | Account(s) | Count | First seen | Last seen |",
              "|---|---|---|---|---|---|---|---|"]
    for f in findings:
        users = ", ".join(f.users[:3]) + (" ..." if len(f.users) > 3 else "")
        lines.append(f"| {f.severity} | {f.rule} | {f.attack_id} | {f.ip} | {users} | "
                     f"{f.count} | {f.first_seen:%Y-%m-%d %H:%M:%S} | {f.last_seen:%Y-%m-%d %H:%M:%S} |")
    lines += ["", "## Recommended actions", ""]
    for rule in dict.fromkeys(f.rule for f in findings):
        sample = next(f for f in findings if f.rule == rule)
        lines.append(f"- **{rule}**: {sample.recommendation}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
