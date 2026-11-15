import argparse
from pathlib import Path

from .generate_sample import write_samples
from .parsers import parse_auth_log, parse_windows_csv
from .report import write_csv, write_json, write_markdown
from .rules import Config, run_all


def analyze(args) -> int:
    events = []
    if args.auth_log:
        with open(args.auth_log, encoding="utf-8", errors="replace") as fh:
            events += parse_auth_log(fh, year=args.year)
    if args.windows_csv:
        with open(args.windows_csv, encoding="utf-8-sig", newline="") as fh:
            events += parse_windows_csv(fh)
    if not events:
        print("No logon events found. Pass --auth-log and/or --windows-csv.")
        return 1
    events.sort(key=lambda e: e.ts)
    cfg = Config(threshold=args.threshold, window_seconds=args.window)
    findings = run_all(events, cfg)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(findings, out / "findings.json")
    write_csv(findings, out / "findings.csv")
    write_markdown(findings, out / "report.md", len(events))

    print(f"Analyzed {len(events)} events, {len(findings)} findings -> {out}/")
    for f in findings:
        print(f"[{f.severity:8}] {f.rule:24} {f.attack_id:10} {f.ip:15} {f.detail}")
    return 0


def generate(args) -> int:
    auth, win = write_samples(Path(args.out))
    print(f"Wrote {auth} and {win}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="logsentinel", description="Log-based threat detection")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze logs and write a report")
    a.add_argument("--auth-log", help="Linux auth.log (sshd lines)")
    a.add_argument("--windows-csv", help="CSV export of Windows events 4624/4625")
    a.add_argument("--out", default="report", help="output directory")
    a.add_argument("--year", type=int, default=None,
                   help="year of the first auth.log line (default: inferred, assuming the log ends before now)")
    a.add_argument("--threshold", type=int, default=5, help="failures that make a burst")
    a.add_argument("--window", type=int, default=300, help="window size in seconds")
    a.set_defaults(func=analyze)

    g = sub.add_parser("generate", help="write synthetic sample logs")
    g.add_argument("--out", default="sample", help="output directory")
    g.set_defaults(func=generate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
