"""Command-line interface for the Mini-SOC workbench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .engine import build_attack_coverage, correlate_alerts, load_events, load_rules, run_detections

DEFAULT_RULES = Path(__file__).resolve().parent / "assets" / "detections.json"


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_summary(
    path: Path,
    alerts: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    source_format: str,
    coverage: list[dict[str, Any]],
) -> None:
    lines = [
        "# Mini-SOC analysis summary",
        "",
        f"- Input format: `{source_format}`",
        f"- Alerts: **{len(alerts)}**",
        f"- Correlated cases: **{len(cases)}**",
        "",
        "## Cases",
        "",
    ]
    if not cases:
        lines.append("No incidents were created from this event set.")
    else:
        lines.extend(["| Case | Severity | Risk | Alerts | Title |", "|---|---:|---:|---:|---|"])
        for case in cases:
            lines.append(
                f"| {case['case_id']} | {case['severity']} | {case['risk_score']} "
                f"| {len(case['alert_ids'])} | {case['title']} |"
            )
    lines.extend(["", "## ATT&CK coverage", ""])
    if not coverage:
        lines.append("No detection rules are configured.")
    else:
        lines.extend(["| Rule | Tactic(s) | Technique | Alerts |", "|---|---|---|---:|"])
        for row in coverage:
            attack = row.get("attack") or {}
            technique_id = str(attack.get("technique_id", "Unmapped"))
            technique_name = str(attack.get("technique_name", ""))
            if technique_id.startswith("T") and technique_id[1:].replace(".", "").isdigit():
                url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                technique = f"[{technique_id} {technique_name}]({url})"
            else:
                technique = f"{technique_id} {technique_name}".strip()
            tactics = ", ".join(attack.get("tactics", [])) or "—"
            lines.append(f"| `{row['rule_id']}` | {tactics} | {technique} | {row['alert_count']} |")
    lines.extend(
        [
            "",
            "Mappings describe the intended behavior covered by each rule; they are not proof of adversary activity or attribution.",
        ]
    )
    lines.extend(
        [
            "",
            "## Analyst note",
            "",
            "This report is generated from the supplied event set. Validate evidence and suggested steps before taking action.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-lab",
        description="Analyze normalized or Wazuh JSONL events and create correlated incident reports.",
    )
    parser.add_argument("events", type=Path, help="input JSONL event file")
    parser.add_argument(
        "--format", choices=("normalized", "wazuh"), default="normalized",
        help="input event format (default: normalized)",
    )
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="JSON detection rules file")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="report output directory")
    parser.add_argument(
        "--correlation-minutes", type=float, default=30.0, help="alert correlation window (default: 30)"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        events = load_events(args.events, args.format)
        rules = load_rules(args.rules)
        alerts = run_detections(events, rules)
        cases = correlate_alerts(alerts, args.correlation_minutes)
        coverage = build_attack_coverage(rules, alerts)
        args.out.mkdir(parents=True, exist_ok=True)
        _write_json(args.out / "alerts.json", alerts)
        _write_json(args.out / "cases.json", cases)
        _write_json(args.out / "attack_coverage.json", coverage)
        _write_summary(args.out / "summary.md", alerts, cases, args.format, coverage)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"soc-lab: {exc}", file=sys.stderr)
        return 2

    print(f"Analyzed {len(events)} event(s); created {len(alerts)} alert(s) and {len(cases)} case(s).")
    print(f"Reports: {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
