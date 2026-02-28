"""Command-line interface for SigmaSage vertical slice."""

from __future__ import annotations

import argparse
import sys

from sigmasage.alerts.writer import write_alert_bundle
from sigmasage.engine.evaluator import evaluate_events, load_events
from sigmasage.rules.compiler import compile_rules
from sigmasage.rules.parser import load_rules


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate Sigma-style rules against JSON/NDJSON logs")
    parser.add_argument("rules", nargs="+", help="Rule file(s) or directories")
    parser.add_argument("--input", required=True, help="Input JSON/NDJSON log file")
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for alerts/evidence, or an alerts .json file path",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        parsed_rules = load_rules(args.rules)
        compiled_rules = compile_rules(parsed_rules)
        events = load_events(args.input)
        alerts = evaluate_events(events, compiled_rules)
        alerts_path, evidence_path = write_alert_bundle(alerts, args.output)
    except Exception as exc:  # noqa: BLE001 - CLI should surface failures as concise messages.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Loaded {len(compiled_rules)} rule(s), evaluated {len(events)} event(s), "
        f"generated {len(alerts)} alert(s)."
    )
    print(f"Alerts: {alerts_path}")
    print(f"Evidence: {evidence_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
