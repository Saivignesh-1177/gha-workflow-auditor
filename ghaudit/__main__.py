"""CLI.

  python -m ghaudit .github/workflows               human-readable report
  python -m ghaudit .github/workflows --sarif out.sarif   for GitHub code scanning
  --fail-on high    exit 1 if any finding is at or above this severity (default: high)
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

from .checks import ALL_CHECKS, Finding

ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}


def audit_file(path: Path) -> list[Finding]:
    raw = path.read_text(encoding="utf-8")
    wf = yaml.safe_load(raw) or {}
    if not isinstance(wf, dict):
        return []
    return [f for check in ALL_CHECKS for f in check(wf, raw)]


def collect(target: Path) -> dict[Path, list[Finding]]:
    files = [target] if target.is_file() else sorted([*target.rglob("*.yml"), *target.rglob("*.yaml")])
    return {p: audit_file(p) for p in files}


def to_sarif(results: dict[Path, list[Finding]]) -> dict:
    rules = sorted({f.rule for fs in results.values() for f in fs})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "ghaudit", "version": "0.1.0",
                                "rules": [{"id": r, "name": r} for r in rules]}},
            "results": [{
                "ruleId": f.rule, "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"[{f.severity}] {f.message}" + (f" (job: {f.job})" if f.job else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": p.as_posix()},
                                                    "region": {"startLine": 1}}}],
            } for p, fs in results.items() for f in fs],
        }],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ghaudit", description="GitHub Actions security auditor")
    ap.add_argument("target", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--fail-on", default="high", choices=list(ORDER))
    args = ap.parse_args(argv)

    results = collect(args.target)
    worst = -1
    for path, findings in results.items():
        print(f"{path.as_posix()}: {len(findings)} finding(s)")
        for f in sorted(findings, key=lambda f: -ORDER[f.severity]):
            loc = "/".join(x for x in (f.job, f.step) if x)
            print(f"  {f.severity.upper():8} {f.rule} {loc}\n           {f.message}")
            worst = max(worst, ORDER[f.severity])
    if args.sarif:
        args.sarif.write_text(json.dumps(to_sarif(results), indent=2), encoding="utf-8")
    return 1 if worst >= ORDER[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
