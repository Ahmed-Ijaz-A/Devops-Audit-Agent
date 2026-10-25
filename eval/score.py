"""Score agent reports against the fixture answer keys (precision and recall).

    python eval/score.py report-obvious.json report-subtle.json report-healthy.json

Each report's key is chosen from its "repository" URL: .../devops-fixture-subtle uses eval/keys/devops-fixture-subtle.json.

A reported violation matches a known defect when the category is one the key accepts, the file matches, the line (if
both give one) is within LINE_TOLERANCE of an expected line, and, where the key lists keywords, the description,
evidence, or rule id mentions one of them. Each defect can be matched once; a second report of it is a duplicate.
Optional defects are defensible extras: matching one is neither rewarded nor counted against precision.

precision = matched defects / (reported - optional matches)      recall = matched defects / known defects
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent / "keys"
LINE_TOLERANCE = 3


def _text(violation: dict) -> str:
    return " ".join(str(violation.get(field) or "") for field in ("rule_id", "description", "evidence")).lower()


def _keyword_hits(violation: dict, entry: dict) -> int:
    text = _text(violation)
    return sum(1 for keyword in entry.get("keywords", []) if keyword.lower() in text)


def _matches(violation: dict, entry: dict) -> bool:
    if violation.get("category") not in entry["categories"]:
        return False
    reported_file = violation.get("file")
    if entry.get("file") is not None:
        allowed = {entry["file"], *entry.get("alt_files", [])}
        if reported_file not in allowed and not (entry.get("file_optional") and reported_file is None):
            return False
    line = violation.get("line")
    if entry.get("lines") and line is not None and reported_file == entry.get("file"):
        if min(abs(line - expected) for expected in entry["lines"]) > LINE_TOLERANCE:
            return False
    return not entry.get("keywords") or _keyword_hits(violation, entry) > 0


def score(report: dict, key: dict) -> dict:
    expected = key["expected"]
    matched: dict[str, dict] = {}
    rows = []
    for violation in report.get("violations", []):
        candidates = [entry for entry in expected if _matches(violation, entry)]
        fresh = [entry for entry in candidates if entry["id"] not in matched]
        # Prefer a required defect over an optional one, then the best keyword match.
        fresh.sort(key=lambda entry: (bool(entry.get("optional")), -_keyword_hits(violation, entry)))
        if fresh:
            entry = fresh[0]
            matched[entry["id"]] = violation
            outcome = "optional" if entry.get("optional") else "TP"
            rows.append((outcome, entry["id"], violation))
        elif candidates:
            rows.append(("duplicate", candidates[0]["id"], violation))
        else:
            rows.append(("FP", "-", violation))
    required = [entry for entry in expected if not entry.get("optional")]
    true_positives = sum(1 for outcome, _, _ in rows if outcome == "TP")
    optional = sum(1 for outcome, _, _ in rows if outcome == "optional")
    counted = len(rows) - optional
    return {
        "rows": rows,
        "missed": [entry["id"] for entry in required if entry["id"] not in matched],
        "tp": true_positives,
        "counted": counted,
        "known": len(required),
        "precision": true_positives / counted if counted else 1.0,
        "recall": true_positives / len(required) if required else 1.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", nargs="+", help="Agent report JSON files")
    args = parser.parse_args()
    total_tp = total_counted = total_known = 0
    for path in args.reports:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        name = report["repository"].rstrip("/").rsplit("/", 1)[-1].lower()
        key_path = KEYS_DIR / f"{name}.json"
        if not key_path.exists():
            print(f"{path}: no answer key {key_path.name}; skipped", file=sys.stderr)
            continue
        result = score(report, json.loads(key_path.read_text(encoding="utf-8")))
        print(f"\n== {name}  ({path})")
        for outcome, defect, violation in result["rows"]:
            location = f"{violation.get('file')}:{violation.get('line')}"
            print(f"  {outcome:<9} {defect:<30} {violation.get('rule_id', '?'):<9} {location:<40} {violation.get('description', '')[:70]}")
        for defect in result["missed"]:
            print(f"  {'MISSED':<9} {defect}")
        print(f"  precision {result['precision']:.2f} ({result['tp']}/{result['counted']})   recall {result['recall']:.2f} ({result['tp']}/{result['known']})")
        total_tp += result["tp"]
        total_counted += result["counted"]
        total_known += result["known"]
    if total_counted or total_known:
        precision = total_tp / total_counted if total_counted else 1.0
        recall = total_tp / total_known if total_known else 1.0
        print(f"\nOVERALL precision {precision:.2f} ({total_tp}/{total_counted})   recall {recall:.2f} ({total_tp}/{total_known})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
