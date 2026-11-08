"""Score the whole pipeline (endpoint -> mini SWG -> Wazuh rules) on the test set.

datagen/evaluate.py scores the scanner alone. This script scores what an
analyst would actually see: the Wazuh alerts raised when every test file is
uploaded through the SWG to a lab site. Each file is matched to its alert by
name and compared with the ground truth.

Run on the Wazuh manager after the upload run (alerts.json needs root):
    sudo .venv/bin/python -m datagen.pipeline_eval \
        --truth /tmp/testdata/ground_truth.json \
        --alerts /var/ossec/logs/alerts/alerts.json --since 2026-11-08T15:40:00
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from scanner.scan import severity_for

# What each web-upload rule means for an analyst.
PAGE = {"100122", "100123"}          # level 12: someone looks at it now
LOW = {"100110", "100124"}           # level 5-7: logged, reviewed in bulk
HIGH_SANCTIONED = {"100111"}         # level 10
NO_ID = {"100140", "100141"}         # upload seen, no Thai ID found
WEB_RULES = PAGE | LOW | HIGH_SANCTIONED | NO_ID


def load_alerts(path: Path, since: str) -> dict[str, dict]:
    """Latest web-upload alert per file name, from alerts at or after `since` (UTC, ISO)."""
    by_file: dict[str, dict] = {}
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"web_upload"' not in line:
                continue
            a = json.loads(line)
            if a["rule"]["id"] not in WEB_RULES:
                continue
            ts = a.get("data", {}).get("timestamp", a.get("timestamp", ""))
            if ts[:19] < since[:19]:
                continue
            by_file[a["data"]["file"]] = {"rule": a["rule"]["id"], "level": int(a["rule"]["level"])}
    return by_file


def score(truth: dict, alerts: dict[str, dict]) -> dict:
    c = Counter()
    for name, info in truth.items():
        valid = info["valid_ids"]
        expected = severity_for(valid)            # none / low / high / critical
        got = alerts.get(name)
        rule = got["rule"] if got else None
        c["files"] += 1
        c[f"truth_{info['kind']}"] += 1
        if got is None:
            c["no_alert"] += 1
            c["missed_pii"] += valid > 0
            continue
        has_id_alert = rule not in NO_ID
        if valid and has_id_alert:
            c["pii_detected"] += 1
        elif valid and not has_id_alert:
            c["missed_pii"] += 1
        elif not valid and has_id_alert:
            c["false_id_alert"] += 1
        else:
            c["clean_correct"] += 1
        if rule in PAGE:
            c["paged"] += 1
            if expected in ("high", "critical"):
                c["paged_correct"] += 1
            else:
                c["paged_false"] += 1
        if expected in ("high", "critical") and rule not in PAGE:
            c["should_page_missed"] += 1
    pii_total = sum(1 for v in truth.values() if v["valid_ids"])
    should_page = sum(1 for v in truth.values() if severity_for(v["valid_ids"]) in ("high", "critical"))
    return {
        **dict(c),
        "pii_files": pii_total,
        "should_page": should_page,
        "recall_any_alert": round(c["pii_detected"] / pii_total, 4) if pii_total else None,
        "page_precision": round(c["paged_correct"] / c["paged"], 4) if c["paged"] else None,
        "page_recall": round(c["paged_correct"] / should_page, 4) if should_page else None,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score the end-to-end pipeline from Wazuh alerts")
    ap.add_argument("--truth", type=Path, required=True)
    ap.add_argument("--alerts", type=Path, default=Path("/var/ossec/logs/alerts/alerts.json"))
    ap.add_argument("--since", required=True, help="UTC ISO time the upload run started")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    truth = json.loads(args.truth.read_text(encoding="utf-8"))
    result = score(truth, load_alerts(args.alerts, args.since))
    text = json.dumps(result, indent=1, ensure_ascii=False)
    print(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
