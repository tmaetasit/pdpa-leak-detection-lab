"""Score the scanner against ground truth, with and without the checksum.

This produces the before/after numbers for the case study.

Usage:
    python -m datagen.evaluate --data testdata --out results.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scanner.extract import extract_text
from scanner.scan import severity_for
from scanner.thai_id import find_thai_ids


def evaluate(data: Path, use_checksum: bool) -> dict:
    truth = json.loads((data / "ground_truth.json").read_text(encoding="utf-8"))
    tp = fp = fn = tn = 0
    exact_counts = 0
    false_ids = 0
    fp_alerting = 0   # false positives at high/critical: the ones that would page an analyst
    for name, info in truth.items():
        text = extract_text(data / name)
        found = len(find_thai_ids(text, use_checksum=use_checksum).valid)
        actual = info["valid_ids"]
        if found and actual:
            tp += 1
        elif found and not actual:
            fp += 1
            fp_alerting += severity_for(found) in ("high", "critical")
        elif not found and actual:
            fn += 1
        else:
            tn += 1
        exact_counts += found == actual
        false_ids += max(found - actual, 0)
    total = len(truth)
    return {
        "mode": "regex + checksum" if use_checksum else "regex only",
        "files": total,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_ids_reported": false_ids,
        "false_positive_high_or_critical": fp_alerting,
        "exact_count_files": exact_counts,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score the scanner on a synthetic test set")
    ap.add_argument("--data", type=Path, default=Path("testdata"))
    ap.add_argument("--out", type=Path, default=Path("results.json"))
    args = ap.parse_args(argv)

    results = [evaluate(args.data, False), evaluate(args.data, True)]
    args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("| Mode | Files | False-positive files | ...of which high/critical | Missed files | Precision | Recall | False IDs reported |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in results:
        print(f"| {r['mode']} | {r['files']} | {r['false_positive']} | {r['false_positive_high_or_critical']} | {r['false_negative']} | "
              f"{r['precision']:.1%} | {r['recall']:.1%} | {r['false_ids_reported']} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
