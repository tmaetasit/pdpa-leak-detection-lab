"""Generate a synthetic test set: files with fake Thai PII, decoys, and clean files.

Every ID is generated, never real. Each file's true count of valid IDs is
written to ground_truth.json so the scanner can be scored.

File mix (by default 1,000 files):
  - pii      : 1-120 valid IDs among names and phone numbers
  - decoy    : 13-digit numbers that FAIL the checksum (order IDs, tracking numbers)
  - clean    : business text with no 13-digit numbers

Usage:
    python -m datagen.generate --out testdata --count 1000 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from scanner.thai_id import checksum_digit, is_valid_thai_id

FIRST = ["สมชาย", "สมหญิง", "วิชัย", "สุดา", "ประเสริฐ", "อรุณี", "ธนพล", "กมลวรรณ", "ณัฐวุฒิ", "พิมพ์ชนก",
         "อนุชา", "ศิริพร", "กิตติพงษ์", "จันทร์เพ็ญ", "ปิยะ", "รัตนา"]
LAST = ["ใจดี", "รักไทย", "ศรีสุข", "บุญมา", "ทองคำ", "แสงทอง", "วงศ์ใหญ่", "มีสุข", "พรหมมา", "สายบุญ"]
DEPTS = ["ฝ่ายขาย", "ฝ่ายบัญชี", "ฝ่ายบุคคล", "ฝ่ายบริการลูกค้า", "ฝ่ายไอที"]
CLEAN_LINES = [
    "สรุปยอดขายประจำไตรมาส 3 เพิ่มขึ้น 12% จากไตรมาสก่อน",
    "ประชุมทีมทุกวันจันทร์ เวลา 10:00 น. ห้อง 4B",
    "Meeting notes: migrate file server to new NAS by end of month.",
    "ราคาสินค้า SKU-2291 ปรับเป็น 1,250 บาท มีผล 1 ธ.ค.",
    "Reminder: update antivirus signatures on all branch PCs.",
]
TYPES = [".txt", ".csv", ".xlsx", ".docx"]


def fake_valid_id(rng: random.Random) -> str:
    first12 = str(rng.randint(1, 8)) + "".join(str(rng.randint(0, 9)) for _ in range(11))
    return first12 + str(checksum_digit(first12))


def fake_invalid_13(rng: random.Random) -> str:
    """A 13-digit number guaranteed to fail the Thai ID check (a realistic decoy)."""
    first12 = str(rng.randint(1, 8)) + "".join(str(rng.randint(0, 9)) for _ in range(11))
    good = checksum_digit(first12)
    bad = (good + rng.randint(1, 9)) % 10
    return first12 + str(bad)


def fmt_id(number: str, rng: random.Random) -> str:
    """Write IDs the way people do: plain, dashed or spaced."""
    style = rng.choice(["plain", "dash", "space"])
    if style == "plain":
        return number
    sep = "-" if style == "dash" else " "
    return sep.join([number[0], number[1:5], number[5:10], number[10:12], number[12]])


def phone(rng: random.Random) -> str:
    return "0" + rng.choice("689") + "".join(str(rng.randint(0, 9)) for _ in range(8))


def person_rows(n: int, rng: random.Random) -> list[list[str]]:
    rows = []
    for _ in range(n):
        rows.append([f"{rng.choice(FIRST)} {rng.choice(LAST)}", fmt_id(fake_valid_id(rng), rng),
                     phone(rng), rng.choice(DEPTS)])
    return rows


def random_13(rng: random.Random) -> str:
    """A business number with no relation to Thai IDs. About 1 in 10 passes the checksum by chance."""
    return str(rng.randint(1, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(12))


def decoy_rows(n: int, rng: random.Random) -> list[list[str]]:
    # Decoys are truly random, NOT forced to fail the checksum, so the
    # evaluation shows the false positives the checksum alone cannot remove.
    rows = []
    for i in range(n):
        label = rng.choice(["Order", "Tracking", "Invoice ref", "Account"])
        rows.append([f"{label} #{i + 1}", fmt_id(random_13(rng), rng), f"{rng.randint(100, 99999)} THB", "pending"])
    return rows


def clean_rows(n: int, rng: random.Random) -> list[list[str]]:
    return [[rng.choice(CLEAN_LINES), "", "", ""] for _ in range(n)]


HEADER = ["ชื่อ-สกุล / รายการ", "เลขอ้างอิง", "ติดต่อ / จำนวน", "หมายเหตุ"]


def write_file(path: Path, rows: list[list[str]], rng: random.Random) -> None:
    ext = path.suffix
    if ext == ".txt":
        path.write_text("\n".join("  ".join(r).strip() for r in rows), encoding="utf-8")
    elif ext == ".csv":
        # Some Thai CSVs arrive as TIS-620 (cp874): mix both to test decoding.
        enc = rng.choice(["utf-8-sig", "cp874"])
        with path.open("w", newline="", encoding=enc) as f:
            w = csv.writer(f)
            w.writerow(HEADER)
            w.writerows(rows)
    elif ext == ".xlsx":
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.append(HEADER)
        for r in rows:
            ws.append(r)
        wb.save(path)
    elif ext == ".docx":
        from docx import Document
        doc = Document()
        doc.add_heading("รายงานภายใน (ข้อมูลทดสอบ)", level=1)
        table = doc.add_table(rows=1, cols=4)
        for i, h in enumerate(HEADER):
            table.rows[0].cells[i].text = h
        for r in rows:
            cells = table.add_row().cells
            for i, v in enumerate(r):
                cells[i].text = v
        doc.save(str(path))


def generate(out: Path, count: int, seed: int) -> dict:
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    truth = {}
    for i in range(count):
        kind = rng.choices(["pii", "decoy", "clean"], weights=[40, 35, 25])[0]
        ext = TYPES[i % len(TYPES)]
        name = f"{i:04d}_{kind}{ext}"
        decoys: list[list[str]] = []
        if kind == "pii":
            # Skewed so most files hold a few records and some hold a lot (bulk export).
            n = rng.choice([1, 2, 3, 5, 8, 12, 25, 60, 120])
            decoys = decoy_rows(rng.randint(0, 5), rng)
            rows = person_rows(n, rng) + decoys
            rng.shuffle(rows)
            valid = n
        elif kind == "decoy":
            decoys = decoy_rows(rng.randint(3, 40), rng)
            rows = decoys + clean_rows(rng.randint(0, 5), rng)
            valid = 0
        else:
            rows = clean_rows(rng.randint(5, 30), rng)
            valid = 0
        write_file(out / name, rows, rng)
        truth[name] = {
            "kind": kind,
            "valid_ids": valid,  # real (synthetic) people in the file
            "decoys_passing_checksum": sum(is_valid_thai_id(r[1]) for r in decoys),
        }
    (out / "ground_truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "README.txt").write_text("SYNTHETIC TEST DATA ONLY. Every ID here is generated; none belong to a real person.\n",
                                    encoding="utf-8")
    return truth


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic Thai PII test files")
    ap.add_argument("--out", type=Path, default=Path("testdata"))
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    truth = generate(args.out, args.count, args.seed)
    kinds = {k: sum(1 for v in truth.values() if v["kind"] == k) for k in ("pii", "decoy", "clean")}
    print(f"wrote {len(truth)} files to {args.out}: {kinds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
