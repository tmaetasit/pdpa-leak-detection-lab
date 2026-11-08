import json
import random

import pytest

from datagen.generate import fake_invalid_13, fake_valid_id, generate
from scanner.scan import scan_file, severity_for
from scanner.thai_id import find_thai_ids, is_valid_thai_id, mask

# Generated with the checksum formula; not a real person's number.
VALID = "1101700230708"


def test_checksum_accepts_valid_and_rejects_changed_digit():
    assert is_valid_thai_id(VALID)
    assert not is_valid_thai_id(VALID[:-1] + str((int(VALID[-1]) + 1) % 10))


def test_rejects_wrong_length_and_bad_first_digit():
    assert not is_valid_thai_id("123")
    assert not is_valid_thai_id("0" + VALID[1:])


def test_generated_ids_follow_the_rule():
    rng = random.Random(1)
    assert all(is_valid_thai_id(fake_valid_id(rng)) for _ in range(500))
    assert not any(is_valid_thai_id(fake_invalid_13(rng)) for _ in range(500))


@pytest.mark.parametrize("written", [VALID, "1-1017-00230-70-8", "1 1017 00230 70 8"])
def test_finds_common_formats(written):
    assert find_thai_ids(f"ลูกค้า {written} โทร 0812345678").valid == ["1-XXXX-XXXXX-XX-8"]


def test_ignores_digits_inside_longer_numbers():
    assert find_thai_ids("ref 99" + VALID + "99").candidate_count == 0


def test_checksum_filters_decoys():
    text = f"{VALID} order 1234567890123"
    assert len(find_thai_ids(text, use_checksum=False).valid) == 2
    f = find_thai_ids(text)
    assert len(f.valid) == 1 and f.invalid_count == 1


def test_mask_never_shows_middle_digits():
    m = mask(VALID)
    assert VALID[1:12] not in m.replace("-", "")


def test_severity_thresholds():
    assert [severity_for(n) for n in (0, 1, 10, 50)] == ["none", "low", "high", "critical"]


def test_generator_and_scanner_agree_on_every_file(tmp_path):
    truth = generate(tmp_path, count=40, seed=7)
    for name, info in truth.items():
        ev = scan_file(tmp_path / name)
        # Random business numbers that pass the checksum by chance are reported too:
        # that is the known limit of checksum-only detection.
        assert ev["match_count"] == info["valid_ids"] + info["decoys_passing_checksum"], name


def test_event_never_contains_full_id(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text(f"สมชาย {VALID}", encoding="utf-8")
    ev = scan_file(p, location_type="usb")
    assert ev["event"] == "pii_detected" and ev["location_type"] == "usb"
    assert VALID not in json.dumps(ev)


def test_tis620_csv(tmp_path):
    p = tmp_path / "thai.csv"
    p.write_bytes(f"ชื่อ,เลข\nสมหญิง,{VALID}\n".encode("cp874"))
    assert scan_file(p)["match_count"] == 1
