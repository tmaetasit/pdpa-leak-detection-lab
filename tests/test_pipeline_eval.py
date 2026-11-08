import json

from datagen.pipeline_eval import load_alerts, score


def _alert(file, rule, level, ts="2026-11-08T15:41:00+00:00"):
    return json.dumps({"rule": {"id": rule, "level": level},
                       "data": {"file": file, "timestamp": ts, "location_type": "web_upload"}})


def test_scores_pipeline(tmp_path):
    truth = {
        "a_pii.csv": {"kind": "pii", "valid_ids": 120},
        "b_pii.csv": {"kind": "pii", "valid_ids": 3},
        "c_decoy.txt": {"kind": "decoy", "valid_ids": 0},
        "d_clean.docx": {"kind": "clean", "valid_ids": 0},
        "e_pii.csv": {"kind": "pii", "valid_ids": 25},
    }
    lines = [
        _alert("a_pii.csv", "100122", 12),
        _alert("b_pii.csv", "100124", 7),
        _alert("c_decoy.txt", "100124", 7),          # a decoy that passed the checksum: low only
        _alert("d_clean.docx", "100141", 5),
        _alert("e_pii.csv", "100123", 12, ts="2026-11-08T15:00:00+00:00"),  # before the run: ignored
    ]
    p = tmp_path / "alerts.json"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = score(truth, load_alerts(p, "2026-11-08T15:40:00"))
    assert r["pii_detected"] == 2 and r["missed_pii"] == 1
    assert r["false_id_alert"] == 1 and r["clean_correct"] == 1
    assert r["paged"] == 1 and r["page_precision"] == 1.0 and r["should_page"] == 2
