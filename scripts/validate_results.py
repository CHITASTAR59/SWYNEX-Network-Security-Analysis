#!/usr/bin/env python3

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
summary_file = ROOT / "reports" / "analysis_summary.json"
csv_file = ROOT / "reports" / "packet-summary.csv"

with summary_file.open(encoding="utf-8") as file:
    summary = json.load(file)

with csv_file.open(newline="", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))

checks = {
    "JSON reports 15 frames": summary.get("total_frames") == 15,
    "JSON reports 15 BFD packets": summary.get("bfd_packet_count") == 15,
    "CSV contains 15 packet rows": len(rows) == 15,
    "CSV includes BFD protocol": all(
        row.get("_ws.col.protocol") == "BFD Control" for row in rows
    ),
    "PCAP excluded from publication": not any(
        path.name.endswith((".pcap", ".pcapng", ".cap"))
        for path in ROOT.glob("*.pcap*")
    ),
}

for label, passed in checks.items():
    print(f"[{'PASS' if passed else 'FAIL'}] {label}")

if not all(checks.values()):
    raise SystemExit(1)

print("All validation checks passed.")
