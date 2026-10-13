#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PCAP = ROOT / "data" / "bfd-raw-auth-simple.pcap"
OUTPUT = ROOT / "reports" / "analysis_summary.json"


def run_tshark(args):
    command = ["tshark", "-r", str(PCAP), *args]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def main():
    if not PCAP.is_file():
        sys.exit(f"Capture not found: {PCAP}")

    try:
        raw_count = run_tshark(["-T", "fields", "-e", "frame.number"])
        packet_numbers = [line for line in raw_count.splitlines() if line]
        hierarchy = run_tshark(["-q", "-z", "io,phs"])

        rows = run_tshark([
            "-Y", "bfd",
            "-T", "fields",
            "-E", "separator=|",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "udp.dstport",
            "-e", "bfd.sta",
            "-e", "bfd.diag",
            "-e", "bfd.flags",
            "-e", "bfd.auth.type",
            "-e", "bfd.auth.len",
        ])

        packets = []
        for row in rows.splitlines():
            fields = row.split("|")
            fields += [""] * (8 - len(fields))
            packets.append({
                "source_ip": fields[0],
                "destination_ip": fields[1],
                "udp_destination_port": fields[2],
                "bfd_state": fields[3],
                "bfd_diagnostic": fields[4],
                "bfd_flags": fields[5],
                "authentication_type": fields[6],
                "authentication_length": fields[7],
            })

        summary = {
            "capture_file": str(PCAP.relative_to(ROOT)),
            "total_frames": len(packet_numbers),
            "bfd_packet_count": len(packets),
            "protocol_hierarchy": hierarchy.strip(),
            "bfd_observations": packets,
            "limitations": [
                "Analysis is limited to the supplied PCAP.",
                "Packet fields alone do not prove an attack or a compromised credential.",
            ],
        }

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Frames analyzed: {len(packet_numbers)}")
        print(f"BFD packets analyzed: {len(packets)}")
        print(f"Summary saved to: {OUTPUT.relative_to(ROOT)}")

    except FileNotFoundError:
        sys.exit("TShark was not found. Install Wireshark/TShark first.")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"TShark failed: {exc.stderr.strip()}")


if __name__ == "__main__":
    main()
