# SWYNEX Network Security Analysis

## Overview
A defensive network traffic analysis project completed using Kali Linux,
Wireshark, TShark, and Python.

## Objective
Analyze a sample BFD packet capture, extract protocol metadata, summarize
observations, and document findings without claiming unsupported attacks
or vulnerabilities.

## Tools
- Kali Linux
- Wireshark
- TShark
- Python 3

## Methodology
1. Inspect the capture with Wireshark.
2. Review protocol hierarchy statistics using TShark.
3. Extract BFD packet metadata.
4. Export a packet summary to CSV.
5. Generate a JSON summary using Python.
6. Document observations, limitations, and recommendations.

## Findings
- 15 frames totaling 1,185 bytes.
- Observed protocol layers: Ethernet, IPv4, UDP, and BFD.
- Source IP: `192.85.1.2`.
- Destination IP: `192.0.0.1`.
- UDP destination port: `3784`.
- BFD authentication metadata was present in the extracted fields.

These observations describe the supplied sample only. They do not establish
a successful attack, credential compromise, or a confirmed vulnerability.

## Project Files
- `scripts/analyze_pcap.py` — Python analysis script.
- `reports/Network_Security_Analysis_Report.md` — written report.
- `reports/analysis_summary.json` — machine-readable analysis output.
- `reports/packet-summary.csv` — packet metadata.
- `reports/protocol-hierarchy.txt` — protocol hierarchy output.
- `evidence/` — project screenshots.

## Run the Analysis
Place your authorized sample capture at
`data/bfd-raw-auth-simple.pcap`, then run:

```bash
python3 scripts/analyze_pcap.py
