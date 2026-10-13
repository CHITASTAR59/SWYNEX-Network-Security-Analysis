# Network Security Analysis Methodology

## 1. Objective
Analyze an authorized sample packet capture, identify the observed
protocols and BFD metadata, export structured results, and document
security-relevant observations without overstating the evidence.

## 2. Scope
- Input: data/bfd-raw-auth-simple.pcap
- Observed traffic: BFD over UDP, carried by IPv4 and Ethernet
- Tools: Kali Linux, Wireshark, TShark, Python 3
- Scope limitation: one supplied 15-frame capture

## 3. Workflow
1. Confirm that the capture file exists.
2. Inspect the capture in Wireshark.
3. Generate protocol hierarchy statistics with TShark.
4. Extract packet timestamps, IP addresses, UDP ports, and BFD fields.
5. Export packet metadata to CSV.
6. Run the Python analysis script to create a JSON summary.
7. Compare the generated results with the original TShark output.
8. Record observations, limitations, and defensive recommendations.
9. Review all artifacts for secrets before publication.

## 4. Commands Used
```bash
tshark -r data/bfd-raw-auth-simple.pcap -q -z io,phs

tshark -r data/bfd-raw-auth-simple.pcap \
  -Y bfd -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src -e ip.dst \
  -e udp.srcport -e udp.dstport \
  -e bfd.version -e bfd.sta -e bfd.diag \
  -e bfd.flags -e bfd.auth.type -e bfd.auth.len

python3 scripts/analyze_pcap.py
python3 -m json.tool reports/analysis_summary.json
