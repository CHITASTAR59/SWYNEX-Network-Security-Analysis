# SWYNEX Network Security Analysis Report

## 1. Executive Summary

This project analyzes an approved BFD packet capture using Kali Linux, Wireshark, and TShark.

## 2. Environment

- Operating system: Kali Linux
- Packet analyzer: Wireshark
- Command-line analyzer: TShark
- Capture: `bfd-raw-auth-simple.pcap`

## 3. Protocol Statistics

The initial protocol hierarchy reports 15 frames and 1,185 bytes. The observed protocol layers are Ethernet, IPv4, UDP, and BFD.

These are nested protocol counts, not independent traffic totals.

## 4. Observations

-The capture contains 15 BFD control packets over Ethernet, IPv4, and UDP.
-All observed packets travel from 192.85.1.2 to 192.0.0.1.
-The UDP source port is 1024, and the destination port is 3784.
-Packets occur at 0.2-second intervals, from 0.0 to 2.8 seconds.
-The decoded BFD version is 1; the state field is 0x01, diagnostic field is 0x00, and flags field is 0x44 in all 15 packets.
-The authentication metadata fields show type 1 and length 9. These values are consistent with Simple Password authentication encoding; the capture alone does not establish whether authentication was successfully enforced or whether any credential was compromised.
-No attack or vulnerability is confirmed by these observations alone.

## 5. Security Assessment

BFD state transitions and authentication configuration can be important to network availability and security.

The presence of BFD traffic alone does not establish a vulnerability or malicious activity. Any concern must be supported by packet evidence and appropriate configuration context.

## 6. Recommendations

- Verify that BFD peers are authorized.
- Review BFD session state and relevant device logs.
- Check authentication settings against the network's security requirements.
- Protect packet captures and redact sensitive authentication material.
- Retain sanitized evidence for review.

## 7. Limitations

The assessment covers only the supplied 15-packet capture. It does not establish the security of the complete network or confirm an attack.

## 8. Evidence

- `reports/protocol-hierarchy.txt`
- `reports/packet-summary.csv`
- Sanitized screenshots in `evidence/`

## 9. Conclusion
 
The sample PCAP was analyzed using Kali Linux and TShark. The capture contains 15 BFD control packets exchanged from 192.85.1.2 to 192.0.0.1 over UDP destination port 3784, spanning 2.8 seconds from the first to the last packet.

The extracted fields show BFD version 1, state value 0x01, diagnostic value 0x00, authentication type value 1, and authentication length value 9 across the observed packets. These observations are consistent with BFD Simple Password authentication being used in the sample. However, the available evidence does not establish credential compromise or an attack.

Recommended next steps include validating the authentication configuration, protecting packet captures that may contain sensitive data, and reviewing relevant device logs and configuration to determine whether authentication is appropriately enforced. The findings apply only to this sample capture and do not establish the security posture of a live network.
