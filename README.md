# W2 — WiFi Deauth Detector

Real-time WiFi deauthentication and disassociation frame detection with threat alerting.

## Overview

This project implements a standalone deauth detector that:
- Monitors WiFi traffic in promiscuous mode for deauth/disassoc frames
- Tracks offending MAC addresses and attack counts
- Escalates threat levels based on deauth rate (normal → warning → critical)
- Channels hop to cover all 2.4 GHz spectrum
- Provides detailed reason code analysis

## Hardware

| Component | Connection | Role |
|-----------|------------|------|
| ESP32-C6 Dev Board | Main board | Promiscuous WiFi monitoring |

## Alert Levels

| Level | Threshold | Meaning |
|-------|-----------|---------|
| NORMAL | < 5 deauth/s | Background noise |
| WARNING | 5-19 deauth/s | Possible attack |
| CRITICAL | ≥ 20 deauth/s | Active deauth attack |

## Serial Output

```
+----------------------------------------------+
|    W2 WiFi Deauth Detector                   |
|    Board: ESP32-C6                           |
+----------------------------------------------+
Promiscuous mode active on channel 1

[DEAUTH ] src=AA:BB:CC:DD:EE:FF -> 11:22:33:44:55:66 reason=7 (Class 3 frame from non-assoc STA)

+==============================================+
|      W2 Deauth Detector - Status Report      |
+==============================================+
| Threat Level: WARNING                        |
| Total Deauth:    12                          |
| Total Disassoc:  3                           |
+----------------------------------------------+
```

## Build & Flash

```bash
arduino-cli compile --fqbn esp32:esp32:esp32c6 firmware/
arduino-cli upload --fqbn esp32:esp32:esp32c6 --port /dev/ttyUSB0 firmware/
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Deploying this defense on networks you don't own without written authorization
- Transmitting deauth frames with any tooling derived from this repository
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### Regulatory Framework
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with authorized radio communications is prohibited — this defense never emits radio.
- **47 CFR Part 15**: Unauthorized intentional radiators are regulated; this detector parses bytes only.
- **CFAA / ECPA / Wiretap Act**: Monitoring wireless traffic without authorization may violate federal interception and computer-access laws.

## Live Lab Test Plan

Offline (this repo, no radio):
1. `python3 firmware/deauth_detect.py` — synthesise the 16-deauth hit fixture (storm +
   locally-administered + broadcast-source forgeries) and detect all three (exit 0).
2. `python3 firmware/deauth_detect.py --gen-fixture reports/hit.pcap --pcap reports/hit.pcap
   --json reports/w2.json --threshold 5` — fixture round-trip + report (exit 0).
3. `python3 -m unittest discover -s tests` — byte-exact FCS/reason/address tests (exit 0).

Authorized lab (defender only):
4. Capture 60s of authorized lab traffic; feed pcap to `--pcap`, confirm storm thresholds and
   forged-SOURCE signatures match the lab's real APs.
5. `green = permitted`: passive deauth analysis on devices you own; injecting deauth is never
   part of this tool (a red-team repo is the place for that).

## Metrics

- Deauth parse (byte-exact): FC subtype verify, DA/SA/BSSID, seq, reason code, FCS verify
- Storm detection: per (da, sa) sliding window (default 1s) >= threshold (default 5) -> high
- Forgery signatures: broadcast SA (high), broadcast DA (medium), locally-administered SA not
  in the allowed-AP set (medium)
- Deterministic hit fixture: 16 deauth frames, lab MACs only, RETRY-flagged storm
- pcap classic (linktype 105) generate + analyze; captures/ and reports/ gitignored
- Defensive posture: radio_emitted always False; no deauth frames ever transmitted

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
