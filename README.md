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
- Intercepting communications on networks you don't own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
