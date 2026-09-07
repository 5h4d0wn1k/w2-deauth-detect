#!/usr/bin/env python3
"""W2 — Deauth Detection (offscreen storm/spoof detector).

Byte-level defensive tool: parses deauth frames off the wire (pcap fixture),
validates each frame's CRC + reason-code + addressing, buckets frames by
target(DA) x source(SA) over a sliding window, and raises alerts for:

  * deauth storms        — >= threshold frames per target+source in a window
  * forged/broadcast deauth — broadcast DA or broadcast SA (classic spoof)
  * origin anomalies     — deauth with locally-administered SA

Passive analysis of bytes only; no deauth is ever transmitted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

START_TS = 1700000000.0
LAB_AP = "00:11:22:33:44:55"
LAB_AP2 = "00:11:22:33:44:56"
CLIENT = "00:11:22:33:44:66"
SPOOF_SA = "02:aa:bb:cc:dd:01"   # locally-administered (forged)


# ----------------------------------------------------------------------
# Byte-exact deauth fixture (defender viewpoint: what an attack looks like)
# ----------------------------------------------------------------------

def build_fixture_frames() -> list[dict]:
    """A hit deauth storm + one broadcast-source spoof, over lab MACs."""
    frames = []
    seq = 0
    # legitimate single deauths (AP -> client, reason 8 "disassociated")
    for i in range(2):
        seq = (seq + 1) & 0xFFFF
        d = fc.build_deauth(CLIENT, LAB_AP, LAB_AP, reason=8, seq_num=seq)
        frames.append({"ts": START_TS + 0.1 * i, "kind": "deauth",
                       "da": CLIENT, "sa": LAB_AP, "bssid": LAB_AP,
                       "data": d + fc.fcs(d), "reason": 8})
    # storm: repeated deauths from the real AP (reason 7, nonauth)
    for i in range(12):
        seq = (seq + 1) & 0xFFFF
        d = fc.build_deauth(CLIENT, LAB_AP, LAB_AP, reason=7, seq_num=seq,
                            flags=fc.FC_FLAG_RETRY)
        frames.append({"ts": START_TS + 2.0 + 0.05 * i, "kind": "deauth",
                       "da": CLIENT, "sa": LAB_AP, "bssid": LAB_AP,
                       "data": d + fc.fcs(d), "reason": 7})
    # forged: spoofed SA forged as the AP, broadcast DA
    seq = (seq + 1) & 0xFFFF
    d = fc.build_deauth(CLIENT, SPOOF_SA, LAB_AP2, reason=7, seq_num=seq)
    frames.append({"ts": START_TS + 3.0, "kind": "deauth",
                   "da": CLIENT, "sa": SPOOF_SA, "bssid": LAB_AP2,
                   "data": d + fc.fcs(d), "reason": 7})
    # broadcast-source spoof: SA = ff:ff:ff:ff:ff:ff
    seq = (seq + 1) & 0xFFFF
    d = fc.build_deauth(CLIENT, fc.BROADCAST_STR, LAB_AP, reason=7, seq_num=seq)
    frames.append({"ts": START_TS + 3.05, "kind": "deauth",
                   "da": CLIENT, "sa": fc.BROADCAST_STR, "bssid": LAB_AP,
                   "data": d + fc.fcs(d), "reason": 7})
    frames.sort(key=lambda f: f["ts"])
    return frames


def write_fixture(path: str) -> int:
    frames = build_fixture_frames()
    fc.write_pcap(path, [f["data"] for f in frames], ts=frames[0]["ts"])
    return len(frames)


# ----------------------------------------------------------------------
# Off-the-wire parser + detector
# ----------------------------------------------------------------------

def classify_deauth(data: bytes) -> dict:
    if not fc.verify_fcs(data):
        raise ValueError("bad FCS")
    payload = data[:-4]
    fields, _ = fc.parse_mgmt_header(payload)
    if fields["subtype_val"] != fc.FC_SUBTYPE_DEAUTH:
        raise ValueError("not a deauth")
    p = fc.parse_deauth(payload)
    return {
        "da": fields["da"], "sa": fields["sa"], "bssid": fields["bssid"],
        "seq": fields["seq_num"], "reason": p["reason_code"],
        "sa_locally_administered": fields["locally_administered_sa"],
        "da_broadcast": fields["is_broadcast"] or fields["da"] == fc.BROADCAST_STR,
        "sa_broadcast": fields["sa"] == fc.BROADCAST_STR,
        "retry": bool(fields["fc"].get("retry")),
    }


def read_fixture_pcap(path: str) -> list[dict]:
    out = []
    for rec in fc.read_pcap(path):
        try:
            f = classify_deauth(rec["data"])
            f["ts"] = rec["ts"]
            out.append(f)
        except ValueError:
            pass
    return out


def detect(frames: list[dict], window_sec: float = 1.0, storm_threshold: int = 5) -> dict:
    alerts = []
    by_key = defaultdict(list)
    for f in frames:
        key = (f["da"], f["sa"])
        by_key[key].append(f["ts"])
    for (da, sa), times in by_key.items():
        times.sort()
        for i in range(len(times)):
            burst = [t for t in times if 0 <= t - times[i] <= window_sec]
            if len(burst) >= storm_threshold:
                alerts.append({"type": "deauth_storm", "da": da, "sa": sa,
                               "count": len(burst), "window_sec": window_sec,
                               "severity": "high"})
                break
    for f in frames:
        if f["sa_broadcast"]:
            alerts.append({"type": "forged_deauth", "detail": "broadcast source SA",
                           "da": f["da"], "sa": f["sa"], "reason": f["reason"],
                           "severity": "high"})
        elif f["da_broadcast"]:
            alerts.append({"type": "forged_deauth", "detail": "broadcast DA",
                           "da": f["da"], "sa": f["sa"], "reason": f["reason"],
                           "severity": "medium"})
        elif f["sa_locally_administered"] and f["sa"] != LAB_AP:
            alerts.append({"type": "forged_deauth", "detail": "locally-administered SA",
                           "da": f["da"], "sa": f["sa"], "reason": f["reason"],
                           "severity": "medium"})
    return {
        "deauth_frames": len(frames),
        "radio_emitted": False,
        "alerts": alerts,
    }


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------

def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w2-deauth-detect",
        description="Deauth detector: parse deauth frames off the wire, CRC/reason/address "
                    "validation, storm + forged-source alerting. Pure-stdlib bytes; "
                    "defensive; no radio.")
    p.add_argument("--pcap", metavar="PATH", help="analyze a pcap fixture")
    p.add_argument("--gen-fixture", metavar="PATH", help="write the hit deauth fixture")
    p.add_argument("--window", type=float, default=1.0, help="storm window seconds")
    p.add_argument("--threshold", type=int, default=5, help="storm threshold")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    return p


def print_report(result: dict) -> None:
    print("=" * 62)
    print(" W2 — Deauth Detection (offscreen storm/spoof detector)")
    print("=" * 62)
    print(f"\n[+] deauth frames analysed: {result['deauth_frames']}   "
          f"radio_emitted={result['radio_emitted']}")
    print("--- alerts ---")
    for a in result["alerts"]:
        detail = a.get("detail", "")
        print(f"  [{a['severity'].upper():6s}] {a['type']}  da={a.get('da','')} "
              f"sa={a.get('sa','')}  {detail}")
    if not result["alerts"]:
        print("  (no alerts)")
    print("[+] defence analysis complete — no deauth frames were transmitted.")
    print("=" * 62)


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    if args.pcap:
        frames = read_fixture_pcap(args.pcap)
    else:
        frames = build_fixture_frames()
        frames = [{"ts": f["ts"], **classify_deauth(f["data"])} for f in frames]
    result = detect(frames, window_sec=args.window, storm_threshold=args.threshold)
    print_report(result)
    if args.gen_fixture:
        d = os.path.dirname(args.gen_fixture)
        if d:
            os.makedirs(d, exist_ok=True)
        n = write_fixture(args.gen_fixture)
        print(f"\n[+] fixture -> {args.gen_fixture} ({n} frames)")
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    return main([])


if __name__ == "__main__":
    raise SystemExit(main())