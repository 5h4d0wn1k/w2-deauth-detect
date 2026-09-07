#!/usr/bin/env python3
"""Byte-exact unit tests for w2-deauth-detect."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import deauth_detect as dd
from firmware import frame_core as fc


class ClassifyTest(unittest.TestCase):
    def test_classify_valid(self):
        d = fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                            "00:11:22:33:44:55", reason=7)
        f = dd.classify_deauth(d + fc.fcs(d))
        self.assertEqual(f["reason"], 7)
        self.assertEqual(f["sa"], "00:11:22:33:44:55")
        self.assertFalse(f["sa_locally_administered"])

    def test_bad_fcs_rejected(self):
        frame = bytearray(fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                          "00:11:22:33:44:55", reason=7)
                          + fc.fcs(fc.build_deauth("00:11:22:33:44:66", "00:11:22:33:44:55",
                                                   "00:11:22:33:44:55", reason=7)))
        frame[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            dd.classify_deauth(bytes(frame))

    def test_spoof_sa_flagged(self):
        d = fc.build_deauth("00:11:22:33:44:66", "02:aa:bb:cc:dd:01",
                            "00:11:22:33:44:55", reason=7)
        f = dd.classify_deauth(d + fc.fcs(d))
        self.assertTrue(f["sa_locally_administered"])


class DetectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frames = [{"ts": f["ts"], **dd.classify_deauth(f["data"])}
                      for f in dd.build_fixture_frames()]
        cls.result = dd.detect(cls.frames, storm_threshold=5)

    def test_storm_detected(self):
        types = [a["type"] for a in self.result["alerts"]]
        self.assertIn("deauth_storm", types)
        storm = [a for a in self.result["alerts"] if a["type"] == "deauth_storm"][0]
        self.assertGreaterEqual(storm["count"], 5)

    def test_forged_detected(self):
        types = [a["type"] for a in self.result["alerts"]]
        self.assertIn("forged_deauth", types)

    def test_no_radio(self):
        self.assertFalse(self.result["radio_emitted"])


class FixtureTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hit.pcap")
            n = dd.write_fixture(path)
            self.assertGreater(n, 10)
            frames = dd.read_fixture_pcap(path)
            self.assertEqual(len(frames), n)


class CLITest(unittest.TestCase):
    def test_demo_exit_zero(self):
        self.assertEqual(dd.run_demo(), 0)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = dd.main(["--json", out])
            self.assertEqual(rc, 0)
            data = json.load(open(out))
            self.assertFalse(data["radio_emitted"])
            self.assertTrue(any(a["type"] == "deauth_storm" for a in data["alerts"]))


if __name__ == "__main__":
    unittest.main()