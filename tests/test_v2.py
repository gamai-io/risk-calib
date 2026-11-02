from __future__ import annotations

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from router import Router  # noqa: E402


class TestRiskV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = json.loads((ROOT / "fixtures/inputs.json").read_text())
        cls.expected = json.loads((ROOT / "fixtures/expected_risk_v2.json").read_text())
        cls.router = Router(risk_model="v2")

    def test_fixture_exact(self):
        fields = ["mode", "agents", "domain", "confidence", "risk", "blocked"]
        mismatches = []
        for i, (task, exp) in enumerate(zip(self.inputs, self.expected)):
            got = self.router.route(task)
            for f in fields:
                if got.get(f) != exp.get(f):
                    mismatches.append((i, f, exp.get(f), got.get(f)))
        self.assertEqual(mismatches, [], mismatches[:10])

    def test_t1_blocks(self):
        r = self.router.route("rm -rf /")
        self.assertEqual(r["risk"], 0.9)
        self.assertTrue(r["blocked"])

    def test_t2_not_blocked(self):
        r = self.router.route("delete file report.txt")
        self.assertGreaterEqual(r["risk"], 0.7)
        self.assertFalse(r["blocked"])

    def test_benign_zero(self):
        r = self.router.route("make a quotation for customer ABC")
        self.assertEqual(r["risk"], 0.0)
        self.assertFalse(r["blocked"])


if __name__ == "__main__":
    unittest.main()
