"""Unit tests for risk computation — no live target needed."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import SEVERITY_WEIGHT


def compute_risk_score(findings):
    """Replicates the logic from main.py and sentinelx.py."""
    total = sum(SEVERITY_WEIGHT.get(f.get("severity", "LOW"), 1) for f in findings)
    return min(total, 100)


class TestComputeRiskScore:
    def test_no_findings(self):
        assert compute_risk_score([]) == 0

    def test_single_critical(self):
        assert compute_risk_score([{"severity": "CRITICAL"}]) == 10

    def test_single_high(self):
        assert compute_risk_score([{"severity": "HIGH"}]) == 5

    def test_single_medium(self):
        assert compute_risk_score([{"severity": "MEDIUM"}]) == 2

    def test_single_low(self):
        assert compute_risk_score([{"severity": "LOW"}]) == 1

    def test_missing_severity_defaults_to_low(self):
        assert compute_risk_score([{"type": "something"}]) == 1

    def test_unknown_severity_defaults_to_low(self):
        assert compute_risk_score([{"severity": "INFO"}]) == 1

    def test_mixed_findings(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
            {"severity": "CRITICAL"},
        ]
        assert compute_risk_score(findings) == 28  # 10 + 5 + 2 + 1 + 10

    def test_capped_at_100(self):
        many_criticals = [{"severity": "CRITICAL"}] * 15  # 150 would be score
        assert compute_risk_score(many_criticals) == 100

    def test_empty_dict_finding(self):
        assert compute_risk_score([{}]) == 1  # defaults to LOW
