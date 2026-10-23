from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.evidence import CodeSecretEvidenceExtractor
from analysis.findings import EvidenceFindingGenerator


class Stage5HonestyTests(unittest.TestCase):
    def test_extraction_limit_metadata_is_recorded(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "one.java").write_text("token = 'ya29.AbCdEfGhIjKlMnOpQrStUvWxYz123456'\n", encoding="utf-8")
            extractor = CodeSecretEvidenceExtractor()
            extractor.extract(root)
            self.assertEqual(extractor.limit_metadata["max_evidence"], 80)
            self.assertEqual(extractor.limit_metadata["emitted"], 1)
            risk = CodeRiskEvidenceExtractor()
            risk.extract(root)
            self.assertEqual(risk.limit_metadata["max_evidence_per_rule"], 12)

    def test_runtime_limit_record_does_not_create_findings(self) -> None:
        base = SimpleNamespace(
            id="e1",
            label="cleartext endpoint",
            evidence_type="cleartext_http_endpoint",
            category=SimpleNamespace(value="code_risk"),
            value_json=json.dumps({"matched_value": "http://example.test"}),
        )
        limit = SimpleNamespace(
            id="e2",
            label="Evidence extraction limits",
            evidence_type="extraction_limits",
            category=SimpleNamespace(value="runtime"),
            value_json=json.dumps({"code_risk": {"truncated_rules": []}}),
        )
        generator = EvidenceFindingGenerator()
        self.assertEqual(len(generator.generate([base])), len(generator.generate([base, limit])))


if __name__ == "__main__":
    unittest.main()
