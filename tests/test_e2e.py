import json
from pathlib import Path
import tempfile
from crascanner.config import Config
from crascanner.discovery import discover_files
from crascanner.fingerprint import fingerprint_files
from crascanner.identification.nsrl import NSRLDatabase
from crascanner.identification.catalog import HumanVerificationCatalog
from crascanner.identification.clearlydefined import ClearlyDefinedClient
from crascanner.identification.engine import ComponentIdentificationEngine
from crascanner.vulnerability.aggregator import ThreatIntelligenceAggregator
from crascanner.vex import apply_precision_filtering
from crascanner.sbom import generate_cyclonedx_16_sbom
from crascanner.reporter import generate_html_report


def test_full_pipeline_end_to_end():
    fixture_dir = Path("tests/fixtures/sample_app").resolve()
    assert fixture_dir.exists()

    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        bom_file = out_dir / "bom.cdx.json"
        report_file = out_dir / "report.html"

        # Step 1: Discovery
        discovered = discover_files(fixture_dir)
        assert len(discovered) >= 3

        # Step 2: Fingerprinting
        fingerprinted = fingerprint_files(discovered)
        assert len(fingerprinted) == len(discovered)

        # Step 3: Identification
        ident_engine = ComponentIdentificationEngine()
        identified = ident_engine.process_files(fingerprinted, fixture_dir)
        assert len(identified) == len(fingerprinted)

        # Step 4: Vulnerability Querying
        threat_agg = ThreatIntelligenceAggregator(cache_dir=out_dir / ".cache")
        findings = threat_agg.query_vulnerabilities_for_components(identified)

        # Step 5: VEX Filtering
        filtered = apply_precision_filtering(findings)

        # Step 6: SBOM
        generate_cyclonedx_16_sbom(fixture_dir, identified, filtered, bom_file)
        assert bom_file.exists()

        with open(bom_file, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        assert sbom_data["specVersion"] == "1.6"

        # Step 7: HTML Report
        generate_html_report(fixture_dir, identified, filtered, report_file)
        assert report_file.exists()
        html_text = report_file.read_text(encoding="utf-8")
        assert "EU Cyber Resilience Act (CRA) Scanner" in html_text
