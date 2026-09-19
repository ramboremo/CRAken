from pathlib import Path
import tempfile
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.engine import IdentifiedComponent
from crascanner.vulnerability.aggregator import VulnerabilityFinding
from crascanner.vex import apply_precision_filtering
from crascanner.reporter import generate_html_report


def test_generate_html_report_schema_and_tiers():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        report_file = out_dir / "report.html"

        disc = DiscoveredFile(Path("app.dll"), "app.dll", 100, ".dll", "PE Binary", True, True)
        fp = FingerprintedFile(disc, "a" * 64, "b" * 128)
        comp = IdentifiedComponent(
            fingerprint=fp,
            name="app-core",
            version="1.0.0",
            purl="pkg:nuget/app-core@1.0.0",
            confidence_level=3,
            confidence_description="Level 3",
            classification="Product Code",
            is_platform=False,
            publisher_verified=True,
        )

        finding = VulnerabilityFinding(
            component=comp,
            primary_id="CVE-2023-1111",
            cve_id="CVE-2023-1111",
            cvss_score=8.5,
            cvss_severity="HIGH",
            is_actively_exploited=True,
            active_exploitation_source="CISA KEV",
        )
        filtered = apply_precision_filtering([finding])
        filtered[0].likely_source_package = "DirectRootApp"

        generate_html_report(out_dir, [comp], filtered, report_file)

        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")

        # Verify 14 columns header presence
        assert "#1 File Path" in content
        assert "#2 File Hash (SHA-256)" in content
        assert "#3 Component & Version" in content
        assert "#4 PURL" in content
        assert "#5 Confidence" in content
        assert "#6 Signature Verified?" in content
        assert "#7 Classification" in content
        assert "#8 CVE ID(s)" in content
        assert "#9 CVSS Severity" in content
        assert "#10 Actively Exploited?" in content
        assert "#11 VEX Status" in content
        assert "#12 AI Verdict" in content
        assert "#13 AI Justification" in content
        assert "#14 Likely Source Package" in content

        # Verify 3 collapsible tiers
        assert "section-tier-1" in content
        assert "section-tier-2" in content
        assert "section-tier-3" in content

        # Verify Level 1 active finding details
        assert "CVE-2023-1111" in content
        assert "DirectRootApp" in content
        assert "CRA Article 14 Alert Triggered" in content
