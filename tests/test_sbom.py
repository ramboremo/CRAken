import json
from pathlib import Path
import tempfile
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.engine import IdentifiedComponent
from crascanner.vulnerability.aggregator import VulnerabilityFinding
from crascanner.vex import apply_precision_filtering
from crascanner.sbom import generate_cyclonedx_16_sbom


def test_generate_cyclonedx_16_sbom():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        sbom_file = out_dir / "bom.cdx.json"

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
            cvss_score=7.5,
            cvss_severity="HIGH",
        )
        filtered = apply_precision_filtering([finding])

        generate_cyclonedx_16_sbom(out_dir, [comp], filtered, sbom_file)

        assert sbom_file.exists()
        with open(sbom_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.6"
        assert len(data["components"]) == 1
        assert data["components"][0]["hashes"][0]["alg"] == "SHA-256"
        assert data["components"][0]["hashes"][1]["alg"] == "SHA-512"
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["id"] == "CVE-2023-1111"
        assert data["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
