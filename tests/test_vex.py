from pathlib import Path
from crascanner.discovery import DiscoveredFile
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.engine import IdentifiedComponent
from crascanner.vulnerability.aggregator import VulnerabilityFinding
from crascanner.vex import apply_precision_filtering, PriorityTier, VEXStatus


def test_precision_filtering_platform_vs_product():
    # 1. Platform component finding
    disc1 = DiscoveredFile(Path("kernel32.dll"), "kernel32.dll", 100, ".dll", "PE Binary", True, True)
    fp1 = FingerprintedFile(disc1, "1" * 64, "2" * 128)
    comp_platform = IdentifiedComponent(
        fingerprint=fp1,
        name="kernel32",
        version="10.0.0",
        purl="pkg:generic/kernel32@10.0.0",
        confidence_level=2,
        confidence_description="Level 2",
        classification="Platform/Infrastructure",
        is_platform=True,
    )
    f_platform = VulnerabilityFinding(
        component=comp_platform,
        primary_id="CVE-2021-1234",
        cve_id="CVE-2021-1234",
        is_actively_exploited=False,
    )

    # 2. Product component finding with KEV (Actively Exploited)
    disc2 = DiscoveredFile(Path("app.dll"), "app.dll", 200, ".dll", "PE Binary", True, True)
    fp2 = FingerprintedFile(disc2, "3" * 64, "4" * 128)
    comp_product = IdentifiedComponent(
        fingerprint=fp2,
        name="app-core",
        version="1.2.0",
        purl="pkg:nuget/app-core@1.2.0",
        confidence_level=3,
        confidence_description="Level 3",
        classification="Product Code",
        is_platform=False,
    )
    f_product = VulnerabilityFinding(
        component=comp_product,
        primary_id="CVE-2023-8888",
        cve_id="CVE-2023-8888",
        is_actively_exploited=True,
        active_exploitation_source="CISA KEV",
    )

    results = apply_precision_filtering([f_platform, f_product])
    assert len(results) == 2

    # Platform must be routed to Level 3 with "Not Affected — Managed by Platform/OS"
    r_platform = next(r for r in results if r.component.name == "kernel32")
    assert r_platform.priority_tier == PriorityTier.LEVEL_3
    assert r_platform.vex_status == VEXStatus.NOT_AFFECTED_PLATFORM.value
    assert r_platform.is_actionable is False

    # Product with KEV must be routed to Level 1
    r_product = next(r for r in results if r.component.name == "app-core")
    assert r_product.priority_tier == PriorityTier.LEVEL_1
    assert r_product.vex_status == VEXStatus.AFFECTED.value
    assert r_product.is_actionable is True
