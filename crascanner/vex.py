from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from crascanner.vulnerability.aggregator import VulnerabilityFinding


class PriorityTier(str, Enum):
    LEVEL_1 = "Level 1 (Active/Critical)"
    LEVEL_2 = "Level 2 (Moderate)"
    LEVEL_3 = "Level 3 (Low/Ignored)"


class VEXStatus(str, Enum):
    AFFECTED = "Affected"
    NOT_AFFECTED_PLATFORM = "Not Affected — Managed by Platform/OS"
    NOT_AFFECTED_FALSE_POSITIVE = "Not Affected — Confirmed False Positive"
    NOT_AFFECTED_UNREACHABLE = "Not Affected — Unreachable Code"
    UNDER_INVESTIGATION = "Under Investigation"


@dataclass
class FilteredVulnerability:
    """Vulnerability finding after Step 5 Precision Filtering & VEX Status Assignment."""
    finding: VulnerabilityFinding
    priority_tier: PriorityTier
    vex_status: str
    vex_justification: str
    is_actionable: bool
    ai_verdict: Optional[str] = None  # "yes" / "no" (is_false_positive)
    ai_justification: Optional[str] = None
    likely_source_package: Optional[str] = None  # For Level 1 findings only

    @property
    def component(self):
        return self.finding.component


def apply_precision_filtering(findings: List[VulnerabilityFinding]) -> List[FilteredVulnerability]:
    """
    Step 5: Precision Filtering & False Positive Reduction.
    - Product Code:
      - Actively exploited (KEV/EUVD) -> Level 1 (Active/Critical)
      - Standard CVSS -> Level 2 (Moderate)
    - Platform/Infrastructure:
      - Relabeled with VEX tag: "Not Affected — Managed by Platform/OS"
      - Routed to Level 3 (Low/Ignored)
    - Nothing is silently deleted; full audit trail is preserved.
    """
    results: List[FilteredVulnerability] = []

    for f in findings:
        comp = f.component

        if comp.is_platform or comp.classification == "Platform/Infrastructure":
            # Platform / OS component -> Level 3 Low/Ignored
            priority = PriorityTier.LEVEL_3
            vex_stat = VEXStatus.NOT_AFFECTED_PLATFORM.value
            justification = f"Vulnerability managed by underlying OS/Platform ({comp.platform_reason or 'OS Platform'})."
            actionable = False
        else:
            # Product Code
            if f.is_actively_exploited:
                # Triggers CRA Article 14 24-hour reporting requirement
                priority = PriorityTier.LEVEL_1
                vex_stat = VEXStatus.AFFECTED.value
                source = f.active_exploitation_source or "Active Threat Feed"
                justification = f"CRITICAL: Actively exploited threat detected ({source}) - CRA Article 14 24h notification triggered."
                actionable = True
            else:
                priority = PriorityTier.LEVEL_2
                vex_stat = VEXStatus.AFFECTED.value
                justification = "Actionable vulnerability in product component requiring remediation during standard sprint cycle."
                actionable = True

        results.append(
            FilteredVulnerability(
                finding=f,
                priority_tier=priority,
                vex_status=vex_stat,
                vex_justification=justification,
                is_actionable=actionable,
            )
        )

    return results
