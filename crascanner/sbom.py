from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
from crascanner.identification.engine import IdentifiedComponent
from crascanner.vex import FilteredVulnerability, PriorityTier, VEXStatus


def generate_cyclonedx_16_sbom(
    target_dir: Path,
    components: List[IdentifiedComponent],
    vulnerabilities: List[FilteredVulnerability],
    output_file: Path,
) -> Path:
    """
    Step 6: CycloneDX 1.6 SBOM Generation.
    Produces an official, machine-readable bom.cdx.json containing:
    - All discovered components (Product Code & Platform/Infrastructure)
    - SHA-256 and SHA-512 hashes (BSI TR-03183-2 compliance)
    - Standard PURLs and Confidence Levels (1-4)
    - Authenticode publisher & signature verification evidence
    - ClearlyDefined license and provenance metadata
    - Full CycloneDX VEX vulnerability data (Actionable threats + Platform-ignored ones)
    """
    output_file = Path(output_file).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Map components to unique bom-refs
    comp_ref_map: Dict[str, str] = {}
    cdx_components: List[Dict[str, Any]] = []

    for i, comp in enumerate(components):
        bom_ref = f"comp-{i+1}-{comp.sha256[:12]}"
        comp_ref_map[comp.sha256] = bom_ref

        # Properties for CRA audit trail
        properties = [
            {"name": "crascanner:confidence_level", "value": str(comp.confidence_level)},
            {"name": "crascanner:confidence_description", "value": comp.confidence_description},
            {"name": "crascanner:classification", "value": comp.classification},
            {"name": "crascanner:is_platform", "value": str(comp.is_platform).lower()},
            {"name": "crascanner:publisher_verified", "value": str(comp.publisher_verified).lower()},
        ]

        if comp.platform_reason:
            properties.append({"name": "crascanner:platform_reason", "value": comp.platform_reason})

        if comp.signature:
            properties.append({"name": "crascanner:signature_status", "value": comp.signature.status})
            if comp.signature.flag:
                properties.append({"name": "crascanner:signature_flag", "value": comp.signature.flag})
            if comp.signature.signer_subject:
                properties.append({"name": "crascanner:signer_subject", "value": comp.signature.signer_subject})

        # Licenses from ClearlyDefined if present
        licenses = []
        if comp.license_data and comp.license_data.declared_license:
            licenses.append({"license": {"id": comp.license_data.declared_license}})
        elif comp.license_data and comp.license_data.discovered_license:
            licenses.append({"license": {"name": comp.license_data.discovered_license}})

        # Determine CycloneDX component type
        cdx_type = "library"
        if comp.is_platform:
            cdx_type = "operating-system" if "system" in comp.relative_path.lower() else "framework"
        elif comp.fingerprint.is_executable and comp.relative_path.endswith(".exe"):
            cdx_type = "application"

        c_entry: Dict[str, Any] = {
            "bom-ref": bom_ref,
            "type": cdx_type,
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "hashes": [
                {"alg": "SHA-256", "content": comp.sha256},
                {"alg": "SHA-512", "content": comp.sha512},
            ],
            "evidence": {
                "occurrences": [
                    {"location": comp.relative_path}
                ]
            },
            "properties": properties,
        }

        if licenses:
            c_entry["licenses"] = licenses

        if comp.signature and comp.signature.claimed_publisher:
            c_entry["publisher"] = comp.signature.claimed_publisher

        cdx_components.append(c_entry)

    # Convert Filtered Vulnerabilities into CycloneDX 1.6 VEX Vulnerabilities
    cdx_vulnerabilities: List[Dict[str, Any]] = []

    for idx, fv in enumerate(vulnerabilities):
        finding = fv.finding
        c_ref = comp_ref_map.get(finding.component.sha256, "")

        # Determine VEX state and justification
        if fv.priority_tier == PriorityTier.LEVEL_3:
            vex_state = "not_affected"
            justification = "platform_or_runtime_provided"
            response = ["will_not_fix"]
        elif fv.ai_verdict == "yes":  # Confirmed false positive by AI
            vex_state = "false_positive"
            justification = "code_not_reachable"
            response = ["will_not_fix"]
        elif fv.priority_tier == PriorityTier.LEVEL_1:
            vex_state = "exploitable"
            justification = "requires_immediate_patch"
            response = ["update", "immediate_action_required"]
        else:
            vex_state = "in_triage"
            justification = None
            response = ["update"]

        ratings = []
        if finding.cvss_score is not None:
            rating: Dict[str, Any] = {
                "score": finding.cvss_score,
                "severity": finding.cvss_severity.lower() if finding.cvss_severity else "unknown",
                "method": "CVSSv31" if (finding.cvss_vector and "3.1" in finding.cvss_vector) else "CVSSv3",
            }
            if finding.cvss_vector:
                rating["vector"] = finding.cvss_vector
            ratings.append(rating)

        advisories = [{"url": u} for u in finding.advisory_urls]

        analysis: Dict[str, Any] = {
            "state": vex_state,
            "detail": fv.vex_justification,
            "response": response,
        }
        if justification:
            analysis["justification"] = justification

        v_entry: Dict[str, Any] = {
            "bom-ref": f"vuln-{idx+1}-{finding.primary_id}",
            "id": finding.primary_id,
            "source": {"name": "OSV / NVD / CISA KEV / ENISA EUVD"},
            "description": finding.description or finding.title_or_summary,
            "ratings": ratings,
            "advisories": advisories,
            "affects": [{"ref": c_ref}],
            "analysis": analysis,
            "properties": [
                {"name": "crascanner:priority_tier", "value": fv.priority_tier.value},
                {"name": "crascanner:vex_status", "value": fv.vex_status},
                {"name": "crascanner:is_actively_exploited", "value": str(finding.is_actively_exploited).lower()},
            ],
        }

        if finding.active_exploitation_source:
            v_entry["properties"].append({
                "name": "crascanner:active_exploitation_source",
                "value": finding.active_exploitation_source,
            })

        if fv.ai_verdict:
            v_entry["properties"].append({"name": "crascanner:ai_verdict", "value": fv.ai_verdict})
            if fv.ai_justification:
                v_entry["properties"].append({"name": "crascanner:ai_justification", "value": fv.ai_justification})

        if fv.likely_source_package:
            v_entry["properties"].append({"name": "crascanner:likely_source_package", "value": fv.likely_source_package})

        cdx_vulnerabilities.append(v_entry)

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "crascanner",
                        "version": "0.1.0",
                        "description": "EU Cyber Resilience Act (CRA) Compliance Scanner & SBOM Generator",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": target_dir.name or "Scanned Application",
                "version": "1.0.0",
            },
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulnerabilities,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)

    return output_file
