from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from crascanner.fingerprint import FingerprintedFile
from crascanner.identification.nsrl import NSRLDatabase
from crascanner.identification.signature import SignatureResult, verify_signature
from crascanner.identification.syft import (
    SyftComponent,
    extract_component_metadata,
    run_syft_on_target,
)
from crascanner.identification.clearlydefined import ClearlyDefinedClient, LicenseData
from crascanner.identification.catalog import HumanVerificationCatalog, CatalogEntry


@dataclass
class IdentifiedComponent:
    """Result of passing a file through the 4-layer identification funnel."""
    fingerprint: FingerprintedFile
    name: str
    version: str
    purl: str
    confidence_level: int  # 1 to 4
    confidence_description: str
    classification: str  # "Platform/Infrastructure" or "Product Code"
    is_platform: bool
    platform_reason: Optional[str] = None
    signature: Optional[SignatureResult] = None
    publisher_verified: bool = False
    license_data: Optional[LicenseData] = None
    is_identified: bool = True
    catalog_entry: Optional[CatalogEntry] = None

    @property
    def file_path(self) -> Path:
        return self.fingerprint.path

    @property
    def relative_path(self) -> str:
        return self.fingerprint.relative_path

    @property
    def sha256(self) -> str:
        return self.fingerprint.sha256

    @property
    def sha512(self) -> str:
        return self.fingerprint.sha512


class ComponentIdentificationEngine:
    """
    Step 3: Component Identification Engine (The 4-Layer Funnel).
    - Layer 1a: NSRL Filter (Noise Reduction) -> Platform tagging
    - Layer 1b: Digital Signature Verification (Publisher Proof) -> Platform tagging & mismatch flags
    - Layer 2: Syft Extraction -> PURL & metadata
    - Layer 3: ClearlyDefined -> License & provenance backfill
    - Layer 4: Human Verification -> Persistent lookup table for leftovers
    """

    def __init__(
        self,
        nsrl_db: Optional[NSRLDatabase] = None,
        catalog: Optional[HumanVerificationCatalog] = None,
        clearlydefined: Optional[ClearlyDefinedClient] = None,
        syft_bin: Optional[str] = None,
    ):
        self.nsrl_db = nsrl_db or NSRLDatabase()
        self.catalog = catalog or HumanVerificationCatalog(Path("./.crascanner_catalog.json"))
        self.clearlydefined = clearlydefined or ClearlyDefinedClient()
        self.syft_bin = syft_bin

    def process_files(
        self,
        files: List[FingerprintedFile],
        target_dir: Path,
    ) -> List[IdentifiedComponent]:
        """
        Executes the 4-layer funnel on all fingerprinted files.
        """
        # Pre-scan with Syft if available
        syft_cache: Dict[str, SyftComponent] = run_syft_on_target(target_dir, self.syft_bin)

        identified_components: List[IdentifiedComponent] = []

        for f in files:
            sha256 = f.sha256
            file_path = f.path

            # Layer 1a: NSRL Filter
            is_nsrl, nsrl_detail = self.nsrl_db.is_in_nsrl(sha256)

            # Layer 1b: Digital Signature Verification
            sig_result: SignatureResult = verify_signature(file_path)

            # Determine Platform / Infrastructure Classification
            # File is classified Platform/Infrastructure if confirmed by EITHER NSRL OR a valid signature
            is_platform = False
            platform_reason = None

            if is_nsrl:
                is_platform = True
                platform_reason = nsrl_detail or "NSRL Platform Match"
            elif sig_result.is_valid:
                is_platform = True
                platform_reason = f"Authenticode Validated: {sig_result.signer_subject or sig_result.signer_issuer or 'Verified Publisher'}"

            classification = "Platform/Infrastructure" if is_platform else "Product Code"
            publisher_verified = sig_result.is_valid

            # Layer 4: Human Verification & Curated Catalog
            catalog_entry: Optional[CatalogEntry] = self.catalog.get(sha256)

            # Layer 2: Syft Extraction (or PE metadata fallback)
            syft_comp: Optional[SyftComponent] = None
            if not catalog_entry:
                syft_comp = extract_component_metadata(file_path, syft_cache)

            # Layer 3: ClearlyDefined (License & Provenance Backfill)
            license_data = None
            target_purl = catalog_entry.purl if catalog_entry else (syft_comp.purl if syft_comp else None)
            if target_purl:
                license_data = self.clearlydefined.fetch_license_and_provenance(target_purl)

            # Assign Identity & Confidence Levels
            # Confidence Levels:
            # - Level 1: Cryptographically verified (NuGet round-trip match, internal curated hash match)
            # - Level 2: Signature/NSRL-confirmed platform file
            # - Level 3: Metadata-only match (Syft/ClearlyDefined identified, unverified)
            # - Level 4: Unidentified (hash + path only, pending human review)

            if catalog_entry:
                name = catalog_entry.name
                version = catalog_entry.version
                purl = catalog_entry.purl
                classification = catalog_entry.classification
                confidence_level = 1
                confidence_desc = "Level 1 — Human / Curated Verified Match"
                is_identified = True
            elif syft_comp:
                name = syft_comp.name
                version = syft_comp.version
                purl = syft_comp.purl
                is_identified = True

                if is_platform:
                    confidence_level = 2
                    confidence_desc = "Level 2 — Signature/NSRL-confirmed Platform File"
                else:
                    confidence_level = 3
                    confidence_desc = "Level 3 — Metadata-only Match (Syft/Assembly)"
            elif is_platform:
                name = file_path.name
                version = "OS-Managed"
                purl = f"pkg:generic/{file_path.stem}@OS-Managed"
                confidence_level = 2
                confidence_desc = "Level 2 — Signature/NSRL-confirmed Platform File"
                is_identified = True
            else:
                # Unidentified leftover
                name = file_path.name
                version = "Unknown"
                purl = f"pkg:generic/{file_path.stem}@unknown"
                confidence_level = 4
                confidence_desc = "Level 4 — Unidentified (Pending Human Review)"
                is_identified = False

            identified_components.append(
                IdentifiedComponent(
                    fingerprint=f,
                    name=name,
                    version=version,
                    purl=purl,
                    confidence_level=confidence_level,
                    confidence_description=confidence_desc,
                    classification=classification,
                    is_platform=is_platform,
                    platform_reason=platform_reason,
                    signature=sig_result,
                    publisher_verified=publisher_verified,
                    license_data=license_data,
                    is_identified=is_identified,
                    catalog_entry=catalog_entry,
                )
            )

        return identified_components
