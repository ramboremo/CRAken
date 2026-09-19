from dataclasses import dataclass
from typing import Dict, List, Optional
import requests
from packageurl import PackageURL


@dataclass
class LicenseData:
    """License and provenance data backfilled from ClearlyDefined."""
    declared_license: Optional[str] = None
    discovered_license: Optional[str] = None
    confidence_score: Optional[int] = None
    source_url: Optional[str] = None
    source_commit: Optional[str] = None


def purl_to_clearlydefined_path(purl_str: str) -> Optional[str]:
    """
    Translates a PURL into ClearlyDefined coordinate path:
    {type}/{provider}/{namespace}/{name}/{revision}
    """
    try:
        p = PackageURL.from_string(purl_str)
        p_type = p.type.lower() if p.type else "generic"
        namespace = p.namespace or "-"
        name = p.name
        version = p.version

        if not name or not version:
            return None

        provider = "-"
        if p_type == "nuget":
            provider = "nuget"
            namespace = "-"
        elif p_type == "npm":
            provider = "npmjs"
        elif p_type == "pypi":
            provider = "pypi"
            namespace = "-"
        elif p_type == "maven":
            provider = "mavencentral"
        elif p_type in ("golang", "go"):
            p_type = "git"
            provider = "github"
        else:
            return None

        return f"{p_type}/{provider}/{namespace}/{name}/{version}"
    except Exception:
        return None


class ClearlyDefinedClient:
    """Step 3 Layer 3: ClearlyDefined backfill client."""

    def __init__(self, base_url: str = "https://api.clearlydefined.io"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CRAScanner/0.1.0 (EU Cyber Resilience Act Compliance Engine)"
        })
        self._cache: Dict[str, Optional[LicenseData]] = {}

    def fetch_license_and_provenance(self, purl_str: str) -> Optional[LicenseData]:
        """
        Queries ClearlyDefined with PURL and returns declared vs discovered license,
        confidence score, and source provenance data.
        """
        if purl_str in self._cache:
            return self._cache[purl_str]

        coord = purl_to_clearlydefined_path(purl_str)
        if not coord:
            self._cache[purl_str] = None
            return None

        url = f"{self.base_url}/definitions/{coord}"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                licensed = data.get("licensed", {})
                described = data.get("described", {})

                declared = licensed.get("declared")
                discovered = None
                disc_obj = licensed.get("discovered", {})
                if isinstance(disc_obj, dict):
                    disc_exprs = disc_obj.get("expressions", [])
                    if disc_exprs:
                        discovered = " OR ".join(disc_exprs)

                confidence = None
                facets = licensed.get("facets", {})
                core_facet = facets.get("core", {})
                if isinstance(core_facet, dict):
                    confidence = core_facet.get("confidence")

                source_loc = described.get("sourceLocation", {})
                source_url = source_loc.get("url") if isinstance(source_loc, dict) else None
                source_commit = source_loc.get("revision") if isinstance(source_loc, dict) else None

                license_data = LicenseData(
                    declared_license=declared,
                    discovered_license=discovered,
                    confidence_score=confidence,
                    source_url=source_url,
                    source_commit=source_commit,
                )
                self._cache[purl_str] = license_data
                return license_data
            else:
                self._cache[purl_str] = None
                return None
        except Exception:
            self._cache[purl_str] = None
            return None
