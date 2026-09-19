from dataclasses import dataclass, field
import os
import shutil
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """Global configuration settings for CRAScanner."""

    # Target & Output
    target_dir: Path = field(default_factory=lambda: Path("."))
    output_dir: Path = field(default_factory=lambda: Path("./output"))
    bom_file: str = "bom.cdx.json"
    report_file: str = "crascanner_report.html"

    # NSRL Settings (Layer 1a)
    nsrl_db_path: Optional[Path] = None  # Path to full NSRL RDS SQLite/CSV
    use_curated_nsrl: bool = True  # Always enabled built-in curated Microsoft/OS hashes

    # Syft Settings (Layer 2)
    syft_bin_path: Optional[str] = None  # Detected automatically or custom path
    syft_tools_dir: Path = field(default_factory=lambda: Path("./.tools"))

    # Human Catalog (Layer 4)
    catalog_path: Path = field(default_factory=lambda: Path("./.crascanner_catalog.json"))

    # AI & Antigravity CLI (Step 7)
    agy_bin_path: Optional[str] = None
    skip_ai: bool = False
    ai_timeout_sec: int = 60

    # Feeds & Endpoints
    osv_api_url: str = "https://api.osv.dev/v1"
    clearlydefined_api_url: str = "https://api.clearlydefined.io"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    euvd_api_url: str = "https://euvd.enisa.europa.eu/api"

    # Cache Settings
    cache_dir: Path = field(default_factory=lambda: Path("./.crascanner_cache"))
    cache_ttl_hours: int = 24

    def __post_init__(self):
        # Resolve target and output
        self.target_dir = Path(self.target_dir).resolve()
        self.output_dir = Path(self.output_dir).resolve()
        self.cache_dir = Path(self.cache_dir).resolve()
        self.catalog_path = Path(self.catalog_path).resolve()
        self.syft_tools_dir = Path(self.syft_tools_dir).resolve()

        if self.nsrl_db_path:
            self.nsrl_db_path = Path(self.nsrl_db_path).resolve()

        # Locate agy.exe
        if not self.agy_bin_path:
            # Check default install location on Windows
            local_agy = Path(os.environ.get("LOCALAPPDATA", "")) / "agy" / "bin" / "agy.exe"
            if local_agy.exists():
                self.agy_bin_path = str(local_agy)
            else:
                found = shutil.which("agy") or shutil.which("agy.exe")
                if found:
                    self.agy_bin_path = found

        # Locate syft
        if not self.syft_bin_path:
            local_syft = self.syft_tools_dir / "syft.exe"
            if local_syft.exists():
                self.syft_bin_path = str(local_syft)
            else:
                found_syft = shutil.which("syft") or shutil.which("syft.exe")
                if found_syft:
                    self.syft_bin_path = found_syft
