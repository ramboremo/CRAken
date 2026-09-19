from dataclasses import asdict, dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Optional


@dataclass
class CatalogEntry:
    """Manual identification entry for Layer 4 Human Verification."""
    sha256: str
    name: str
    version: str
    purl: str
    classification: str = "Product Code"  # "Product Code" or "Platform/Infrastructure"
    notes: Optional[str] = None
    verified_by: Optional[str] = "engineer"
    verified_at: Optional[str] = None


class HumanVerificationCatalog:
    """
    Step 3 Layer 4: Human Verification Catalog.
    A persistent lookup table for files unidentified after Layers 1-3.
    Once an engineer identifies the file, every future scan resolves it automatically.
    """

    def __init__(self, catalog_path: Path):
        self.catalog_path = Path(catalog_path)
        self.entries: Dict[str, CatalogEntry] = {}
        self.load()

    def load(self):
        if self.catalog_path.exists():
            try:
                with open(self.catalog_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self.entries[k.lower()] = CatalogEntry(**v)
            except Exception:
                self.entries = {}

    def save(self):
        try:
            self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.catalog_path, "w", encoding="utf-8") as f:
                json.dump(
                    {k: asdict(v) for k, v in self.entries.items()},
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def get(self, sha256: str) -> Optional[CatalogEntry]:
        return self.entries.get(sha256.lower())

    def add(
        self,
        sha256: str,
        name: str,
        version: str,
        purl: str,
        classification: str = "Product Code",
        notes: Optional[str] = None,
        verified_by: str = "engineer",
    ):
        entry = CatalogEntry(
            sha256=sha256.lower(),
            name=name,
            version=version,
            purl=purl,
            classification=classification,
            notes=notes,
            verified_by=verified_by,
            verified_at=datetime.utcnow().isoformat() + "Z",
        )
        self.entries[sha256.lower()] = entry
        self.save()
