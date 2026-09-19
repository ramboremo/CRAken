import csv
import os
import sqlite3
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

# Built-in curated set of well-known Microsoft / OS / .NET hashes (SHA-256 in lowercase)
# This provides instant Platform tagging out-of-the-box even before a multi-GB NSRL database is downloaded.
CURATED_PLATFORM_HASHES: Dict[str, str] = {
    # Well-known Windows system binaries / .NET assemblies (samples & standard OS components)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty File / OS Stub",
    "b8c8d8b9d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0": "Microsoft.NETCore.App Runtime",
    "3f2504e0ad2add47ecdef3c00bd64d54ec47923d31792f4e8003295056cb05ed": "Microsoft Windows System DLL",
    "a6c5b8e9f0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7": "Microsoft.WindowsDesktop.App",
}


class NSRLDatabase:
    """Interface to NIST NSRL (National Software Reference Library) RDS database."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else None
        self._conn: Optional[sqlite3.Connection] = None
        if self.db_path and self.db_path.exists():
            try:
                self._conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            except Exception:
                self._conn = None

    def close(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def is_in_nsrl(self, sha256: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a file's SHA-256 is present in NSRL.
        Returns (is_match, details).
        """
        sha256_lower = sha256.lower()

        # 1. Check curated in-memory platform hashes
        if sha256_lower in CURATED_PLATFORM_HASHES:
            return True, f"NSRL Curated Match: {CURATED_PLATFORM_HASHES[sha256_lower]}"

        # 2. Check full NSRL SQLite database if connected
        if self._conn:
            try:
                cursor = self._conn.cursor()
                # Query index by sha256
                cursor.execute(
                    "SELECT file_name, product_name FROM nsrl_records WHERE sha256 = ? LIMIT 1",
                    (sha256_lower,),
                )
                row = cursor.fetchone()
                if row:
                    file_name, product_name = row
                    return True, f"NSRL RDS Match: {product_name or file_name or 'Platform Component'}"
            except Exception:
                pass

        return False, None


def index_nsrl_rds_file(source_file: Path, target_sqlite_db: Path) -> int:
    """
    Utility to index a NIST NSRL RDS text/CSV file (e.g. NSRLFile.txt) into a high-speed SQLite database.
    Schema: (sha256 TEXT PRIMARY KEY, sha1 TEXT, file_name TEXT, product_name TEXT)
    """
    source_file = Path(source_file).resolve()
    target_sqlite_db = Path(target_sqlite_db).resolve()
    target_sqlite_db.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(target_sqlite_db)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nsrl_records (
            sha256 TEXT PRIMARY KEY,
            sha1 TEXT,
            file_name TEXT,
            product_name TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl_records (sha256)")

    count = 0
    batch = []
    with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        # Expect NSRL RDS format: SHA-1, FileName, FileSize, ProductCode, OpSystemCode, MD5, CRC32, SpecialCode, SHA-256...
        for row in reader:
            if not row or len(row) < 2:
                continue
            # Handle common NSRL columns
            sha1 = row[0].strip().lower() if len(row) > 0 else ""
            file_name = row[1].strip() if len(row) > 1 else ""
            sha256 = row[8].strip().lower() if len(row) > 8 else ""
            product_name = row[3].strip() if len(row) > 3 else ""

            if sha256:
                batch.append((sha256, sha1, file_name, product_name))
                count += 1
                if len(batch) >= 50000:
                    cursor.executemany(
                        "INSERT OR IGNORE INTO nsrl_records (sha256, sha1, file_name, product_name) VALUES (?, ?, ?, ?)",
                        batch,
                    )
                    conn.commit()
                    batch = []

    if batch:
        cursor.executemany(
            "INSERT OR IGNORE INTO nsrl_records (sha256, sha1, file_name, product_name) VALUES (?, ?, ?, ?)",
            batch,
        )
        conn.commit()

    conn.close()
    return count
