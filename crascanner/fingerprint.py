from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
from crascanner.discovery import DiscoveredFile


@dataclass
class FingerprintedFile:
    """Represents a file with BSI TR-03183-2 compliant cryptographic hashes."""
    discovered: DiscoveredFile
    sha256: str
    sha512: str

    @property
    def path(self) -> Path:
        return self.discovered.path

    @property
    def relative_path(self) -> str:
        return self.discovered.relative_path

    @property
    def size_bytes(self) -> int:
        return self.discovered.size_bytes

    @property
    def extension(self) -> str:
        return self.discovered.extension

    @property
    def file_type(self) -> str:
        return self.discovered.file_type

    @property
    def is_binary(self) -> bool:
        return self.discovered.is_binary

    @property
    def is_executable(self) -> bool:
        return self.discovered.is_executable


def compute_hashes(path: Path, block_size: int = 65536) -> Tuple[str, str]:
    """
    Computes SHA-256 and SHA-512 hashes in chunks for memory-efficient processing.
    Complies with BSI TR-03183-2 CRA integrity standards.
    """
    hasher_256 = hashlib.sha256()
    hasher_512 = hashlib.sha512()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            hasher_256.update(chunk)
            hasher_512.update(chunk)

    return hasher_256.hexdigest(), hasher_512.hexdigest()


def fingerprint_files(files: List[DiscoveredFile]) -> List[FingerprintedFile]:
    """
    Step 2: Fingerprinting.
    Computes SHA-256 and SHA-512 for each discovered file.
    """
    results: List[FingerprintedFile] = []
    for item in files:
        try:
            sha256, sha512 = compute_hashes(item.path)
            results.append(
                FingerprintedFile(
                    discovered=item,
                    sha256=sha256,
                    sha512=sha512,
                )
            )
        except (OSError, PermissionError):
            # Skip unreadable files
            continue
    return results
