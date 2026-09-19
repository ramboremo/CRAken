from dataclasses import dataclass
import os
from pathlib import Path
from typing import Generator, List, Optional
import mimetypes


@dataclass
class DiscoveredFile:
    """Represents a discovered file from Step 1."""
    path: Path
    relative_path: str
    size_bytes: int
    extension: str
    file_type: str
    is_binary: bool
    is_executable: bool


# Common executable/library extensions
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".com", ".scr", ".cpl", ".drv", ".efi"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".py", ".rb", ".php"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".nupkg", ".jar", ".war", ".ear"}
MANIFEST_EXTENSIONS = {
    ".deps.json",
    ".lock",
    "packages.lock.json",
    "packages.config",
    "project.assets.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
}


def classify_file_type(path: Path) -> tuple[str, bool, bool]:
    """
    Classify file type, returning (category_string, is_binary, is_executable).
    """
    ext = path.suffix.lower()
    name = path.name.lower()

    # Check for known manifest names
    if name in MANIFEST_EXTENSIONS or any(name.endswith(m) for m in MANIFEST_EXTENSIONS):
        return "Dependency Manifest", False, False

    if ext in PE_EXTENSIONS:
        return "PE Binary (Windows)", True, True

    if ext in SCRIPT_EXTENSIONS:
        return "Script", False, True

    if ext in ARCHIVE_EXTENSIONS:
        return "Archive / Package", True, False

    mime, _ = mimetypes.guess_type(str(path))
    if mime:
        if mime.startswith("text/"):
            return f"Text ({mime})", False, False
        if "application" in mime:
            return f"Application ({mime})", True, False

    # Default fallback: check if file has null bytes
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return "Binary Data", True, False
            return "Plain Text", False, False
    except Exception:
        return "Unknown", True, False


def discover_files(target_dir: Path) -> List[DiscoveredFile]:
    """
    Step 1: Discovery.
    Recursively traverses target directory and builds an inventory of all files.
    """
    target_dir = target_dir.resolve()
    if not target_dir.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")
    if not target_dir.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_dir}")

    inventory: List[DiscoveredFile] = []

    for root, dirs, files in os.walk(target_dir, followlinks=False):
        for filename in files:
            file_path = Path(root) / filename
            try:
                # Handle broken symlinks or permission errors
                stat = file_path.stat()
                size_bytes = stat.st_size
                rel_path = str(file_path.relative_to(target_dir))
                ext = file_path.suffix.lower()
                category, is_bin, is_exe = classify_file_type(file_path)

                inventory.append(
                    DiscoveredFile(
                        path=file_path,
                        relative_path=rel_path,
                        size_bytes=size_bytes,
                        extension=ext,
                        file_type=category,
                        is_binary=is_bin,
                        is_executable=is_exe,
                    )
                )
            except (OSError, PermissionError):
                # Safely continue on unreadable or locked files
                continue

    return inventory
