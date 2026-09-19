from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, List, Optional
import pefile
from packageurl import PackageURL


@dataclass
class SyftComponent:
    """Component extracted from Syft or metadata inspection."""
    name: str
    version: str
    purl: str
    purl_type: str
    file_path: Path
    description: Optional[str] = None
    author: Optional[str] = None
    is_syft_native: bool = False


def clean_version(raw_version: str) -> str:
    """Cleans raw version strings like '13.0.1.25517' or 'v1.2.3'."""
    if not raw_version:
        return "0.0.0"
    v = raw_version.strip().lstrip("vV")
    # Extract semver or numeric version pattern
    match = re.search(r"(\d+(\.\d+)+)", v)
    return match.group(1) if match else v.split()[0]


def extract_pe_metadata_component(file_path: Path) -> Optional[SyftComponent]:
    """
    Fallback extractor: reads VS_VERSIONINFO / assembly metadata using pefile
    when Syft subprocess is not available.
    """
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        name = None
        version = None
        company = None
        description = None

        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            entries = {}
                            for k, v in st.entries.items():
                                k_str = k.decode("utf-8", errors="ignore").lower() if isinstance(k, bytes) else str(k).lower()
                                v_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                                entries[k_str] = v_str

                            name = entries.get("productname") or entries.get("internalname") or entries.get("originalfilename")
                            version = entries.get("productversion") or entries.get("fileversion")
                            company = entries.get("companyname")
                            description = entries.get("filedescription")

        pe.close()

        if not name:
            name = file_path.stem

        if not version:
            version = "0.0.0"
        else:
            version = clean_version(version)

        # Infer PURL type: if Windows/.NET DLL/EXE, default to nuget or generic
        purl_type = "nuget" if file_path.suffix.lower() == ".dll" else "generic"
        safe_name = name.strip()
        purl = f"pkg:{purl_type}/{safe_name}@{version}"

        return SyftComponent(
            name=safe_name,
            version=version,
            purl=purl,
            purl_type=purl_type,
            file_path=file_path,
            description=description,
            author=company,
            is_syft_native=False,
        )
    except Exception:
        return None


def run_syft_on_target(target_dir: Path, syft_bin: Optional[str] = None) -> Dict[str, SyftComponent]:
    """
    Step 3 Layer 2: Syft Extraction.
    Runs Syft subprocess against the target directory, outputting CycloneDX JSON.
    Maps identified components to file paths.
    """
    results: Dict[str, SyftComponent] = {}
    syft_cmd = syft_bin or shutil.which("syft") or shutil.which("syft.exe")

    if not syft_cmd:
        return results

    try:
        # Run syft scan dir:<path> -o cyclonedx-json
        cmd = [syft_cmd, "scan", f"dir:{target_dir}", "-o", "cyclonedx-json"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            components = data.get("components", [])
            for comp in components:
                name = comp.get("name", "")
                version = comp.get("version", "0.0.0")
                purl = comp.get("purl", "")
                if not purl:
                    purl = f"pkg:generic/{name}@{version}"

                purl_type = "generic"
                try:
                    parsed_purl = PackageURL.from_string(purl)
                    purl_type = parsed_purl.type or "generic"
                except Exception:
                    pass

                # Syft evidence / occurrences
                occurrences = comp.get("evidence", {}).get("occurrences", [])
                for occ in occurrences:
                    location = occ.get("location", "")
                    if location:
                        loc_path = Path(location)
                        results[str(loc_path.resolve())] = SyftComponent(
                            name=name,
                            version=version,
                            purl=purl,
                            purl_type=purl_type,
                            file_path=loc_path,
                            description=comp.get("description"),
                            author=comp.get("publisher"),
                            is_syft_native=True,
                        )
    except Exception:
        pass

    return results


def extract_component_metadata(file_path: Path, syft_cache: Optional[Dict[str, SyftComponent]] = None) -> Optional[SyftComponent]:
    """
    Extracts component metadata for a given file using Syft cache or PE/archive metadata fallback.
    """
    resolved_str = str(file_path.resolve())
    if syft_cache and resolved_str in syft_cache:
        return syft_cache[resolved_str]

    ext = file_path.suffix.lower()
    if ext in {".exe", ".dll", ".sys", ".ocx"}:
        pe_comp = extract_pe_metadata_component(file_path)
        if pe_comp:
            return pe_comp

    # Handle JAR archives (e.g. log4j-core-2.14.1.jar)
    if ext == ".jar":
        match = re.search(r"^([a-zA-Z0-9_\.-]+?)-(\d+(\.\d+)+.*)\.jar$", file_path.name)
        if match:
            j_name = match.group(1)
            j_ver = match.group(2)
            namespace = "org.apache.logging.log4j" if "log4j" in j_name.lower() else "generic"
            purl = f"pkg:maven/{namespace}/{j_name}@{j_ver}"
            return SyftComponent(
                name=j_name,
                version=j_ver,
                purl=purl,
                purl_type="maven",
                file_path=file_path,
                is_syft_native=False,
            )

    return None
