from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Optional, Tuple
import pefile


@dataclass
class SignatureResult:
    """Result of Layer 1b Authenticode Digital Signature Verification."""
    is_signed: bool
    is_valid: bool
    status: str
    signer_subject: Optional[str] = None
    signer_issuer: Optional[str] = None
    claimed_publisher: Optional[str] = None
    claimed_microsoft: bool = False
    flag: Optional[str] = None


def extract_pe_claimed_publisher(file_path: Path) -> Tuple[Optional[str], bool]:
    """
    Reads VS_VERSIONINFO from a PE file to check claimed publisher / company.
    Returns (claimed_publisher, claims_microsoft).
    """
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for key, val in st.entries.items():
                                key_str = key.decode("utf-8", errors="ignore").lower() if isinstance(key, bytes) else str(key).lower()
                                val_str = val.decode("utf-8", errors="ignore") if isinstance(val, bytes) else str(val)
                                if key_str in ("companyname", "legalcopyright", "productname"):
                                    val_lower = val_str.lower()
                                    if "microsoft" in val_lower or "windows" in val_lower:
                                        return val_str, True
                                    if key_str == "companyname":
                                        return val_str, False
        pe.close()
    except Exception:
        pass
    return None, False


def verify_authenticode_powershell(file_path: Path) -> Tuple[bool, bool, str, Optional[str], Optional[str]]:
    """
    Uses Windows PowerShell Get-AuthenticodeSignature to cryptographically verify signature chain.
    Returns (is_signed, is_valid, status, subject, issuer).
    """
    escaped_path = str(file_path).replace("'", "''")
    ps_cmd = (
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
        f"$res = [PSCustomObject]@{{ "
        f"Status = $sig.Status.ToString(); "
        f"Subject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ '' }}; "
        f"Issuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ '' }} "
        f"}} ; "
        f"$res | ConvertTo-Json -Compress"
    )

    try:
        output = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stderr=subprocess.DEVNULL,
            timeout=15,
            text=True,
        )
        data = json.loads(output.strip())
        status = data.get("Status", "Unknown")
        subject = data.get("Subject") or None
        issuer = data.get("Issuer") or None

        is_signed = status not in ("NotSigned", "Unknown")
        is_valid = status == "Valid"
        return is_signed, is_valid, status, subject, issuer
    except Exception:
        return False, False, "VerificationError", None, None


def verify_signature(file_path: Path) -> SignatureResult:
    """
    Step 3 Layer 1b: Digital Signature Verification.
    - Reads embedded Authenticode certificate (if present).
    - Cryptographically verifies signature chain.
    - Case A: Authentic -> Valid signature.
    - Case B: Missing, invalid, or fails. If claims Microsoft but fails ->
              Flagged "Signature Verification Failed — Claimed Publisher Mismatch".
    """
    ext = file_path.suffix.lower()
    is_pe = ext in {".exe", ".dll", ".sys", ".ocx", ".com", ".scr", ".cpl", ".drv", ".efi"}

    if not is_pe or not file_path.exists():
        return SignatureResult(
            is_signed=False,
            is_valid=False,
            status="Not Applicable",
            claimed_publisher=None,
            claimed_microsoft=False,
            flag=None,
        )

    # 1. Extract claimed publisher from PE metadata
    claimed_pub, claims_ms = extract_pe_claimed_publisher(file_path)

    # 2. Cryptographically verify Authenticode signature
    is_signed, is_valid, status, subject, issuer = verify_authenticode_powershell(file_path)

    flag: Optional[str] = None
    if claims_ms and not is_valid:
        flag = "Signature Verification Failed — Claimed Publisher Mismatch"

    return SignatureResult(
        is_signed=is_signed,
        is_valid=is_valid,
        status=status,
        signer_subject=subject,
        signer_issuer=issuer,
        claimed_publisher=claimed_pub,
        claimed_microsoft=claims_ms,
        flag=flag,
    )
