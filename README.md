# CRAken 🐙

### The EU Cyber Resilience Act (CRA) Compliance Scanner & SBOM Engine

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Standard](https://img.shields.io/badge/CRA-EU_2024%2F2847-green.svg)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
[![Integrity](https://img.shields.io/badge/Integrity-BSI_TR--03183--2-success.svg)](https://www.bsi.bund.de/)

**CRAken** is a production-grade, open-source compliance engine and SBOM generator designed to meet the rigorous requirements of the **EU Cyber Resilience Act (CRA)**.

It automates end-to-end component discovery, cryptographic integrity fingerprinting, a 4-layer identification funnel (NSRL, Authenticode signatures, Syft, and ClearlyDefined), multi-source threat intelligence aggregation (OSV, NVD, CISA KEV, ENISA EUVD, JVN), precision VEX false-positive filtering, official **CycloneDX 1.6 SBOM** generation (`bom.cdx.json`), and **AI-powered vulnerability validation** with deterministic **Root Package Attribution**.

---

## ⚡ Quick Start for New Users

### 1. Clone & Setup
```bash
git clone https://github.com/your-org/crascanner.git
cd crascanner
```

#### Windows (One-Click Setup)
```powershell
.\setup.ps1
```
Or manually:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

#### Linux / macOS
```bash
chmod +x setup.sh
./setup.sh
```

---

## 🚀 Usage

### Standard Scan
```bash
crascanner scan "C:\path\to\your\application" --output-dir ./output
```

### Full NSRL Database Mode
To query against the full NIST NSRL RDS database:
```bash
# 1. Index raw NSRL RDS file into fast SQLite database
crascanner index-nsrl "C:\path\to\NSRLFile.txt" --output ./nsrl.db

# 2. Run scan with NSRL database
crascanner scan "C:\path\to\app" --nsrl-db ./nsrl.db --output-dir ./output
```

---

## 🏗 Architecture & The 7 Steps

1. **Step 1: Discovery**: Recursive inventory of all installation files, sizes, and MIME types.
2. **Step 2: Fingerprinting**: SHA-256 and SHA-512 checksums (BSI TR-03183-2 compliance).
3. **Step 3: Component Identification Engine (The 4-Layer Funnel)**:
   - **Layer 1a — NSRL Filter**: Local NIST NSRL hash lookup. Identifies OS/Microsoft platform components without dropping them from the audit pipeline.
   - **Layer 1b — Digital Signature Verification**: Authenticode certificate chain verification. Flags publisher mismatches.
   - **Layer 2 — Syft Extraction**: Subprocess extraction of VERSIONINFO / assembly metadata to generate standard PURLs in CycloneDX format.
   - **Layer 3 — ClearlyDefined**: Supplemental license and provenance backfill for open-source components.
   - **Layer 4 — Human Verification**: Centralized persistent lookup table (`.crascanner_catalog.json`) for unclassified files.
4. **Step 4: Threat Intelligence & Vulnerability Querying**:
   - **OSV.dev** (native PURL queries)
   - **NIST NVD 2.0** (CVE baseline & CVSS)
   - **CISA KEV & ENISA EUVD** (Actively exploited threats — CRA Article 14 24h reporting window)
   - **JVN iPedia** & GitHub Advisories
5. **Step 5: Precision Filtering & False Positive Reduction**:
   - Routes `Platform/Infrastructure` to Level 3 with official VEX tag: `"Not Affected — Managed by Platform/OS"`.
   - Preserves `Product Code` as actionable Level 1 (Actively Exploited) or Level 2 (Standard CVSS).
6. **Step 6: CycloneDX 1.6 SBOM Generation**:
   - Emits `bom.cdx.json` with components, hashes, PURLs, signatures, and VEX vulnerability records.
7. **Step 7: AI Validation & Root Package Attribution**:
   - AI CVE false-positive evaluation using **Antigravity CLI (`agy`)**.
   - Deterministic root package attribution via `.deps.json` / `packages.lock.json` dependency graph parsing, with AI fallback.
   - Executive interactive HTML dashboard with exact 14-column schema.

---

## 📄 License
This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
