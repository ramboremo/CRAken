from datetime import datetime
import html
import json
from pathlib import Path
from typing import Dict, List, Optional
from crascanner.identification.engine import IdentifiedComponent
from crascanner.vex import FilteredVulnerability, PriorityTier


def escape(val: Optional[str]) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def generate_html_report(
    target_dir: Path,
    all_components: List[IdentifiedComponent],
    vulnerabilities: List[FilteredVulnerability],
    output_file: Path,
    bom_file_name: str = "bom.cdx.json",
) -> Path:
    """
    Step 7: HTML Report Generation.
    Produces an interactive, ultra-modern dashboard implementing the exact 14-column schema,
    grouped into 3 collapsible sections by Priority Tier.
    Only components with at least one matched vulnerability appear in the dashboard.
    """
    output_file = Path(output_file).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Separate findings into the three Priority Tiers
    level_1: List[FilteredVulnerability] = []
    level_2: List[FilteredVulnerability] = []
    level_3: List[FilteredVulnerability] = []

    for fv in vulnerabilities:
        if fv.priority_tier == PriorityTier.LEVEL_1:
            level_1.append(fv)
        elif fv.priority_tier == PriorityTier.LEVEL_2:
            level_2.append(fv)
        else:
            level_3.append(fv)

    # Calculate executive metrics
    total_files = len(all_components)
    total_identified = sum(1 for c in all_components if c.is_identified)
    level_1_count = len(level_1)
    level_2_count = len(level_2)
    level_3_count = len(level_3)
    cra_alert_active = level_1_count > 0

    scan_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    target_name = target_dir.name or str(target_dir)

    def render_table_rows(items: List[FilteredVulnerability], is_level_1: bool) -> str:
        if not items:
            return '<tr><td colspan="14" class="empty-msg">No findings in this priority tier.</td></tr>'

        rows = []
        for i, item in enumerate(items):
            f = item.finding
            c = f.component

            # Column 1: File Path
            file_path_html = f'<div class="path-cell" title="{escape(c.relative_path)}">{escape(c.relative_path)}</div>'

            # Column 2: File Hash (SHA-256)
            hash_short = c.sha256[:12] + "..." + c.sha256[-8:]
            hash_html = f'<code class="hash-badge" title="{c.sha256}">{hash_short}</code>'

            # Column 3: Component Name & Version
            comp_html = f'<div class="comp-title"><strong>{escape(c.name)}</strong> <span class="ver-tag">v{escape(c.version)}</span></div>'

            # Column 4: PURL
            purl_short = c.purl if len(c.purl) <= 35 else c.purl[:32] + "..."
            purl_html = f'<code class="purl-badge" title="{escape(c.purl)}">{escape(purl_short)}</code>'

            # Column 5: Confidence Level (1-4)
            conf_class = f"conf-l{c.confidence_level}"
            conf_html = f'<span class="badge {conf_class}" title="{escape(c.confidence_description)}">Level {c.confidence_level}</span>'

            # Column 6: Publisher/Signature Verified?
            if c.publisher_verified:
                sig_html = '<span class="badge badge-success">✓ Verified</span>'
            elif c.signature and c.signature.flag:
                sig_html = f'<span class="badge badge-danger" title="{escape(c.signature.flag)}">⚠ Mismatch</span>'
            elif c.signature and c.signature.is_signed:
                sig_html = f'<span class="badge badge-warning" title="{escape(c.signature.status)}">Signed (Unverified)</span>'
            else:
                sig_html = '<span class="badge badge-neutral">Unsigned</span>'

            # Column 7: Classification
            class_badge = "badge-platform" if c.is_platform else "badge-product"
            class_html = f'<span class="badge {class_badge}">{escape(c.classification)}</span>'

            # Column 8: CVE ID(s)
            cve_links = []
            ids_to_show = f.all_ids if f.all_ids else [f.cve_id or f.primary_id]
            for cid in ids_to_show[:3]:
                if not cid:
                    continue
                if cid.startswith("CVE-"):
                    cve_links.append(f'<a href="https://nvd.nist.gov/vuln/detail/{cid}" target="_blank" class="cve-link">{escape(cid)}</a>')
                elif cid.startswith("GHSA-"):
                    cve_links.append(f'<a href="https://github.com/advisories/{cid}" target="_blank" class="cve-link">{escape(cid)}</a>')
                else:
                    cve_links.append(f'<span class="cve-tag">{escape(cid)}</span>')
            if len(ids_to_show) > 3:
                cve_links.append(f'<span class="cve-more">+{len(ids_to_show)-3}</span>')
            cve_html = '<div class="cve-stack">' + " ".join(cve_links) + '</div>'

            # Column 9: CVSS Severity
            score_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            sev_class = f"sev-{f.cvss_severity.lower()}"
            sev_html = f'<span class="badge {sev_class}">{score_str} {escape(f.cvss_severity)}</span>'

            # Column 10: Actively Exploited?
            if f.is_actively_exploited:
                exploit_src = f.active_exploitation_source or "Active Feed"
                exploit_html = f'<span class="badge badge-alert-blink" title="{escape(exploit_src)}">🚨 YES ({escape(exploit_src)})</span>'
            else:
                exploit_html = '<span class="badge badge-neutral">No</span>'

            # Column 11: VEX Status
            vex_class = "vex-suppressed" if "Not Affected" in item.vex_status else "vex-affected"
            vex_html = f'<span class="badge {vex_class}" title="{escape(item.vex_justification)}">{escape(item.vex_status)}</span>'

            # Column 12: AI Verdict
            ai_verdict = item.ai_verdict or "no"
            ai_badge = "badge-fp" if ai_verdict.lower() == "yes" else "badge-tp"
            ai_text = "False Positive" if ai_verdict.lower() == "yes" else "Valid Finding"
            ai_html = f'<span class="badge {ai_badge}">{ai_text}</span>'

            # Column 13: AI Justification
            just_text = item.ai_justification or item.vex_justification
            ai_just_html = f'<div class="just-text" title="{escape(just_text)}">{escape(just_text)}</div>'

            # Column 14: Likely Source Package (Level 1 only)
            if is_level_1:
                pkg_val = item.likely_source_package or "Direct Root Component"
                pkg_html = f'<div class="pkg-cell"><code>{escape(pkg_val)}</code></div>'
            else:
                pkg_html = '<div class="pkg-cell text-muted">—</div>'

            rows.append(f"""
            <tr class="finding-row" data-severity="{escape(f.cvss_severity.lower())}" data-tier="{item.priority_tier.value}">
                <td class="col-path">{file_path_html}</td>
                <td class="col-hash">{hash_html}</td>
                <td class="col-comp">{comp_html}</td>
                <td class="col-purl">{purl_html}</td>
                <td class="col-conf">{conf_html}</td>
                <td class="col-sig">{sig_html}</td>
                <td class="col-class">{class_html}</td>
                <td class="col-cve">{cve_html}</td>
                <td class="col-sev">{sev_html}</td>
                <td class="col-exploit">{exploit_html}</td>
                <td class="col-vex">{vex_html}</td>
                <td class="col-ai">{ai_html}</td>
                <td class="col-just">{ai_just_html}</td>
                <td class="col-source">{pkg_html}</td>
            </tr>
            """)
        return "\n".join(rows)

    table_headers = """
    <thead>
        <tr>
            <th>#1 File Path</th>
            <th>#2 File Hash (SHA-256)</th>
            <th>#3 Component & Version</th>
            <th>#4 PURL</th>
            <th>#5 Confidence</th>
            <th>#6 Signature Verified?</th>
            <th>#7 Classification</th>
            <th>#8 CVE ID(s)</th>
            <th>#9 CVSS Severity</th>
            <th>#10 Actively Exploited?</th>
            <th>#11 VEX Status</th>
            <th>#12 AI Verdict</th>
            <th>#13 AI Justification</th>
            <th>#14 Likely Source Package</th>
        </tr>
    </thead>
    """

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CRA Compliance & Threat Intelligence Dashboard — {escape(target_name)}</title>
    <style>
        :root {{
            --bg-body: #0a0e17;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --bg-card-hover: #283548;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --border-color: #374151;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --critical-red: #ef4444;
            --critical-glow: rgba(239, 68, 68, 0.35);
            --warning-amber: #f59e0b;
            --success-green: #10b981;
            --purple: #8b5cf6;
            --badge-radius: 6px;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }}

        [data-theme="light"] {{
            --bg-body: #f8fafc;
            --bg-surface: #ffffff;
            --bg-card: #f1f5f9;
            --bg-card-hover: #e2e8f0;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --border-color: #cbd5e1;
            --critical-glow: rgba(239, 68, 68, 0.15);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: var(--font-sans);
            background-color: var(--bg-body);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 24px;
        }}

        .container {{ max-width: 1720px; margin: 0 auto; }}

        /* Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        }}
        .header-title h1 {{
            font-size: 24px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-meta {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .btn {{
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .btn:hover {{ background: var(--bg-card-hover); border-color: var(--accent-cyan); }}
        .btn-primary {{
            background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%);
            border: none;
            color: #ffffff;
        }}
        .btn-primary:hover {{ opacity: 0.9; }}

        /* Alert Banner */
        .cra-banner {{
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px 20px;
            border-radius: 10px;
            margin-bottom: 24px;
            font-weight: 500;
            box-shadow: 0 0 25px var(--critical-glow);
        }}
        .cra-banner.alert-active {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid var(--critical-red);
            color: #fca5a5;
        }}
        .cra-banner.alert-clean {{
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid var(--success-green);
            color: #6ee7b7;
        }}
        .cra-banner .icon {{ font-size: 24px; }}

        /* Metric Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .metric-card .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}
        .metric-card .value {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .metric-card.critical .value {{ color: var(--critical-red); text-shadow: 0 0 12px var(--critical-glow); }}
        .metric-card.moderate .value {{ color: var(--warning-amber); }}
        .metric-card.ignored .value {{ color: var(--accent-cyan); }}

        /* Filter Controls */
        .filter-bar {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .search-box {{
            flex: 1;
            max-width: 400px;
            position: relative;
        }}
        .search-box input {{
            width: 100%;
            padding: 8px 14px;
            background: var(--bg-body);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 13px;
        }}
        .search-box input:focus {{ outline: none; border-color: var(--accent-cyan); }}

        /* Sections & Accordions */
        .tier-section {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .tier-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }}
        .tier-header:hover {{ background: var(--bg-card-hover); }}
        .tier-header-left {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .tier-header-left h2 {{
            font-size: 16px;
            font-weight: 700;
        }}
        .tier-1-badge {{ background: var(--critical-red); color: white; }}
        .tier-2-badge {{ background: var(--warning-amber); color: #000; }}
        .tier-3-badge {{ background: #4b5563; color: white; }}

        .tier-desc {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-left: 10px;
        }}
        .chevron {{
            font-size: 14px;
            transition: transform 0.2s;
        }}
        .tier-section.collapsed .chevron {{ transform: rotate(-90deg); }}
        .tier-section.collapsed .tier-content {{ display: none; }}

        /* Table Styles */
        .table-wrap {{
            overflow-x: auto;
            width: 100%;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12.5px;
            text-align: left;
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            font-weight: 600;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            white-space: nowrap;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr:hover td {{ background: var(--bg-card); }}

        /* Cell Formatters */
        .path-cell {{
            font-family: var(--font-mono);
            max-width: 180px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 11.5px;
        }}
        .hash-badge {{
            font-family: var(--font-mono);
            font-size: 11px;
            background: rgba(255,255,255,0.05);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }}
        .purl-badge {{
            font-family: var(--font-mono);
            font-size: 11px;
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.08);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .comp-title {{
            font-weight: 600;
        }}
        .ver-tag {{
            font-size: 11px;
            color: var(--text-secondary);
            background: var(--bg-card);
            padding: 1px 5px;
            border-radius: 3px;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: var(--badge-radius);
            white-space: nowrap;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #10b981; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid #ef4444; }}
        .badge-neutral {{ background: rgba(107, 114, 128, 0.2); color: #9ca3af; }}
        .badge-platform {{ background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid #8b5cf6; }}
        .badge-product {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid #3b82f6; }}
        .badge-alert-blink {{
            background: var(--critical-red);
            color: white;
            font-weight: 700;
            animation: pulse 1.5s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.6; }}
        }}

        .conf-l1 {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
        .conf-l2 {{ background: rgba(139, 92, 246, 0.2); color: #c084fc; }}
        .conf-l3 {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
        .conf-l4 {{ background: rgba(107, 114, 128, 0.2); color: #9ca3af; }}

        .sev-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .sev-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .sev-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .sev-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
        .sev-unknown {{ background: rgba(107, 114, 128, 0.2); color: #9ca3af; }}

        .vex-affected {{ background: rgba(239, 68, 68, 0.15); color: #fca5a5; }}
        .vex-suppressed {{ background: rgba(16, 185, 129, 0.12); color: #6ee7b7; }}

        .badge-fp {{ background: rgba(16, 185, 129, 0.15); color: #34d399; }}
        .badge-tp {{ background: rgba(239, 68, 68, 0.15); color: #f87171; }}

        .cve-stack {{ display: flex; flex-wrap: wrap; gap: 4px; }}
        .cve-link {{
            color: #38bdf8;
            text-decoration: none;
            background: rgba(56, 189, 248, 0.1);
            padding: 1px 5px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 11px;
        }}
        .cve-link:hover {{ text-decoration: underline; }}
        .cve-tag {{ font-family: var(--font-mono); font-size: 11px; background: rgba(255,255,255,0.05); padding: 1px 5px; border-radius: 3px; }}

        .just-text {{
            max-width: 220px;
            font-size: 11.5px;
            color: var(--text-secondary);
            overflow: hidden;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
        }}

        .pkg-cell {{
            font-family: var(--font-mono);
            font-size: 11px;
            color: #fbbf24;
            max-width: 140px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .empty-msg {{
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-style: italic;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 12px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="header-title">
                <h1>🛡 EU Cyber Resilience Act (CRA) Scanner</h1>
                <div class="header-meta">
                    Target: <strong>{escape(target_name)}</strong> &bull;
                    Scanned: {scan_date} &bull;
                    Standard: BSI TR-03183-2 &bull;
                    CycloneDX 1.6 VEX
                </div>
            </div>
            <div class="header-actions">
                <button class="btn" onclick="toggleTheme()">🌓 Toggle Theme</button>
                <a href="{bom_file_name}" download class="btn btn-primary">📥 Download CycloneDX SBOM</a>
            </div>
        </header>

        <!-- CRA Article 14 Alert Banner -->
        <div class="cra-banner {'alert-active' if cra_alert_active else 'alert-clean'}">
            <span class="icon">{'🚨' if cra_alert_active else '✅'}</span>
            <div>
                <strong>{'CRA Article 14 Alert Triggered' if cra_alert_active else 'No Active Exploits Detected'}</strong>:
                {'Actively exploited vulnerabilities (KEV/EUVD) detected in product code! Under CRA Article 14, manufacturers must notify ENISA and CSIRTs within 24 hours.' if cra_alert_active else 'No actively exploited vulnerabilities detected in scanned product components.'}
            </div>
        </div>

        <!-- Metric Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <span class="label">Total Files Discovered</span>
                <span class="value">{total_files}</span>
            </div>
            <div class="metric-card">
                <span class="label">Identified Components</span>
                <span class="value">{total_identified}</span>
            </div>
            <div class="metric-card critical">
                <span class="label">Level 1 (Active/Critical)</span>
                <span class="value">{level_1_count}</span>
            </div>
            <div class="metric-card moderate">
                <span class="label">Level 2 (Moderate Actionable)</span>
                <span class="value">{level_2_count}</span>
            </div>
            <div class="metric-card ignored">
                <span class="label">Level 3 (Platform / Suppressed)</span>
                <span class="value">{level_3_count}</span>
            </div>
        </div>

        <!-- Filter Controls -->
        <div class="filter-bar">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by file, component, CVE, or hash..." onkeyup="filterRows()">
            </div>
            <div>
                <span style="font-size: 13px; color: var(--text-secondary); margin-right: 12px;">Collapsible Tiers:</span>
                <button class="btn" onclick="toggleAllSections(true)">Expand All</button>
                <button class="btn" onclick="toggleAllSections(false)">Collapse All</button>
            </div>
        </div>

        <!-- Section 1: Level 1 (Active/Critical) -->
        <div class="tier-section" id="section-tier-1">
            <div class="tier-header" onclick="toggleSection('section-tier-1')">
                <div class="tier-header-left">
                    <span class="badge tier-1-badge">Level 1</span>
                    <h2>Active / Critical Vulnerabilities (KEV & EUVD)</h2>
                    <span class="tier-desc">Actively exploited threats triggering CRA Article 14 24-hour reporting requirement</span>
                </div>
                <div>
                    <span class="badge tier-1-badge">{level_1_count} Findings</span>
                    <span class="chevron">▼</span>
                </div>
            </div>
            <div class="tier-content">
                <div class="table-wrap">
                    <table>
                        {table_headers}
                        <tbody>
                            {render_table_rows(level_1, is_level_1=True)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Section 2: Level 2 (Moderate) -->
        <div class="tier-section" id="section-tier-2">
            <div class="tier-header" onclick="toggleSection('section-tier-2')">
                <div class="tier-header-left">
                    <span class="badge tier-2-badge">Level 2</span>
                    <h2>Moderate / Standard Actionable Findings</h2>
                    <span class="tier-desc">Standard CVSS-based findings in product components for regular sprint cycle remediation</span>
                </div>
                <div>
                    <span class="badge tier-2-badge">{level_2_count} Findings</span>
                    <span class="chevron">▼</span>
                </div>
            </div>
            <div class="tier-content">
                <div class="table-wrap">
                    <table>
                        {table_headers}
                        <tbody>
                            {render_table_rows(level_2, is_level_1=False)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Section 3: Level 3 (Low/Ignored) -->
        <div class="tier-section" id="section-tier-3">
            <div class="tier-header" onclick="toggleSection('section-tier-3')">
                <div class="tier-header-left">
                    <span class="badge tier-3-badge">Level 3</span>
                    <h2>Low / Suppressed / Platform Infrastructure</h2>
                    <span class="tier-desc">Confirmed false positives, unreachable code, or platform OS noise (VEX: Not Affected)</span>
                </div>
                <div>
                    <span class="badge tier-3-badge">{level_3_count} Findings</span>
                    <span class="chevron">▼</span>
                </div>
            </div>
            <div class="tier-content">
                <div class="table-wrap">
                    <table>
                        {table_headers}
                        <tbody>
                            {render_table_rows(level_3, is_level_1=False)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer>
            Generated by <strong>CRAScanner v0.1.0</strong> &bull; Open-source EU Cyber Resilience Act compliance automation engine.
        </footer>
    </div>

    <script>
        function toggleTheme() {{
            const html = document.documentElement;
            const current = html.getAttribute('data-theme');
            html.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
        }}

        function toggleSection(id) {{
            const el = document.getElementById(id);
            if (el) {{
                el.classList.toggle('collapsed');
            }}
        }}

        function toggleAllSections(expand) {{
            ['section-tier-1', 'section-tier-2', 'section-tier-3'].forEach(id => {{
                const el = document.getElementById(id);
                if (el) {{
                    if (expand) el.classList.remove('collapsed');
                    else el.classList.add('collapsed');
                }}
            }});
        }}

        function filterRows() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_file
