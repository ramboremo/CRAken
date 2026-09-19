import argparse
import os
from pathlib import Path
import sys
import urllib.request
import zipfile
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from crascanner import __version__
from crascanner.config import Config
from crascanner.discovery import discover_files
from crascanner.fingerprint import fingerprint_files
from crascanner.identification.nsrl import NSRLDatabase, index_nsrl_rds_file
from crascanner.identification.signature import verify_signature
from crascanner.identification.catalog import HumanVerificationCatalog
from crascanner.identification.clearlydefined import ClearlyDefinedClient
from crascanner.identification.engine import ComponentIdentificationEngine
from crascanner.vulnerability.aggregator import ThreatIntelligenceAggregator
from crascanner.vex import apply_precision_filtering, PriorityTier
from crascanner.sbom import generate_cyclonedx_16_sbom
from crascanner.ai import AntigravityAIBridge
from crascanner.attribution import RootPackageAttributor
from crascanner.reporter import generate_html_report

console = Console()


def cmd_scan(args):
    target_path = Path(args.target).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    config = Config(
        target_dir=target_path,
        output_dir=output_dir,
        nsrl_db_path=Path(args.nsrl_db) if args.nsrl_db else None,
        syft_bin_path=args.syft_path,
        skip_ai=args.skip_ai,
    )

    console.print(Panel.fit(
        f"[bold cyan]CRAScanner v{__version__}[/bold cyan]\n"
        f"[dim]EU Cyber Resilience Act (CRA) Compliance & Threat Intelligence Engine[/dim]\n\n"
        f"[white]Target Directory:[/white] [yellow]{target_path}[/yellow]\n"
        f"[white]Output Directory:[/white] [green]{output_dir}[/green]\n"
        f"[white]NSRL Database:[/white] [blue]{config.nsrl_db_path or 'Curated Platform Hashes (Built-in)'}[/blue]\n"
        f"[white]AI Evaluation:[/white] [{'red' if config.skip_ai else 'green'}]{'Disabled (--skip-ai)' if config.skip_ai else 'Enabled (Antigravity CLI agy)'}[/{'red' if config.skip_ai else 'green'}]",
        title="[bold green]Scan Configuration[/bold green]",
        border_style="cyan"
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        # Step 1: Discovery
        t_disc = progress.add_task("[cyan]Step 1: Discovering files recursively...", total=1)
        discovered = discover_files(target_path)
        progress.update(t_disc, completed=1)

        # Step 2: Fingerprinting
        t_hash = progress.add_task(f"[cyan]Step 2: Fingerprinting {len(discovered)} files (BSI TR-03183-2)...", total=len(discovered))
        fingerprinted = fingerprint_files(discovered)
        progress.update(t_hash, completed=len(discovered))

        # Step 3: Component Identification Engine (4-Layer Funnel)
        t_ident = progress.add_task(f"[cyan]Step 3: 4-Layer Component Funnel (NSRL, Signatures, Syft, ClearlyDefined)...", total=len(fingerprinted))
        nsrl_db = NSRLDatabase(config.nsrl_db_path)
        catalog = HumanVerificationCatalog(config.catalog_path)
        clearlydefined = ClearlyDefinedClient(config.clearlydefined_api_url)
        ident_engine = ComponentIdentificationEngine(
            nsrl_db=nsrl_db,
            catalog=catalog,
            clearlydefined=clearlydefined,
            syft_bin=config.syft_bin_path,
        )
        identified_components = ident_engine.process_files(fingerprinted, target_path)
        progress.update(t_ident, completed=len(fingerprinted))

        # Step 4: Vulnerability & Threat Intelligence Querying
        t_threat = progress.add_task("[cyan]Step 4: Querying Threat Feeds (OSV, NVD, CISA KEV, ENISA EUVD, JVN)...", total=len(identified_components))
        threat_agg = ThreatIntelligenceAggregator(cache_dir=config.cache_dir)
        raw_findings = threat_agg.query_vulnerabilities_for_components(identified_components)
        progress.update(t_threat, completed=len(identified_components))

        # Step 5: Precision Filtering & False Positive Reduction
        t_vex = progress.add_task(f"[cyan]Step 5: Applying Precision Filtering & VEX Status to {len(raw_findings)} findings...", total=1)
        filtered_vulns = apply_precision_filtering(raw_findings)
        progress.update(t_vex, completed=1)

        # Step 7 (AI part): AI Evaluation & Root Package Attribution
        ai_bridge = AntigravityAIBridge(config.agy_bin_path)
        attributor = RootPackageAttributor(target_path, ai_bridge)

        t_ai = progress.add_task("[cyan]Step 7: AI Validation & Root Package Attribution...", total=len(filtered_vulns) or 1)
        for fv in filtered_vulns:
            # AI evaluation
            if not config.skip_ai and ai_bridge.is_available():
                verdict = ai_bridge.evaluate_vulnerability(
                    cve_id=fv.finding.primary_id,
                    component_name=fv.component.name,
                    component_version=fv.component.version,
                    file_path=fv.component.relative_path,
                    classification=fv.component.classification,
                )
                fv.ai_verdict = verdict.is_false_positive
                fv.ai_justification = verdict.justification
                if verdict.is_false_positive == "yes":
                    # Re-route confirmed false positive to Level 3
                    fv.priority_tier = PriorityTier.LEVEL_3

            # Root package attribution for Level 1 findings
            if fv.priority_tier == PriorityTier.LEVEL_1:
                fv.likely_source_package = attributor.attribute_root_package(
                    fv.component, identified_components
                )

            progress.update(t_ai, advance=1)

        # Step 6: CycloneDX 1.6 SBOM Generation
        t_sbom = progress.add_task("[cyan]Step 6: Generating CycloneDX 1.6 SBOM (bom.cdx.json)...", total=1)
        sbom_path = output_dir / config.bom_file
        generate_cyclonedx_16_sbom(target_path, identified_components, filtered_vulns, sbom_path)
        progress.update(t_sbom, completed=1)

        # Step 7 (Report part): HTML Report Generation
        t_rep = progress.add_task("[cyan]Step 7: Generating Executive HTML Dashboard...", total=1)
        report_path = output_dir / config.report_file
        generate_html_report(target_path, identified_components, filtered_vulns, report_path, config.bom_file)
        progress.update(t_rep, completed=1)

    # Display Executive Summary Table
    lvl_1_count = sum(1 for v in filtered_vulns if v.priority_tier == PriorityTier.LEVEL_1)
    lvl_2_count = sum(1 for v in filtered_vulns if v.priority_tier == PriorityTier.LEVEL_2)
    lvl_3_count = sum(1 for v in filtered_vulns if v.priority_tier == PriorityTier.LEVEL_3)

    summary_table = Table(title="[bold]Scan Execution Summary[/bold]", border_style="cyan")
    summary_table.add_column("Metric", style="white", justify="left")
    summary_table.add_column("Value", style="bold green", justify="right")

    summary_table.add_row("Total Discovered Files", str(len(discovered)))
    summary_table.add_row("Identified Components", str(sum(1 for c in identified_components if c.is_identified)))
    summary_table.add_row("Level 1 (Active/Critical - KEV/EUVD)", f"[bold red]{lvl_1_count}[/bold red]")
    summary_table.add_row("Level 2 (Moderate Actionable)", f"[yellow]{lvl_2_count}[/yellow]")
    summary_table.add_row("Level 3 (Low / Suppressed / Platform)", f"[cyan]{lvl_3_count}[/cyan]")
    summary_table.add_row("CycloneDX 1.6 SBOM", str(sbom_path))
    summary_table.add_row("Interactive HTML Report", str(report_path))

    console.print()
    console.print(summary_table)
    console.print()

    if lvl_1_count > 0:
        console.print(Panel(
            f"[bold red]CRITICAL: CRA ARTICLE 14 ALERT TRIGGERED![/bold red]\n"
            f"{lvl_1_count} actively exploited vulnerabilities (KEV/EUVD) detected in product code.\n"
            f"Under EU CRA Article 14, manufacturers must notify ENISA and CSIRTs within 24 hours.",
            border_style="red"
        ))
    else:
        console.print(Panel(
            "[bold green][OK] CRA COMPLIANCE CHECK PASSED[/bold green]\n"
            "No actively exploited vulnerabilities (KEV/EUVD) detected in product components.",
            border_style="green"
        ))


def cmd_index_nsrl(args):
    """Utility command to index a NIST NSRL RDS file into SQLite."""
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()

    console.print(f"[cyan]Indexing NIST NSRL RDS file:[/cyan] {source}")
    console.print(f"[cyan]Target SQLite database:[/cyan] {output}")

    count = index_nsrl_rds_file(source, output)
    console.print(f"[bold green]Successfully indexed {count:,} NSRL records into {output}![/bold green]")


def cmd_setup_tools(args):
    """Utility command to download Syft for Windows into .tools/ if not installed."""
    tools_dir = Path("./.tools").resolve()
    tools_dir.mkdir(parents=True, exist_ok=True)
    syft_exe = tools_dir / "syft.exe"

    if syft_exe.exists():
        console.print(f"[green]Syft already installed at: {syft_exe}[/green]")
        return

    console.print("[cyan]Downloading Syft for Windows (x86_64)...[/cyan]")
    syft_url = "https://github.com/anchore/syft/releases/latest/download/syft_windows_amd64.zip"
    zip_path = tools_dir / "syft.zip"

    try:
        urllib.request.urlretrieve(syft_url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extract("syft.exe", path=tools_dir)
        zip_path.unlink(missing_ok=True)
        console.print(f"[bold green][OK] Syft successfully installed to {syft_exe}![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to download Syft: {e}[/bold red]")


def main():
    parser = argparse.ArgumentParser(
        prog="crascanner",
        description="EU Cyber Resilience Act (CRA) Compliance Scanner & SBOM Generator",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a directory for CRA compliance")
    p_scan.add_argument("target", help="Path to installation directory to scan")
    p_scan.add_argument("-o", "--output-dir", default="./output", help="Directory to store SBOM and HTML report")
    p_scan.add_argument("--nsrl-db", default=None, help="Path to NIST NSRL SQLite database")
    p_scan.add_argument("--syft-path", default=None, help="Custom path to syft binary")
    p_scan.add_argument("--skip-ai", action="store_true", help="Skip AI evaluation via Antigravity CLI")
    p_scan.set_defaults(func=cmd_scan)

    # index-nsrl
    p_nsrl = subparsers.add_parser("index-nsrl", help="Index a raw NIST NSRL RDS file into SQLite")
    p_nsrl.add_argument("source", help="Path to NSRLFile.txt or RDS CSV")
    p_nsrl.add_argument("-o", "--output", default="./nsrl.db", help="Output SQLite database path")
    p_nsrl.set_defaults(func=cmd_index_nsrl)

    # setup-tools
    p_tools = subparsers.add_parser("setup-tools", help="Download external tools (Syft) into .tools/")
    p_tools.set_defaults(func=cmd_setup_tools)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
