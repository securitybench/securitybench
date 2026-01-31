"""Command-line interface for Security Bench.

Provides CLI commands for scanning, describing tests, and initialization.
"""
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

# Auto-load .env file from current directory or parent directories
# This ensures API keys are available without manual sourcing
load_dotenv()

from .config import PipelineConfig, ConfigError
from .bench import SecurityBench, ScanResults
from .loader import TestLoader
from .reports import ReportFormatter, Reporter
from .auditor import Auditor, AuditResults
from .output import AuditOutput, format_audit_json


@click.group()
@click.version_option(version="0.2.11", prog_name="sb")
def main():
    """Security Bench CLI - Test LLM pipelines for security vulnerabilities."""
    pass


@main.command()
@click.argument('endpoint', required=False)
@click.option('--config', '-c', type=click.Path(exists=True), help='Config file path')
@click.option('--model', '-m', help='Model name (for Ollama endpoints)')
@click.option('--header', '-H', multiple=True, help='Custom header (e.g., "Authorization: Bearer key")')
@click.option('--categories', type=str, help='Filter categories: SPE,PIN,JBR')
@click.option('--severity', type=str, help='Filter severity: critical,high,medium,low')
@click.option('--limit', '-l', default=50, help='Max tests to run')
@click.option('--balanced', '-b', is_flag=True, help='Sample evenly across all categories')
@click.option('--per-category', default=5, help='Tests per category (with --balanced)')
@click.option('--dry-run', is_flag=True, help='Show what would run without executing')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json', 'markdown']), default='text')
@click.option('--save', type=click.Path(), help='Save results to file')
@click.option('--submit', is_flag=True, help='Submit results to leaderboard')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--delay', type=float, default=0, help='Delay between API calls (seconds)')
def scan(
    endpoint: Optional[str],
    config: Optional[str],
    model: Optional[str],
    header: tuple,
    categories: Optional[str],
    severity: Optional[str],
    limit: int,
    balanced: bool,
    per_category: int,
    dry_run: bool,
    output_format: str,
    save: Optional[str],
    submit: bool,
    verbose: bool,
    delay: float,
):
    """Scan an LLM endpoint for security vulnerabilities.

    ENDPOINT is the Ollama API URL (e.g., http://192.168.1.50:11434)

    Returns responses with judging criteria for LLM evaluation.
    Use Claude or another LLM to judge pass/fail based on the criteria.
    """
    # Need either endpoint or config
    if not endpoint and not config:
        raise click.ClickException("Must provide either ENDPOINT or --config")

    # Parse categories/severity filters
    cat_list = [c.strip() for c in categories.split(',')] if categories else None
    sev_list = [s.strip() for s in severity.split(',')] if severity else None

    # Load or build config
    # Parse custom headers
    custom_headers = {}
    for h in header:
        if ':' in h:
            key, value = h.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    if config:
        try:
            pipeline_config = PipelineConfig.from_yaml(Path(config))
        except ConfigError as e:
            raise click.ClickException(str(e))
    else:
        # Build config from endpoint URL
        from .config import EndpointConfig, InputConfig, OutputConfig

        # Normalize URL: strip trailing /v1 suffix (common mistake)
        normalized_endpoint = endpoint.rstrip('/')
        if normalized_endpoint.endswith('/v1'):
            normalized_endpoint = normalized_endpoint[:-3]
            if verbose:
                click.echo(f"[Note] Stripped /v1 suffix from URL: {normalized_endpoint}")

        # Detect endpoint type
        if 'ollama' in normalized_endpoint.lower() or ':11434' in normalized_endpoint:
            input_format = "ollama"
            response_path = "message.content"
            api_url = normalized_endpoint + "/api/chat"
        elif '/v1' in endpoint:
            # vLLM or OpenAI-compatible API (original URL had /v1)
            input_format = "openai"
            response_path = "choices[0].message.content"
            api_url = normalized_endpoint + "/v1/chat/completions"
        else:
            input_format = "json"
            response_path = "response"
            api_url = normalized_endpoint

        pipeline_config = PipelineConfig(
            endpoint=EndpointConfig(url=api_url, model=model, headers=custom_headers or None),
            input=InputConfig(format=input_format, model=model),
            output=OutputConfig(response_path=response_path),
        )

    # Dry run mode
    if dry_run:
        if output_format == 'json':
            click.echo(json.dumps({
                "mode": "dry_run",
                "endpoint": pipeline_config.endpoint.url,
                "model": model,
                "categories": cat_list,
                "severity": sev_list,
                "limit": limit,
            }, indent=2))
        else:
            click.echo(f"Dry run mode - would scan {endpoint or config}")
            click.echo(f"  Endpoint: {pipeline_config.endpoint.url}")
            if model:
                click.echo(f"  Model: {model}")
            if cat_list:
                click.echo(f"  Categories: {', '.join(cat_list)}")
            if sev_list:
                click.echo(f"  Severity: {', '.join(sev_list)}")
            click.echo(f"  Limit: {limit}")
        return

    # Auto-generate save path if not specified (LLM-friendly: always save results)
    if save:
        final_save_path = Path(save)
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        final_save_path = Path(f"sb_scan_{timestamp}.json")

    # Run the actual scan (with incremental save)
    results = asyncio.run(_run_scan(
        pipeline_config,
        categories=cat_list,
        severity=sev_list,
        limit=limit,
        balanced=balanced,
        per_category=per_category,
        verbose=verbose,
        delay=delay,
        save_path=final_save_path,
    ))

    # Get endpoint URL for metadata
    endpoint_url = pipeline_config.endpoint.url if pipeline_config.endpoint else endpoint

    # Format and display results (pass metadata for LLM-friendly output)
    formatter = ReportFormatter(
        format=output_format,
        endpoint=endpoint_url,
        model=model,
        save_path=str(final_save_path),
    )
    output = formatter.format(results)
    click.echo(output)

    # Save results with embedded instructions
    with open(final_save_path, 'w') as f:
        if output_format in ('json', 'markdown'):
            f.write(output)
        else:
            # Always save as JSON with instructions for LLM analysis
            json_formatter = ReportFormatter(
                format='json',
                endpoint=endpoint_url,
                model=model,
            )
            f.write(json_formatter.format(results))

    # Submit to leaderboard if requested
    if submit and model:
        reporter = Reporter()
        url = asyncio.run(reporter.submit_to_leaderboard(model, results))
        if url:
            click.echo(f"Submitted to leaderboard: {url}")


async def _run_scan(
    config: PipelineConfig,
    categories: Optional[list[str]] = None,
    severity: Optional[list[str]] = None,
    limit: int = 50,
    balanced: bool = False,
    per_category: int = 5,
    verbose: bool = False,
    delay: float = 0,
    save_path: Optional[Path] = None,
) -> ScanResults:
    """Run the security scan.

    Args:
        config: Pipeline configuration.
        categories: Category filter.
        severity: Severity filter.
        limit: Maximum tests.
        balanced: Sample evenly across categories.
        per_category: Tests per category (with balanced).
        verbose: Enable verbose output.
        delay: Delay between tests in seconds.
        save_path: Path to save incremental results (updates after each test).

    Returns:
        ScanResults with responses and criteria for LLM judging.
    """
    # Load tests from API
    loader = TestLoader()
    if balanced:
        tests = await loader.load_balanced_from_api(
            per_category=per_category,
            categories=categories.split(',') if isinstance(categories, str) else categories,
        )
    else:
        tests = await loader.load_from_api(categories=categories, limit=limit)

    # Create bench with loaded tests
    bench = SecurityBench(tests=tests)

    # Filter by severity if specified
    if severity:
        tests = [t for t in tests if t.severity in severity]
        bench = SecurityBench(tests=tests)

    # Run scan
    if verbose:
        click.echo(f"Running {len(tests)} tests across {len(set(t.category for t in tests))} categories...")

    results = await bench.scan(config, delay=delay, save_path=save_path)

    return results


@main.command()
@click.argument('category', required=False)
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
def describe(category: Optional[str], output_format: str):
    """Describe available test categories.

    Optionally specify CATEGORY to see details for that category.
    """
    # Category descriptions
    categories = {
        "SPE": {
            "name": "System Prompt Extraction",
            "description": "Tests that attempt to extract system prompts from the model",
            "severity": "critical",
        },
        "PIN": {
            "name": "Prompt Injection",
            "description": "Tests for prompt injection vulnerabilities",
            "severity": "critical",
        },
        "JBR": {
            "name": "Jailbreak",
            "description": "Tests attempting to bypass safety measures",
            "severity": "high",
        },
        "PII": {
            "name": "PII Leakage",
            "description": "Tests for personal data exposure",
            "severity": "critical",
        },
        "TOX": {
            "name": "Toxicity",
            "description": "Tests for generation of harmful content",
            "severity": "high",
        },
        "IND": {
            "name": "Indirect Injection",
            "description": "Tests for indirect prompt injection attacks",
            "severity": "critical",
        },
        "HAL": {
            "name": "Hallucination",
            "description": "Tests for fabricated information",
            "severity": "medium",
        },
    }

    if output_format == 'json':
        if category:
            if category in categories:
                click.echo(json.dumps({"categories": {category: categories[category]}}, indent=2))
            else:
                click.echo(json.dumps({"error": f"Unknown category: {category}"}, indent=2))
        else:
            click.echo(json.dumps({"categories": categories}, indent=2))
    else:
        if category:
            if category in categories:
                cat = categories[category]
                click.echo(f"\n{category} - {cat['name']}")
                click.echo(f"  {cat['description']}")
                click.echo(f"  Severity: {cat['severity']}")
            else:
                click.echo(f"Unknown category: {category}")
                click.echo(f"Available: {', '.join(categories.keys())}")
        else:
            click.echo("\nSecurity Bench Categories:")
            click.echo("=" * 40)
            for code, cat in categories.items():
                click.echo(f"\n{code} - {cat['name']}")
                click.echo(f"  {cat['description']}")


@main.command('list-categories')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
def list_categories(output_format: str):
    """List all available test categories with test counts.

    Shows the 32 security test categories available for LLM scanning,
    grouped by type (Injection, Information, Agentic, Safety, Emerging).
    """
    from rich.console import Console
    from rich.table import Table

    console = Console()
    loader = TestLoader()

    try:
        categories = asyncio.run(loader.load_categories())
    except Exception as e:
        raise click.ClickException(f"Failed to load categories: {e}")

    if output_format == 'json':
        click.echo(json.dumps(categories, indent=2))
        return

    # Group categories by type
    groups = {
        'Injection': ['SPE', 'PIN', 'IND', 'JBR', 'OBF', 'MTM', 'GHJ', 'CTX'],
        'Information': ['ILK', 'SEC', 'EXF', 'MEX', 'CEX', 'OPS'],
        'Agentic': ['AGY', 'RAG', 'VEC', 'MEM', 'IAT', 'MCP', 'COT', 'IMG'],
        'Safety': ['SOC', 'BSE', 'CMP', 'HAL', 'RES'],
        'Emerging': ['POI', 'TRG', 'AUD', 'SID', 'UNC'],
    }

    # Build lookup
    cat_lookup = {c['code']: c for c in categories}
    total_tests = sum(c.get('count', 0) for c in categories)

    console.print()
    console.print(f"[bold]Security Bench Test Categories[/bold]")
    console.print(f"Total: {len(categories)} categories, {total_tests} tests")
    console.print()

    for group_name, codes in groups.items():
        table = Table(title=f"[bold]{group_name}[/bold]", show_header=True, header_style="bold")
        table.add_column("Code", style="cyan", width=6)
        table.add_column("Name", width=35)
        table.add_column("Tests", justify="right", width=6)
        table.add_column("Description", width=50)

        group_total = 0
        for code in codes:
            if code in cat_lookup:
                cat = cat_lookup[code]
                count = cat.get('count', 0)
                group_total += count
                desc = cat.get('description') or ''
                table.add_row(
                    code,
                    cat.get('name', code),
                    str(count),
                    (desc[:47] + '...') if len(desc) > 50 else desc
                )
            else:
                table.add_row(code, f"[dim]{code}[/dim]", "-", "[dim]Not yet available[/dim]")

        console.print(table)
        console.print(f"  [dim]Subtotal: {group_total} tests[/dim]")
        console.print()

    console.print("[bold]Usage:[/bold]")
    console.print("  sb scan <endpoint> --categories AGY,PIN,JBR  # Specific categories")
    console.print("  sb scan <endpoint> --balanced                # Sample from all")
    console.print("  sb scan <endpoint> --limit 100               # More tests")
    console.print()


@main.command('quick-scan')
@click.argument('endpoint', required=False)
@click.option('--config', '-c', type=click.Path(exists=True), help='Config file path')
@click.option('--model', '-m', help='Model name (for Ollama endpoints)')
@click.option('--dry-run', is_flag=True, help='Show what would run without executing')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
def quick_scan(
    endpoint: Optional[str],
    config: Optional[str],
    model: Optional[str],
    dry_run: bool,
    output_format: str,
):
    """Run a quick security scan with high-priority tests only.

    ENDPOINT is the Ollama API URL (e.g., http://192.168.1.50:11434)
    """
    # Reuse scan command with limited tests
    from click.testing import CliRunner
    runner = CliRunner()

    args = ['scan']
    if endpoint:
        args.append(endpoint)
    if config:
        args.extend(['--config', config])
    if model:
        args.extend(['--model', model])
    if dry_run:
        args.append('--dry-run')
    args.extend(['--format', output_format])
    args.extend(['--limit', '10'])  # Quick scan = limited tests

    result = runner.invoke(main, args)
    click.echo(result.output)


@main.command()
@click.option('--preset', type=click.Choice(['openai', 'anthropic', 'ollama', 'custom']), default='custom')
def init(preset: str):
    """Initialize a new sb.yaml configuration file.

    Use --preset to start with a provider-specific template.
    """
    templates = {
        'openai': '''# Security Bench configuration for OpenAI
endpoint:
  url: "https://api.openai.com/v1/chat/completions"
  headers:
    Authorization: "Bearer ${OPENAI_API_KEY}"
input:
  format: "openai"
  model: "gpt-4"
output:
  response_path: "choices[0].message.content"
''',
        'anthropic': '''# Security Bench configuration for Anthropic
endpoint:
  url: "https://api.anthropic.com/v1/messages"
  headers:
    x-api-key: "${ANTHROPIC_API_KEY}"
    anthropic-version: "2023-06-01"
input:
  format: "anthropic"
  model: "claude-3-5-sonnet-20241022"
output:
  response_path: "content[0].text"
''',
        'ollama': '''# Security Bench configuration for Ollama
# Replace with your Ollama server IP (e.g., H100 on local network)
endpoint:
  url: "http://<YOUR-OLLAMA-IP>:11434/api/chat"
input:
  format: "ollama"
  model: "mistral"
output:
  response_path: "message.content"
''',
        'custom': '''# Security Bench configuration
endpoint:
  url: "https://your-api.example.com/chat"
  headers:
    Authorization: "Bearer ${API_KEY}"
  timeout: 30
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
''',
    }

    config_path = Path('sb.yaml')
    if config_path.exists():
        if not click.confirm('sb.yaml already exists. Overwrite?'):
            return

    config_path.write_text(templates[preset])
    click.echo(f"Created sb.yaml with {preset} preset")
    click.echo("Edit the file to configure your endpoint, then run:")
    click.echo("  sb scan --config sb.yaml")


# =============================================================================
# AUDIT COMMANDS - Local security checks (Lynis-style)
# =============================================================================

def _run_audit_command(
    path: str,
    command: Optional[str],
    categories: Optional[str],
    output_format: str,
    verbose: bool,
    save: Optional[str],
):
    """Shared implementation for audit commands."""
    from rich.console import Console

    # Parse categories
    cat_list = [c.strip() for c in categories.split(',')] if categories else None

    # Setup output
    console = Console()
    output = AuditOutput(console=console)

    if output_format == 'text':
        output.print_banner()
        output.print_scan_start(path, command)

    # Create auditor
    auditor = Auditor(scan_path=Path(path))

    # Track all check results for log file
    check_results = []
    checks_seen = set()

    def progress_callback(current: int, total: int, check):
        if output_format == 'text':
            # Group by category
            if check.category not in checks_seen:
                if checks_seen:
                    console.print()
                output.print_category_header(check.category)
                checks_seen.add(check.category)

    def result_callback(check, passed: bool, findings: list):
        # Store result for log file
        check_results.append({
            'check': check,
            'passed': passed,
            'findings': findings,
        })
        # Print each check result (Lynis-style)
        if output_format == 'text':
            output.print_check_result(check, passed, len(findings))

    # Run audit with both callbacks
    results = asyncio.run(auditor.audit(
        command=command,
        categories=cat_list,
        progress_callback=progress_callback if output_format == 'text' else None,
        result_callback=result_callback if output_format == 'text' else None,
    ))

    # Generate log file (always, like Lynis)
    log_filename = f"sb_audit_{command or 'full'}.log"
    _write_audit_log(log_filename, path, command, results, check_results)

    # Output results
    if output_format == 'json':
        click.echo(json.dumps(format_audit_json(results), indent=2))
    else:
        output.print_results_summary(results)
        if verbose:
            output.print_findings_detail(results)
        output.print_recommendations(results)
        console.print(f"  [dim]Log file written to:[/dim] [bold]{log_filename}[/bold]")
        output.print_footer()

    # Save JSON if requested
    if save:
        save_path = Path(save)
        with open(save_path, 'w') as f:
            json.dump(format_audit_json(results), f, indent=2)
        if output_format == 'text':
            console.print(f"JSON results saved to: {save_path}")


def _write_audit_log(filename: str, path: str, command: Optional[str], results: AuditResults, check_results: list):
    """Write Lynis-style log file with all check results."""
    with open(filename, 'w') as f:
        # Header
        f.write("=" * 80 + "\n")
        f.write("  Security Bench Audit Log\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Scan path:     {path}\n")
        f.write(f"Check type:    {command or 'full audit'}\n")
        f.write(f"Started at:    {results.started_at}\n")
        f.write(f"Completed at:  {results.completed_at}\n")
        f.write("\n")

        # Executive Summary
        f.write("-" * 80 + "\n")
        f.write("  EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n\n")

        by_severity = results.findings_by_severity()
        crit_count = len(by_severity.get('critical', []))
        high_count = len(by_severity.get('high', []))
        med_count = len(by_severity.get('medium', []))

        if results.checks_failed == 0:
            f.write("All security checks passed. No vulnerabilities detected.\n")
        else:
            # Categorize risk types from findings
            risk_types = {}
            for finding in results.findings:
                # Extract risk type from check name (e.g., "RCE", "Authentication", etc.)
                name = finding.check_name.lower()
                if 'rce' in name or 'code execution' in name or 'deserialization' in name:
                    risk_types['Remote Code Execution'] = risk_types.get('Remote Code Execution', 0) + 1
                elif 'auth' in name or 'bypass' in name or 'without auth' in name:
                    risk_types['Authentication Bypass'] = risk_types.get('Authentication Bypass', 0) + 1
                elif 'escape' in name or 'container' in name:
                    risk_types['Container Escape'] = risk_types.get('Container Escape', 0) + 1
                elif 'dos' in name or 'denial' in name:
                    risk_types['Denial of Service'] = risk_types.get('Denial of Service', 0) + 1
                elif 'exposed' in name or 'public' in name:
                    risk_types['Exposed Service'] = risk_types.get('Exposed Service', 0) + 1
                else:
                    risk_types['Other'] = risk_types.get('Other', 0) + 1

            f.write(f"Your AI infrastructure has {crit_count} critical")
            if high_count:
                f.write(f" and {high_count} high severity")
            f.write(" vulnerabilities requiring attention.\n\n")

            if risk_types:
                risks_str = ", ".join(f"{k} ({v})" for k, v in sorted(risk_types.items(), key=lambda x: -x[1]))
                f.write(f"Primary risks: {risks_str}\n")

        f.write("\n")

        # Summary stats
        f.write("-" * 80 + "\n")
        f.write("  SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Grade:          {results.grade}\n")
        f.write(f"Score:          {results.hardening_score}%\n")
        f.write(f"Checks run:     {results.checks_run}\n")
        f.write(f"Checks passed:  {results.checks_passed}\n")
        f.write(f"Checks failed:  {results.checks_failed}\n")
        f.write("\n")

        # Risk breakdown by category
        if results.findings:
            f.write("-" * 80 + "\n")
            f.write("  RISK BY CATEGORY\n")
            f.write("-" * 80 + "\n\n")

            # Group findings by category and severity
            cat_risks = {}
            for finding in results.findings:
                cat = finding.category
                sev = finding.severity
                if cat not in cat_risks:
                    cat_risks[cat] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                cat_risks[cat][sev] += 1

            for cat, sevs in sorted(cat_risks.items()):
                parts = []
                if sevs['critical']:
                    parts.append(f"{sevs['critical']} critical")
                if sevs['high']:
                    parts.append(f"{sevs['high']} high")
                if sevs['medium']:
                    parts.append(f"{sevs['medium']} medium")
                if sevs['low']:
                    parts.append(f"{sevs['low']} low")
                f.write(f"  {cat:20} {', '.join(parts)}\n")
            f.write("\n")

        # All checks with results
        f.write("-" * 80 + "\n")
        f.write("  ALL CHECKS\n")
        f.write("-" * 80 + "\n\n")

        current_category = None
        for result in check_results:
            check = result['check']
            passed = result['passed']
            findings = result['findings']

            # Category header
            if check.category != current_category:
                if current_category:
                    f.write("\n")
                f.write(f"[{check.category}]\n")
                current_category = check.category

            # Check result
            status = "PASS" if passed else "FAIL"
            f.write(f"  [{status}] {check.id}: {check.name}\n")
            f.write(f"         Severity: {check.severity}, Type: {check.detection_type}\n")

            # Show findings for failed checks
            if not passed and findings:
                for finding in findings:
                    location = finding.file_path or "system"
                    if finding.line_number:
                        location += f":{finding.line_number}"
                    f.write(f"         -> {location}\n")
                    if finding.matched_content:
                        content = finding.matched_content[:60].replace('\n', ' ')
                        f.write(f"            Match: {content}...\n")

        # Findings summary
        f.write("\n")
        f.write("-" * 80 + "\n")
        f.write("  FINDINGS DETAIL\n")
        f.write("-" * 80 + "\n\n")

        if results.findings:
            for i, finding in enumerate(results.findings, 1):
                f.write(f"{i}. [{finding.severity.upper()}] {finding.check_name}\n")
                f.write(f"   Check ID: {finding.check_id}\n")
                f.write(f"   Category: {finding.category}\n")
                if finding.file_path:
                    loc = finding.file_path
                    if finding.line_number:
                        loc += f":{finding.line_number}"
                    f.write(f"   Location: {loc}\n")
                if finding.matched_content:
                    f.write(f"   Match: {finding.matched_content[:100]}\n")
                if finding.cwe:
                    f.write(f"   CWE: {finding.cwe}\n")
                if finding.remediation:
                    f.write(f"   Fix: {finding.remediation}\n")
                f.write("\n")
        else:
            f.write("No findings - all checks passed!\n")

        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("  End of Security Bench Audit Log\n")
        f.write("=" * 80 + "\n")


@main.command()
@click.argument('path', default='.', type=click.Path(exists=True))
@click.option('--categories', '-c', type=str, help='Filter categories: secrets,docker,permissions')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed findings')
@click.option('--save', type=click.Path(), help='Save results to JSON file')
def audit(
    path: str,
    categories: Optional[str],
    output_format: str,
    verbose: bool,
    save: Optional[str],
):
    """Run a full security audit on local code and configuration.

    PATH is the directory to scan (default: current directory).

    This runs all check types: code analysis, configuration review,
    and infrastructure security checks.
    """
    _run_audit_command(path, None, categories, output_format, verbose, save)


@main.command()
@click.argument('path', default='.', type=click.Path(exists=True))
@click.option('--categories', '-c', type=str, help='Filter categories')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed findings')
@click.option('--save', type=click.Path(), help='Save results to JSON file')
def code(
    path: str,
    categories: Optional[str],
    output_format: str,
    verbose: bool,
    save: Optional[str],
):
    """Run code security analysis.

    Scans source code for security vulnerabilities including:
    - Hardcoded secrets and credentials
    - SQL injection patterns
    - Command injection risks
    - Insecure deserialization
    - Prompt injection vulnerabilities
    """
    _run_audit_command(path, 'code', categories, output_format, verbose, save)


@main.command()
@click.argument('path', default='.', type=click.Path(exists=True))
@click.option('--categories', '-c', type=str, help='Filter categories')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed findings')
@click.option('--save', type=click.Path(), help='Save results to JSON file')
def config(
    path: str,
    categories: Optional[str],
    output_format: str,
    verbose: bool,
    save: Optional[str],
):
    """Run configuration security analysis.

    Checks configuration files for security issues including:
    - Exposed API keys and tokens
    - Insecure default settings
    - Missing security headers
    - Overly permissive CORS policies
    """
    _run_audit_command(path, 'config', categories, output_format, verbose, save)


@main.command()
@click.argument('path', default='.', type=click.Path(exists=True))
@click.option('--categories', '-c', type=str, help='Filter categories')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed findings')
@click.option('--save', type=click.Path(), help='Save results to JSON file')
def infra(
    path: str,
    categories: Optional[str],
    output_format: str,
    verbose: bool,
    save: Optional[str],
):
    """Run infrastructure security analysis.

    Checks infrastructure configuration for:
    - Docker security misconfigurations
    - Kubernetes security issues
    - Cloud configuration problems
    - Network security settings
    - File permission issues
    """
    _run_audit_command(path, 'infra', categories, output_format, verbose, save)


@main.command()
@click.argument('check_id')
def fix(check_id: str):
    """Get remediation guidance for a specific finding.

    CHECK_ID is the check identifier (e.g., CODE-001, INFRA-042).
    """
    from rich.console import Console
    from rich.panel import Panel
    from .auditor import CheckLoader

    console = Console()
    check_id_upper = check_id.upper()

    # Determine command type from check ID prefix
    if check_id_upper.startswith('INFRA-'):
        command = 'infra'
    elif check_id_upper.startswith('CODE-'):
        command = 'code'
    elif check_id_upper.startswith('CONFIG-'):
        command = 'config'
    else:
        command = None

    # Fetch check from API
    loader = CheckLoader()
    try:
        checks = asyncio.run(loader.load_checks(command=command, limit=500))
        check = next((c for c in checks if c.id.upper() == check_id_upper), None)
    except Exception as e:
        console.print(f"[red]Error fetching check data:[/red] {e}")
        return

    if not check:
        console.print(f"[yellow]Check {check_id} not found in database.[/yellow]")
        console.print("Run 'sb audit' to see available checks.")
        return

    # Display check details
    console.print()
    severity_colors = {'critical': 'red bold', 'high': 'red', 'medium': 'yellow', 'low': 'blue'}
    sev_style = severity_colors.get(check.severity, 'white')

    console.print(Panel(
        f"[bold]{check.name}[/bold]",
        title=f"[{sev_style}]{check.severity.upper()}[/{sev_style}] {check.id}",
        subtitle=f"Category: {check.category}",
    ))

    # Description
    console.print(f"\n[bold]Description:[/bold]")
    console.print(f"  {check.description}")

    # Detection info
    console.print(f"\n[bold]Detection:[/bold]")
    console.print(f"  Type: {check.detection_type}")
    if check.file_patterns and isinstance(check.file_patterns, list) and len(check.file_patterns) > 0:
        # Filter out empty strings and single chars (malformed data)
        valid_patterns = [p for p in check.file_patterns if isinstance(p, str) and len(p) > 1]
        if valid_patterns:
            console.print(f"  Files: {', '.join(valid_patterns)}")

    # CWE reference
    if check.cwe:
        console.print(f"\n[bold]CWE:[/bold] {check.cwe}")
        cwe_num = check.cwe.replace('CWE-', '')
        console.print(f"  https://cwe.mitre.org/data/definitions/{cwe_num}.html")

    # OWASP LLM reference
    if check.owasp_llm:
        console.print(f"\n[bold]OWASP LLM:[/bold] {check.owasp_llm}")
        console.print(f"  https://owasp.org/www-project-top-10-for-large-language-model-applications/")

    # Remediation
    console.print(f"\n[bold]Remediation:[/bold]")
    if check.remediation:
        console.print(f"  {check.remediation}")
    else:
        console.print("  [dim]No specific remediation available yet.[/dim]")
        # Generate generic remediation based on check type
        if 'CVE-' in check.name:
            # Extract CVE from name
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', check.name)
            if cve_match:
                cve = cve_match.group()
                console.print(f"\n[bold]References:[/bold]")
                console.print(f"  NVD: https://nvd.nist.gov/vuln/detail/{cve}")
                console.print(f"  Search: https://www.google.com/search?q={cve}+remediation")

    console.print(f"\n[dim]Run 'sb audit --verbose' to see if this check failed in your project.[/dim]")
    console.print()


@main.command()
def update():
    """Update local cache of tests and checks.

    Downloads the latest tests and checks from the API,
    regardless of whether the cache is current.
    """
    from rich.console import Console
    from .loader import TestLoader, get_cache_dir, load_cached_version
    from .auditor import CheckLoader

    console = Console()
    console.print("\n[bold]Updating Security Bench cache...[/bold]\n")

    cache_dir = get_cache_dir()
    old_version = load_cached_version()

    async def do_update():
        # Force refresh tests
        test_loader = TestLoader(use_cache=True)
        tests = await test_loader.load_from_api(limit=5000, force_refresh=True)

        # Force refresh checks
        check_loader = CheckLoader(use_cache=True)
        checks = await check_loader.load_checks(limit=1000, force_refresh=True)

        return len(tests), len(checks)

    test_count, check_count = asyncio.run(do_update())
    new_version = load_cached_version()

    console.print(f"  Tests:  {test_count} downloaded")
    console.print(f"  Checks: {check_count} downloaded")
    console.print(f"\n  Cache location: {cache_dir}")

    # Show version changes
    if old_version:
        if old_version.get("tests_version") != new_version.get("tests_version"):
            console.print(f"  [green]Tests updated[/green]: {old_version.get('tests_version', 'none')} → {new_version.get('tests_version')}")
        if old_version.get("checks_version") != new_version.get("checks_version"):
            console.print(f"  [green]Checks updated[/green]: {old_version.get('checks_version', 'none')} → {new_version.get('checks_version')}")

    console.print("\n[green]Cache updated successfully![/green]\n")


@main.command()
def man():
    """Open the Security Bench manual in browser."""
    import webbrowser
    try:
        from importlib.resources import files
        man_path = files('sb.docs').joinpath('man.html')
        webbrowser.open(f'file://{man_path}')
        click.echo("Opening Security Bench manual in browser...")
    except Exception as e:
        click.echo(f"Error opening manual: {e}")
        click.echo("Manual available at: https://securitybench.ai/docs")


if __name__ == '__main__':
    main()
