"""Rich terminal output for Security Bench.

Lynis-inspired terminal output with colors, progress bars, and professional formatting.
"""
import sys
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text
from rich import box

from .auditor import AuditResults, Finding, SecurityCheck


@dataclass
class OutputTheme:
    """Color theme for output."""
    critical: str = "red bold"
    high: str = "red"
    medium: str = "yellow"
    low: str = "blue"
    info: str = "dim"
    success: str = "green"
    warning: str = "yellow"
    header: str = "cyan bold"
    grade_a: str = "green bold"
    grade_b: str = "green"
    grade_c: str = "yellow"
    grade_d: str = "red"
    grade_f: str = "red bold"


class AuditOutput:
    """Lynis-style terminal output for audit results."""

    BANNER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ____                       _ _         ____                  _              ║
║  / ___|  ___  ___ _   _ _ __(_) |_ _   _| __ )  ___ _ __   ___| |__           ║
║  \\___ \\ / _ \\/ __| | | | '__| | __| | | |  _ \\ / _ \\ '_ \\ / __| '_ \\          ║
║   ___) |  __/ (__| |_| | |  | | |_| |_| | |_) |  __/ | | | (__| | | |         ║
║  |____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |____/ \\___|_| |_|\\___|_| |_|         ║
║                                     |___/                                      ║
║                        Security Audit Tool v0.2.13                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

    def __init__(self, console: Optional[Console] = None, theme: Optional[OutputTheme] = None):
        """Initialize output handler.

        Args:
            console: Rich console instance.
            theme: Color theme.
        """
        self.console = console or Console()
        self.theme = theme or OutputTheme()

    def print_banner(self):
        """Print the Security Bench banner."""
        self.console.print(self.BANNER, style="cyan")

    def print_scan_start(self, path: str, command: Optional[str] = None):
        """Print scan start message."""
        self.console.print()
        self.console.print(f"  [bold]Scan target:[/bold] {path}")
        if command:
            self.console.print(f"  [bold]Check type:[/bold] {command}")
        self.console.print()
        self.console.rule("[cyan]Initializing audit[/cyan]")
        self.console.print()

    def create_progress(self) -> Progress:
        """Create a progress bar for audit."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            console=self.console,
        )

    def print_check_result(self, check: SecurityCheck, passed: bool, findings_count: int = 0):
        """Print result of a single check."""
        if passed:
            status = Text("[ OK ]", style="green")
        else:
            status = Text("[WARN]", style="yellow")

        severity_color = getattr(self.theme, check.severity, "white")

        self.console.print(
            f"  {status}  ",
            Text(f"[{check.severity.upper()[:4]}]", style=severity_color),
            f"  {check.id}: {check.name[:60]}",
            end="",
        )
        if findings_count > 0:
            self.console.print(f" ({findings_count} finding{'s' if findings_count > 1 else ''})", style="dim")
        else:
            self.console.print()

    def print_category_header(self, category: str):
        """Print a category section header."""
        self.console.print()
        self.console.rule(f"[cyan]{category}[/cyan]")
        self.console.print()

    def print_results_summary(self, results: AuditResults):
        """Print the final results summary."""
        self.console.print()
        self.console.rule("[cyan]Audit Summary[/cyan]")
        self.console.print()

        # Grade and score
        grade = results.grade
        grade_color = getattr(self.theme, f"grade_{grade.lower()}", "white")

        score_panel = Panel(
            Text(f"{grade}", style=grade_color, justify="center"),
            title="[bold]Security Grade[/bold]",
            subtitle=f"Hardening Score: {results.hardening_score}%",
            width=30,
            box=box.ROUNDED,
        )
        self.console.print(score_panel)
        self.console.print()

        # Stats table
        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column(style="dim")
        stats_table.add_column()

        stats_table.add_row("Checks performed:", str(results.checks_run))
        stats_table.add_row("Checks passed:", Text(str(results.checks_passed), style="green"))
        stats_table.add_row("Checks failed:", Text(str(results.checks_failed), style="red" if results.checks_failed > 0 else "green"))
        stats_table.add_row("Scan path:", results.scan_path)

        self.console.print(stats_table)
        self.console.print()

        # Findings by severity
        by_severity = results.findings_by_severity()
        has_findings = any(by_severity.values())

        if has_findings:
            self.console.rule("[cyan]Findings by Severity[/cyan]")
            self.console.print()

            severity_table = Table(show_header=True, box=box.SIMPLE)
            severity_table.add_column("Severity", style="bold")
            severity_table.add_column("Count", justify="right")

            for severity, findings in by_severity.items():
                if findings:
                    style = getattr(self.theme, severity, "white")
                    severity_table.add_row(
                        Text(severity.upper(), style=style),
                        str(len(findings)),
                    )

            self.console.print(severity_table)
            self.console.print()

    def print_findings_detail(self, results: AuditResults, max_findings: int = 10):
        """Print detailed findings."""
        if not results.findings:
            return

        self.console.rule("[cyan]Top Findings[/cyan]")
        self.console.print()

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            results.findings,
            key=lambda f: severity_order.get(f.severity, 4),
        )

        for i, finding in enumerate(sorted_findings[:max_findings]):
            self._print_finding(finding, i + 1)

        remaining = len(results.findings) - max_findings
        if remaining > 0:
            self.console.print(f"  ... and {remaining} more findings", style="dim")
            self.console.print()

    def _print_finding(self, finding: Finding, index: int):
        """Print a single finding."""
        severity_style = getattr(self.theme, finding.severity, "white")

        # Header
        header = Text()
        header.append(f"{index}. ", style="bold")
        header.append(f"[{finding.severity.upper()}] ", style=severity_style)
        header.append(finding.check_name, style="bold")

        self.console.print(header)

        # Details
        if finding.file_path:
            location = finding.file_path
            if finding.line_number:
                location += f":{finding.line_number}"
            self.console.print(f"   Location: {location}", style="dim")

        if finding.matched_content:
            self.console.print(f"   Match: {finding.matched_content[:80]}...", style="dim")

        if finding.cwe:
            self.console.print(f"   CWE: {finding.cwe}", style="dim")

        if finding.remediation:
            self.console.print(f"   [green]Fix:[/green] {finding.remediation[:100]}...")

        self.console.print()

    def print_recommendations(self, results: AuditResults):
        """Print recommendations based on findings."""
        if results.hardening_score >= 90:
            self.console.print("[green]✓[/green] Your project has excellent security hardening!")
            return

        self.console.rule("[cyan]Recommendations[/cyan]")
        self.console.print()

        recommendations = []

        by_severity = results.findings_by_severity()
        if by_severity["critical"]:
            recommendations.append("🚨 Address [red bold]CRITICAL[/red bold] findings immediately")
        if by_severity["high"]:
            recommendations.append("⚠️  Fix [red]HIGH[/red] severity issues before deployment")
        if by_severity["medium"]:
            recommendations.append("📋 Review [yellow]MEDIUM[/yellow] severity findings")

        for rec in recommendations:
            self.console.print(f"  • {rec}")

        self.console.print()
        self.console.print("  Run [bold]sb audit --verbose[/bold] for detailed findings")
        self.console.print("  Run [bold]sb fix <CHECK-ID>[/bold] for remediation guidance")
        self.console.print()

    def print_footer(self):
        """Print footer with links."""
        self.console.print()
        self.console.rule()
        self.console.print(
            "  [dim]Security Bench • securitybench.ai • github.com/securitybench/securitybench[/dim]",
            justify="center",
        )
        self.console.print()


def format_audit_json(results: AuditResults) -> dict:
    """Format audit results as JSON-serializable dict."""
    return {
        "scan_path": results.scan_path,
        "started_at": results.started_at,
        "completed_at": results.completed_at,
        "hardening_score": results.hardening_score,
        "grade": results.grade,
        "summary": {
            "checks_run": results.checks_run,
            "checks_passed": results.checks_passed,
            "checks_failed": results.checks_failed,
        },
        "findings_by_severity": {
            sev: len(findings)
            for sev, findings in results.findings_by_severity().items()
        },
        "findings": [
            {
                "check_id": f.check_id,
                "check_name": f.check_name,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "matched_content": f.matched_content,
                "remediation": f.remediation,
                "cwe": f.cwe,
            }
            for f in results.findings
        ],
    }
