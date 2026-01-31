"""Security Auditor for local code, config, and infrastructure checks.

Lynis-inspired security scanner that fetches checks from the API
and runs them against local files and system.
"""
import asyncio
import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from .loader import (
    TestLoader, _parse_patterns, get_cache_dir,
    load_cached_version, save_cached_version
)


def load_cached_checks() -> Optional[list]:
    """Load checks from cache."""
    checks_file = get_cache_dir() / "checks.json"
    if checks_file.exists():
        try:
            return json.loads(checks_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def save_cached_checks(checks: list[dict]):
    """Save checks to cache."""
    checks_file = get_cache_dir() / "checks.json"
    checks_file.write_text(json.dumps(checks, indent=2))


@dataclass
class SecurityCheck:
    """A security check definition from the API."""
    id: str
    command: str  # "code", "config", or "infra"
    category: str
    name: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    detection_type: str  # "regex" or "command"
    pattern: str  # Regex pattern or shell command
    file_patterns: list[str] = field(default_factory=list)
    cwe: Optional[str] = None
    owasp_llm: Optional[str] = None
    weight: int = 5
    remediation: Optional[str] = None


@dataclass
class Finding:
    """A security finding from running a check."""
    check_id: str
    check_name: str
    severity: str
    category: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    matched_content: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None


@dataclass
class AuditResults:
    """Results from running an audit."""
    scan_path: str
    started_at: str
    completed_at: str
    checks_run: int
    checks_passed: int
    checks_failed: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def hardening_score(self) -> int:
        """Calculate hardening score (0-100)."""
        if self.checks_run == 0:
            return 100
        return int((self.checks_passed / self.checks_run) * 100)

    @property
    def grade(self) -> str:
        """Letter grade based on hardening score."""
        score = self.hardening_score
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity."""
        result = {"critical": [], "high": [], "medium": [], "low": []}
        for f in self.findings:
            if f.severity in result:
                result[f.severity].append(f)
        return result


class CheckLoader:
    """Loads security checks from the API."""

    API_BASE = TestLoader.API_BASE

    def __init__(self, use_cache: bool = True):
        """Initialize the check loader.

        Args:
            use_cache: Whether to use local cache (default True).
        """
        self.use_cache = use_cache

    async def get_api_version(self) -> dict:
        """Fetch version info from API."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{self.API_BASE}/api/version")
            response.raise_for_status()
            return response.json()

    async def is_cache_valid(self) -> bool:
        """Check if local cache matches API version."""
        try:
            api_version = await self.get_api_version()
            local_version = load_cached_version()
            return local_version.get("checks_version") == api_version.get("checks_version")
        except Exception:
            return False

    async def load_checks(
        self,
        command: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 500,
        force_refresh: bool = False,
    ) -> list[SecurityCheck]:
        """Load checks from the Security Bench API.

        Uses local cache when available and version matches.

        Args:
            command: Filter by command type (code, config, infra).
            category: Filter by category.
            limit: Maximum number of checks to load.
            force_refresh: Skip cache and download fresh.

        Returns:
            List of SecurityCheck objects.
        """
        # Try cache first (for full loads without filters)
        if self.use_cache and not force_refresh and not command and not category:
            if await self.is_cache_valid():
                cached = load_cached_checks()
                if cached:
                    return self._checks_from_data(cached)[:limit]

        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {"limit": limit}
            if command:
                params["command"] = command
            if category:
                params["category"] = category

            response = await client.get(
                f"{self.API_BASE}/api/checks",
                params=params,
            )
            response.raise_for_status()

            data = response.json()
            checks_data = data.get("checks", data if isinstance(data, list) else [])
            checks = self._checks_from_data(checks_data)

            # Cache the data if this was a full load
            if self.use_cache and not command and not category:
                save_cached_checks(checks_data)
                try:
                    api_version = await self.get_api_version()
                    save_cached_version(api_version)
                except Exception:
                    pass

            return checks

    def _checks_from_data(self, checks_data: list[dict]) -> list[SecurityCheck]:
        """Convert check data dicts to SecurityCheck objects."""
        checks = []
        for check_data in checks_data:
            # Parse file_patterns - API may return as string repr of list
            file_patterns = _parse_patterns(check_data.get("file_patterns", []))

            # Unescape pattern - API may return double-escaped backslashes
            pattern = check_data.get("pattern", "")
            if pattern:
                # Replace double backslashes with single backslashes
                # This handles patterns like \\\\s (stored) -> \\s (regex)
                pattern = pattern.replace("\\\\", "\\")

            check = SecurityCheck(
                id=check_data["id"],
                command=check_data.get("command", "code"),
                category=check_data.get("category", "misc"),
                name=check_data.get("name", check_data["id"]),
                description=check_data.get("description", ""),
                severity=check_data.get("severity", "medium"),
                detection_type=check_data.get("detection_type", "regex"),
                pattern=pattern,
                file_patterns=file_patterns,
                cwe=check_data.get("cwe"),
                owasp_llm=check_data.get("owasp_llm"),
                weight=check_data.get("weight", 5),
                remediation=check_data.get("remediation"),
            )
            checks.append(check)

        return checks


class Auditor:
    """Security auditor that runs checks against local files and system."""

    def __init__(
        self,
        scan_path: Path = Path("."),
        exclude_patterns: Optional[list[str]] = None,
    ):
        """Initialize the auditor.

        Args:
            scan_path: Directory to scan.
            exclude_patterns: Glob patterns to exclude.
        """
        self.scan_path = scan_path.resolve()
        self.exclude_patterns = exclude_patterns or [
            "node_modules/*",
            ".git/*",
            "__pycache__/*",
            "*.pyc",
            ".venv/*",
            "venv/*",
            "dist/*",
            "build/*",
        ]
        self.loader = CheckLoader()
        self._file_cache: dict[str, list[Path]] = {}

    def _should_exclude(self, path: Path) -> bool:
        """Check if a path should be excluded."""
        rel_path = str(path.relative_to(self.scan_path))
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        return False

    def _find_files(self, patterns: list[str]) -> list[Path]:
        """Find files matching glob patterns."""
        cache_key = tuple(sorted(patterns))
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]

        files = set()
        for pattern in patterns:
            if not pattern:
                continue

            # Handle different pattern types
            if pattern.startswith("."):
                # Hidden files like .env - search directly for this filename
                for path in self.scan_path.rglob(pattern):
                    if path.is_file() and not self._should_exclude(path):
                        files.add(path)
                # Also check root directory for exact match
                root_file = self.scan_path / pattern
                if root_file.is_file() and not self._should_exclude(root_file):
                    files.add(root_file)
            elif pattern.startswith("*."):
                # Extension patterns like *.py, *.env - use glob
                # For hidden extensions like *.env, also check for .env files
                ext = pattern[1:]  # ".py" or ".env"
                try:
                    for path in self.scan_path.rglob(f"*{ext}"):
                        if path.is_file() and not self._should_exclude(path):
                            files.add(path)
                    # Also search for hidden files with this extension
                    for path in self.scan_path.rglob(f".*{ext}"):
                        if path.is_file() and not self._should_exclude(path):
                            files.add(path)
                except (NotImplementedError, ValueError):
                    pass
            elif "*" in pattern:
                # Other glob patterns like docker-compose*, Dockerfile.*
                try:
                    for path in self.scan_path.rglob(pattern):
                        if path.is_file() and not self._should_exclude(path):
                            files.add(path)
                except (NotImplementedError, ValueError):
                    # Fall back to fnmatch for complex patterns
                    for path in self.scan_path.rglob("*"):
                        if path.is_file() and fnmatch.fnmatch(path.name, pattern):
                            if not self._should_exclude(path):
                                files.add(path)
            else:
                # Exact filename like Dockerfile, Makefile
                try:
                    for path in self.scan_path.rglob(pattern):
                        if path.is_file() and not self._should_exclude(path):
                            files.add(path)
                except (NotImplementedError, ValueError):
                    pass

        result = list(files)
        self._file_cache[cache_key] = result
        return result

    # Patterns for minified/bundled files to skip (regex would hang on these)
    MINIFIED_SUFFIXES = {'.min.js', '.min.css', '.bundle.js', '.packed.js'}
    MINIFIED_PREFIXES = {'vendor.', 'vendor-', 'chunk.', 'chunk-'}
    MAX_LINE_LENGTH = 1000  # Lines longer than this are likely minified

    def _is_minified_file(self, path: Path) -> bool:
        """Check if file is likely minified/bundled code."""
        name = path.name.lower()
        # Check suffix patterns (.min.js, .bundle.js)
        for suffix in self.MINIFIED_SUFFIXES:
            if name.endswith(suffix):
                return True
        # Check prefix patterns (vendor., chunk.)
        for prefix in self.MINIFIED_PREFIXES:
            if name.startswith(prefix):
                return True
        return False

    def _run_regex_check(self, check: SecurityCheck) -> list[Finding]:
        """Run a regex-based check against matching files."""
        findings = []

        if not check.file_patterns:
            return findings

        files = self._find_files(check.file_patterns)

        try:
            pattern = re.compile(check.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            return findings

        for file_path in files:
            # Skip minified/bundled files - regex can hang on these
            if self._is_minified_file(file_path):
                continue

            try:
                content = file_path.read_text(errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    # Skip very long lines (minified code signature)
                    if len(line) > self.MAX_LINE_LENGTH:
                        continue
                    match = pattern.search(line)
                    if match:
                        findings.append(Finding(
                            check_id=check.id,
                            check_name=check.name,
                            severity=check.severity,
                            category=check.category,
                            description=check.description,
                            file_path=str(file_path.relative_to(self.scan_path)),
                            line_number=line_num,
                            matched_content=line.strip()[:200],
                            remediation=check.remediation,
                            cwe=check.cwe,
                        ))
            except Exception:
                continue

        return findings

    def _run_command_check(self, check: SecurityCheck) -> list[Finding]:
        """Run a command-based check."""
        findings = []

        try:
            result = subprocess.run(
                check.pattern,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.scan_path),
            )

            # Command checks typically return non-zero or specific output on failure
            if result.returncode != 0 or result.stdout.strip():
                findings.append(Finding(
                    check_id=check.id,
                    check_name=check.name,
                    severity=check.severity,
                    category=check.category,
                    description=check.description,
                    matched_content=result.stdout.strip()[:500] if result.stdout else None,
                    remediation=check.remediation,
                    cwe=check.cwe,
                ))
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings

    async def run_check(self, check: SecurityCheck) -> tuple[bool, list[Finding]]:
        """Run a single security check.

        Args:
            check: The check to run.

        Returns:
            Tuple of (passed, findings).
        """
        if check.detection_type == "regex":
            findings = self._run_regex_check(check)
        elif check.detection_type == "command":
            findings = self._run_command_check(check)
        else:
            findings = []

        return len(findings) == 0, findings

    async def audit(
        self,
        command: Optional[str] = None,
        categories: Optional[list[str]] = None,
        progress_callback=None,
        result_callback=None,
    ) -> AuditResults:
        """Run a full audit.

        Args:
            command: Filter checks by command type (code, config, infra).
            categories: Filter checks by category.
            progress_callback: Called with (current, total, check) before each check.
            result_callback: Called with (check, passed, findings) after each check.

        Returns:
            AuditResults with all findings.
        """
        started_at = datetime.now().isoformat()

        # Load checks
        checks = await self.loader.load_checks(command=command)

        # Filter by categories if specified
        if categories:
            checks = [c for c in checks if c.category in categories]

        all_findings = []
        passed = 0
        failed = 0

        for i, check in enumerate(checks):
            if progress_callback:
                progress_callback(i + 1, len(checks), check)

            check_passed, findings = await self.run_check(check)

            if check_passed:
                passed += 1
            else:
                failed += 1
                all_findings.extend(findings)

            # Report result after each check
            if result_callback:
                result_callback(check, check_passed, findings)

        return AuditResults(
            scan_path=str(self.scan_path),
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            checks_run=len(checks),
            checks_passed=passed,
            checks_failed=failed,
            findings=all_findings,
        )
