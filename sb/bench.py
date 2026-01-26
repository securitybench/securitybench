"""Security Bench orchestration and test management.

Provides the main SecurityBench class for loading, filtering, and running
security tests against LLM pipelines.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json
import yaml

from .config import PipelineConfig


# Category descriptions for the Security Bench test suite
CATEGORY_DESCRIPTIONS = {
    "SPE": "System Prompt Extraction - Tests that attempt to extract system prompts",
    "PIN": "Prompt Injection - Tests for prompt injection vulnerabilities",
    "JBR": "Jailbreak - Tests attempting to bypass safety measures",
    "PII": "PII Leakage - Tests for personal data exposure",
    "TOX": "Toxicity - Tests for generation of harmful content",
    "BIA": "Bias - Tests for discriminatory outputs",
    "MIS": "Misinformation - Tests for factual accuracy",
    "SEC": "Security - General security vulnerability tests",
    "HAL": "Hallucination - Tests for fabricated information",
    "IND": "Indirect Injection - Tests for indirect prompt attacks",
}


@dataclass
class SecurityTest:
    """A single security test case."""
    id: str
    category: str
    prompt: str
    failure_patterns: list[str] = field(default_factory=list)
    severity: str = "medium"
    priority: str = "medium"
    description: Optional[str] = None
    patterns: Optional[list[str]] = None  # Alias for failure_patterns from API

    def __post_init__(self):
        # If patterns was provided but failure_patterns wasn't, use patterns
        if self.patterns and not self.failure_patterns:
            self.failure_patterns = self.patterns


@dataclass
class TestResult:
    """Result of running a single security test."""
    test_id: Optional[str] = None
    category: Optional[str] = None
    passed: Optional[bool] = None  # None = pending LLM judgment
    response_text: Optional[str] = None
    matched_pattern: Optional[str] = None
    error: Optional[str] = None
    id: Optional[str] = None  # Alias for test_id
    prompt: Optional[str] = None  # The attack prompt that was sent
    criteria: Optional[dict] = None  # Judging criteria from judge_rules.json

    def __post_init__(self):
        # Support both 'id' and 'test_id' as field names
        if self.id and not self.test_id:
            self.test_id = self.id
        elif self.test_id and not self.id:
            self.id = self.test_id


@dataclass
class ScanResults:
    """Results of a complete security scan."""
    total_tests: int
    passed: int
    failed: int
    score: float = 0.0
    grade: Optional[str] = None
    failures_by_category: dict = field(default_factory=dict)
    test_results: list[TestResult] = field(default_factory=list)
    category_scores: Optional[dict] = None
    failed_tests: Optional[list] = None

    def __post_init__(self):
        # Calculate grade if not provided
        if self.grade is None:
            self.grade = self._calculate_grade()

    def _calculate_grade(self) -> str:
        """Calculate letter grade from score."""
        if self.score >= 90:
            return "A"
        elif self.score >= 80:
            return "B"
        elif self.score >= 70:
            return "C"
        elif self.score >= 60:
            return "D"
        else:
            return "F"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        test_results = []
        for r in self.test_results:
            result = {
                "test_id": r.test_id,
                "category": r.category,
                "passed": r.passed,
                "response": r.response_text,
                "error": r.error,
            }
            # Include prompt if available
            if r.prompt:
                result["prompt"] = r.prompt
            # Include criteria if available (for LLM judging)
            if r.criteria:
                result["criteria"] = r.criteria
            # Include matched_pattern only if it exists (not in judge mode)
            if r.matched_pattern:
                result["matched_pattern"] = r.matched_pattern
            test_results.append(result)

        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "score": self.score,
            "grade": self.grade,
            "failures_by_category": self.failures_by_category,
            "category_stats": self.category_scores or {},
            "test_results": test_results,
        }


class SecurityBench:
    """Main orchestrator for security testing."""

    def __init__(self, tests_dir: Optional[Path] = None, tests: Optional[list[SecurityTest]] = None):
        """Initialize SecurityBench.

        Args:
            tests_dir: Directory containing test YAML files.
            tests: Pre-loaded list of tests (alternative to tests_dir).
        """
        self._tests: list[SecurityTest] = []

        if tests:
            self._tests = tests
        elif tests_dir:
            self._load_tests_from_dir(tests_dir)

    @property
    def tests(self) -> list[SecurityTest]:
        """Get all loaded tests."""
        return self._tests

    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade from score."""
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

    def _load_tests_from_dir(self, tests_dir: Path):
        """Load tests from YAML files in directory."""
        for yaml_file in tests_dir.glob("*.yaml"):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)

            if data and "tests" in data:
                for test_data in data["tests"]:
                    self._tests.append(SecurityTest(
                        id=test_data["id"],
                        category=test_data["category"],
                        prompt=test_data["prompt"],
                        failure_patterns=test_data.get("failure_patterns", []),
                        severity=test_data.get("severity", "medium"),
                        priority=test_data.get("priority", "medium"),
                        description=test_data.get("description"),
                    ))

    def get_tests(
        self,
        categories: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[SecurityTest]:
        """Get filtered list of tests.

        Args:
            categories: Filter by category codes (e.g., ["SPE", "PIN"]).
            severity: Filter by severity levels (e.g., ["critical", "high"]).
            limit: Maximum number of tests to return.

        Returns:
            Filtered list of SecurityTest objects.
        """
        result = self._tests

        if categories:
            result = [t for t in result if t.category in categories]

        if severity:
            result = [t for t in result if t.severity in severity]

        if limit:
            result = result[:limit]

        return result

    def get_test(self, test_id: str) -> Optional[SecurityTest]:
        """Get a specific test by ID.

        Args:
            test_id: The test ID to look up.

        Returns:
            SecurityTest or None if not found.
        """
        for test in self._tests:
            if test.id == test_id:
                return test
        return None

    def category_breakdown(self) -> dict[str, int]:
        """Get count of tests by category.

        Returns:
            Dictionary mapping category codes to test counts.
        """
        breakdown = {}
        for test in self._tests:
            breakdown[test.category] = breakdown.get(test.category, 0) + 1
        return breakdown

    def describe_categories(self) -> dict:
        """Get descriptions of all categories with test counts.

        Returns:
            Dictionary with category info including description and count.
        """
        breakdown = self.category_breakdown()
        result = {}

        for category, count in breakdown.items():
            description = CATEGORY_DESCRIPTIONS.get(
                category,
                f"{category} - Security tests"
            )
            result[category] = {
                "description": description,
                "count": count,
            }

        return result

    def _load_judge_rules(self) -> dict:
        """Load judging criteria from judge_rules.json."""
        # Try to find judge_rules.json in package directory or current directory
        possible_paths = [
            Path(__file__).parent / "judge_rules.json",
            Path("sb/judge_rules.json"),
            Path("judge_rules.json"),
        ]
        for path in possible_paths:
            if path.exists():
                with open(path) as f:
                    return json.load(f)
        return {}

    async def scan(
        self,
        config: PipelineConfig,
        categories: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        limit: Optional[int] = None,
        delay: float = 0,
        save_path: Optional[Path] = None,
        judge_mode: bool = True,  # Always LLM judging, no regex
    ) -> ScanResults:
        """Run a full security scan.

        Args:
            config: Pipeline configuration.
            categories: Filter by categories.
            severity: Filter by severity.
            limit: Maximum tests to run.
            delay: Delay between tests in seconds.
            save_path: Path to save incremental results (updates after each test).
            judge_mode: Deprecated - always True. LLM judging only.

        Returns:
            ScanResults with responses and criteria for LLM judging.
        """
        from .runner import TestRunner

        tests = self.get_tests(categories=categories, severity=severity, limit=limit)
        runner = TestRunner(config)

        # Always load judge rules for LLM evaluation
        judge_rules = self._load_judge_rules()

        results = []
        category_stats: dict[str, dict] = {}

        for test in tests:
            # Track category totals
            if test.category not in category_stats:
                category_stats[test.category] = {"total": 0, "pending": 0}
            category_stats[test.category]["total"] += 1
            category_stats[test.category]["pending"] += 1

            run_result = await runner.run_test(test)

            # Get criteria for this test's category
            criteria = judge_rules.get(test.category)

            # LLM judging only - passed=None until LLM evaluates
            test_result = TestResult(
                test_id=test.id,
                category=test.category,
                passed=None,  # LLM will judge
                response_text=run_result.response_text,
                matched_pattern=None,
                error=run_result.error,
                prompt=test.prompt,
                criteria=criteria,
            )

            results.append(test_result)

            # Save incremental results after each test
            if save_path:
                interim_results = {
                    "total_tests": len(results),
                    "pending": len(results),
                    "status": f"scanning ({len(results)}/{len(tests)})",
                    "category_stats": category_stats,
                    "test_results": [
                        {
                            "test_id": r.test_id,
                            "category": r.category,
                            "prompt": r.prompt,
                            "passed": r.passed,
                            "response": r.response_text,
                            "criteria": r.criteria,
                            "error": r.error,
                        }
                        for r in results
                    ],
                }
                with open(save_path, 'w') as f:
                    json.dump(interim_results, f, indent=2)

            # Delay between tests for rate limiting
            if delay > 0:
                import asyncio
                await asyncio.sleep(delay)

        total = len(results)
        return ScanResults(
            total_tests=total,
            passed=0,  # LLM will judge
            failed=0,  # LLM will judge
            score=0.0,  # LLM will judge
            failures_by_category={},
            category_scores=category_stats,
            test_results=results,
        )

    async def quick_scan(self, config: PipelineConfig) -> ScanResults:
        """Run a quick scan with high-priority tests only.

        Args:
            config: Pipeline configuration.

        Returns:
            ScanResults from running high-priority subset.
        """
        # Filter to high-priority tests and limit to ~10
        high_priority = [t for t in self._tests if t.priority == "high"]
        if not high_priority:
            high_priority = self._tests[:10]
        else:
            high_priority = high_priority[:10]

        # Create a temp bench with just these tests
        temp_bench = SecurityBench(tests=high_priority)
        return await temp_bench.scan(config)
