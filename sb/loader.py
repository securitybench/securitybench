"""Test loader for Security Bench.

Provides loading tests from local YAML files or remote API.
"""
import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml
import httpx

from .bench import SecurityTest


# Cache directory for tests and checks
CACHE_DIR = Path.home() / ".securitybench" / "cache"


def get_cache_dir() -> Path:
    """Get or create cache directory."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def load_cached_version() -> dict:
    """Load cached version info."""
    version_file = get_cache_dir() / "version.json"
    if version_file.exists():
        try:
            return json.loads(version_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_cached_version(version_info: dict):
    """Save version info to cache."""
    version_file = get_cache_dir() / "version.json"
    version_file.write_text(json.dumps(version_info, indent=2))


def load_cached_tests() -> Optional[list]:
    """Load tests from cache."""
    tests_file = get_cache_dir() / "tests.json"
    if tests_file.exists():
        try:
            return json.loads(tests_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def save_cached_tests(tests: list[dict]):
    """Save tests to cache."""
    tests_file = get_cache_dir() / "tests.json"
    tests_file.write_text(json.dumps(tests, indent=2))


class LoaderError(Exception):
    """Raised when test loading fails."""
    pass


def _parse_patterns(patterns_data) -> list[str]:
    """Parse patterns from API response.

    The API may return patterns as:
    - A list (correct): ["pattern1", "pattern2"]
    - A string repr of a list: "['pattern1', 'pattern2']"
    - A JSON string: '["pattern1", "pattern2"]'
    - None or empty

    Returns a list of pattern strings.
    """
    if not patterns_data:
        return []

    if isinstance(patterns_data, list):
        return patterns_data

    if isinstance(patterns_data, str):
        # Try to parse as Python literal (handles "['a', 'b']")
        try:
            parsed = ast.literal_eval(patterns_data)
            if isinstance(parsed, list):
                return parsed
        except (ValueError, SyntaxError):
            pass

        # Try JSON parsing
        import json
        try:
            parsed = json.loads(patterns_data)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

        # If it's a non-empty string that's not a list repr,
        # treat as single pattern (but filter out very short strings)
        if len(patterns_data) > 3:
            return [patterns_data]

    return []


@dataclass
class MultiTurnTest(SecurityTest):
    """A multi-turn security test case."""
    name: Optional[str] = None
    turns: list = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class TestLoader:
    """Loads security tests from YAML files or API."""

    API_BASE = "https://api.securitybench.ai"

    def __init__(self, tests_dir: Optional[Path] = None, use_cache: bool = True):
        """Initialize the test loader.

        Args:
            tests_dir: Directory containing test YAML files.
            use_cache: Whether to use local cache (default True).
        """
        self.tests_dir = tests_dir
        self._tests: list[SecurityTest] = []
        self._loaded = False
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
            return local_version.get("tests_version") == api_version.get("tests_version")
        except Exception:
            return False

    def load_all(
        self,
        categories: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> list[SecurityTest]:
        """Load all tests from the test directory.

        Args:
            categories: Filter by category codes.
            severity: Filter by severity levels.
            tags: Filter by tags.

        Returns:
            List of SecurityTest objects.

        Raises:
            LoaderError: If loading fails or tests are invalid.
        """
        if not self._loaded:
            self._load_from_dir()
            self._loaded = True

        result = self._tests

        if categories:
            result = [t for t in result if t.category in categories]

        if severity:
            result = [t for t in result if t.severity in severity]

        if tags:
            result = [t for t in result if hasattr(t, 'tags') and any(tag in t.tags for tag in tags)]

        return result

    def _load_from_dir(self):
        """Load tests from YAML files in directory."""
        if not self.tests_dir:
            return

        seen_ids = set()

        # Recursively find all YAML files
        yaml_files = list(self.tests_dir.glob("**/*.yaml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise LoaderError(f"Invalid YAML in {yaml_file.name}: {e}")

            if not data or "tests" not in data:
                continue

            for test_data in data["tests"]:
                # Validate required fields
                if "id" not in test_data:
                    raise LoaderError(f"Missing required field 'id' in {yaml_file.name}")
                if "category" not in test_data:
                    raise LoaderError(f"Missing required field 'category' in {yaml_file.name}")

                test_id = test_data["id"]

                # Check for duplicates
                if test_id in seen_ids:
                    raise LoaderError(f"Duplicate test ID: {test_id}")
                seen_ids.add(test_id)

                # Create appropriate test type
                if "turns" in test_data:
                    test = MultiTurnTest(
                        id=test_id,
                        category=test_data["category"],
                        prompt=test_data.get("prompt", ""),
                        failure_patterns=test_data.get("failure_patterns", []),
                        severity=test_data.get("severity", "medium"),
                        priority=test_data.get("priority", "medium"),
                        description=test_data.get("description"),
                        name=test_data.get("name"),
                        turns=test_data.get("turns", []),
                        tags=test_data.get("tags", []),
                    )
                else:
                    test = SecurityTest(
                        id=test_id,
                        category=test_data["category"],
                        prompt=test_data.get("prompt", ""),
                        failure_patterns=test_data.get("failure_patterns", []),
                        severity=test_data.get("severity", "medium"),
                        priority=test_data.get("priority", "medium"),
                        description=test_data.get("description"),
                    )
                    # Add tags attribute for filtering
                    test.tags = test_data.get("tags", [])

                self._tests.append(test)

    def count_by_category(self) -> dict[str, int]:
        """Get count of tests by category.

        Returns:
            Dictionary mapping category codes to counts.
        """
        if not self._loaded:
            self._load_from_dir()
            self._loaded = True

        counts = {}
        for test in self._tests:
            counts[test.category] = counts.get(test.category, 0) + 1
        return counts

    async def load_from_api(
        self,
        categories: Optional[list[str]] = None,
        limit: int = 50,
        force_refresh: bool = False,
    ) -> list[SecurityTest]:
        """Load tests from the Security Bench API.

        Uses local cache when available and version matches.

        Args:
            categories: Filter by category codes.
            limit: Maximum number of tests to load.
            force_refresh: Skip cache and download fresh.

        Returns:
            List of SecurityTest objects.
        """
        # Try cache first (for full loads without category filter)
        if self.use_cache and not force_refresh and not categories:
            if await self.is_cache_valid():
                cached = load_cached_tests()
                if cached:
                    tests = self._tests_from_data(cached)
                    return tests[:limit]

        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {"limit": limit}
            if categories and len(categories) == 1:
                params["category"] = categories[0]

            response = await client.get(
                f"{self.API_BASE}/api/tests",
                params=params,
            )
            response.raise_for_status()

            data = response.json()
            tests_data = data.get("tests", [])
            tests = self._tests_from_data(tests_data)

            # Cache the data if this was a full load
            if self.use_cache and not categories:
                save_cached_tests(tests_data)
                try:
                    api_version = await self.get_api_version()
                    save_cached_version(api_version)
                except Exception:
                    pass

            # Filter by multiple categories if needed
            if categories and len(categories) > 1:
                tests = [t for t in tests if t.category in categories]

            return tests[:limit]

    def _tests_from_data(self, tests_data: list[dict]) -> list[SecurityTest]:
        """Convert test data dicts to SecurityTest objects."""
        tests = []
        for test_data in tests_data:
            # Parse patterns from API (may be string repr of list)
            patterns = _parse_patterns(
                test_data.get("patterns") or test_data.get("failure_patterns")
            )
            test = SecurityTest(
                id=test_data["id"],
                category=test_data["category"],
                prompt=test_data["prompt"],
                failure_patterns=patterns,
                severity=test_data.get("severity", "medium"),
                priority=test_data.get("priority", "medium"),
            )
            tests.append(test)
        return tests

    async def load_balanced_from_api(
        self,
        per_category: int = 5,
        categories: Optional[list[str]] = None,
    ) -> list[SecurityTest]:
        """Load tests with balanced sampling across all categories.

        Args:
            per_category: Number of tests to load per category.
            categories: Specific categories to load (or all if None).

        Returns:
            List of SecurityTest objects balanced across categories.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get category list if not provided
            if not categories:
                response = await client.get(f"{self.API_BASE}/api/categories")
                response.raise_for_status()
                cat_data = response.json()
                categories = [c["code"] for c in cat_data if c["code"] != "UNC"]

            all_tests = []
            for category in categories:
                response = await client.get(
                    f"{self.API_BASE}/api/tests",
                    params={"category": category, "limit": per_category},
                )
                response.raise_for_status()
                data = response.json()

                for test_data in data.get("tests", []):
                    # Parse patterns from API (may be string repr of list)
                    patterns = _parse_patterns(
                        test_data.get("patterns") or test_data.get("failure_patterns")
                    )
                    test = SecurityTest(
                        id=test_data["id"],
                        category=test_data["category"],
                        prompt=test_data["prompt"],
                        failure_patterns=patterns,
                        severity=test_data.get("severity", "medium"),
                        priority=test_data.get("priority", "medium"),
                    )
                    all_tests.append(test)

            return all_tests

    async def load_categories(self) -> list[dict]:
        """Load all available categories from the API.

        Returns:
            List of category dicts with code, name, description, and count.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{self.API_BASE}/api/categories")
            response.raise_for_status()
            return response.json()
