"""Test runner for executing security tests against LLM endpoints.

Provides async HTTP client for sending test prompts and extracting responses.
"""
from dataclasses import dataclass
from typing import Optional
import json
import re
import httpx

from .config import PipelineConfig
from .bench import SecurityTest


@dataclass
class RunResult:
    """Result of running a single test."""
    response_text: Optional[str] = None
    error: Optional[str] = None
    status_code: Optional[int] = None
    raw_response: Optional[dict] = None


class TestRunner:
    """Executes security tests against configured endpoints."""

    def __init__(self, config: PipelineConfig):
        """Initialize the test runner.

        Args:
            config: Pipeline configuration with endpoint and format settings.
        """
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.endpoint.timeout)
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def run_test(self, test: SecurityTest) -> RunResult:
        """Execute a single security test.

        Args:
            test: The security test to run.

        Returns:
            RunResult with response text or error.
        """
        try:
            client = await self._get_client()

            # Build request payload
            payload = self._build_payload(test.prompt)

            # Build headers
            headers = {"Content-Type": "application/json"}
            if self.config.endpoint.headers:
                headers.update(self.config.endpoint.headers)

            # Send request
            response = await client.post(
                self.config.endpoint.url,
                json=payload,
                headers=headers,
            )

            # Parse response
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                # Capture raw response for debugging
                raw_text = response.text[:200] if response.text else "(empty)"
                return RunResult(
                    error=f"Invalid JSON response: {raw_text}",
                    status_code=response.status_code,
                )

            # Extract response text using path
            response_text = self._extract_response(
                response_data,
                self.config.output.response_path
            )

            return RunResult(
                response_text=response_text,
                status_code=response.status_code,
                raw_response=response_data,
            )

        except httpx.TimeoutException:
            return RunResult(error="Request timeout")
        except httpx.ConnectError as e:
            return RunResult(error=f"Connection error: {e}")
        except Exception as e:
            return RunResult(error=f"Request failed: {e}")

    def _build_payload(self, prompt: str) -> dict:
        """Build request payload based on input format.

        Args:
            prompt: The test prompt to inject.

        Returns:
            Request payload dictionary.
        """
        input_config = self.config.input

        # Handle preset formats
        if input_config.format == "openai":
            return {
                "model": input_config.model or "gpt-4",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
        elif input_config.format == "anthropic":
            return {
                "model": input_config.model or "claude-3-5-sonnet-20241022",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif input_config.format == "ollama":
            return {
                "model": self.config.endpoint.model or input_config.model or "mistral",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
        elif input_config.template:
            # Custom template format
            payload_str = input_config.template.replace("{{user_input}}", prompt)
            try:
                return json.loads(payload_str)
            except json.JSONDecodeError:
                return {"message": prompt}
        else:
            # Default simple format
            return {"message": prompt}

    def _extract_response(self, data: dict, path: str) -> Optional[str]:
        """Extract response text from API response using path.

        Args:
            data: Response JSON data.
            path: JSONPath-like path (e.g., "choices[0].message.content").

        Returns:
            Extracted response text or None.
        """
        if not path:
            return str(data)

        try:
            # Parse path like "choices[0].message.content" or "response"
            current = data

            # Split on dots, handling array indices
            parts = re.split(r'\.(?![^\[]*\])', path)

            for part in parts:
                if not part:
                    continue

                # Check for array index: key[0]
                match = re.match(r'(\w+)\[(\d+)\]', part)
                if match:
                    key = match.group(1)
                    index = int(match.group(2))
                    current = current[key][index]
                else:
                    current = current[part]

            return str(current) if current is not None else None

        except (KeyError, IndexError, TypeError):
            return None
