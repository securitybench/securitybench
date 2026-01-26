"""Pipeline configuration for Security Bench CLI.

Provides dataclasses for configuring endpoints, input/output formats,
and loading configuration from YAML files with environment variable substitution.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os
import re
import yaml


class ConfigError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""
    pass


@dataclass
class SensitivePattern:
    """A pattern for detecting sensitive data in responses."""
    name: str
    pattern: str


@dataclass
class EndpointConfig:
    """Configuration for the target API endpoint."""
    url: str
    model: Optional[str] = None
    headers: Optional[dict] = None
    timeout: int = 30


@dataclass
class InputConfig:
    """Configuration for request formatting."""
    format: str
    template: Optional[str] = None
    model: Optional[str] = None


@dataclass
class OutputConfig:
    """Configuration for response parsing."""
    response_path: str


@dataclass
class PipelineConfig:
    """Complete pipeline configuration."""
    endpoint: EndpointConfig
    input: InputConfig
    output: OutputConfig
    sensitive_patterns: list[SensitivePattern] = field(default_factory=list)
    pipeline_name: Optional[str] = None
    pipeline_description: Optional[str] = None
    industry: Optional[str] = None

    @classmethod
    def from_yaml(cls, path: Path) -> "PipelineConfig":
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            PipelineConfig instance.

        Raises:
            ConfigError: If the configuration is invalid or has missing env vars.
        """
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML: {e}")

        if data is None:
            raise ConfigError("Empty configuration file")

        # Substitute environment variables
        data = cls._substitute_env_vars(data)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "PipelineConfig":
        """Create configuration from a dictionary.

        Args:
            data: Dictionary containing configuration.

        Returns:
            PipelineConfig instance.

        Raises:
            ConfigError: If required fields are missing.
        """
        # Validate required fields
        if "endpoint" not in data or data["endpoint"] is None:
            raise ConfigError("Missing required field: endpoint")
        if "url" not in data["endpoint"]:
            raise ConfigError("Missing required field: endpoint.url")
        if "input" not in data:
            raise ConfigError("Missing required field: input")
        if "format" not in data["input"]:
            raise ConfigError("Missing required field: input.format")

        # Build EndpointConfig
        endpoint_data = data["endpoint"]
        endpoint = EndpointConfig(
            url=endpoint_data["url"],
            model=endpoint_data.get("model"),
            headers=endpoint_data.get("headers"),
            timeout=endpoint_data.get("timeout", 30),
        )

        # Build InputConfig
        input_data = data["input"]
        input_config = InputConfig(
            format=input_data["format"],
            template=input_data.get("template"),
            model=input_data.get("model"),
        )

        # Build OutputConfig
        output_data = data.get("output", {})
        output = OutputConfig(
            response_path=output_data.get("response_path", "response"),
        )

        # Build SensitivePatterns
        sensitive_patterns = []
        for pattern_data in data.get("sensitive_patterns", []):
            sensitive_patterns.append(SensitivePattern(
                name=pattern_data["name"],
                pattern=pattern_data["pattern"],
            ))

        return cls(
            endpoint=endpoint,
            input=input_config,
            output=output,
            sensitive_patterns=sensitive_patterns,
            pipeline_name=data.get("pipeline_name"),
            pipeline_description=data.get("pipeline_description"),
            industry=data.get("industry"),
        )

    @classmethod
    def _substitute_env_vars(cls, data):
        """Recursively substitute ${VAR} environment variable references.

        Args:
            data: Configuration data (dict, list, or string).

        Returns:
            Data with environment variables substituted.

        Raises:
            ConfigError: If an environment variable is not set.
        """
        if isinstance(data, dict):
            return {k: cls._substitute_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls._substitute_env_vars(item) for item in data]
        elif isinstance(data, str):
            # Find all ${VAR} patterns
            pattern = r'\$\{([^}]+)\}'
            matches = re.findall(pattern, data)

            result = data
            for var_name in matches:
                value = os.environ.get(var_name)
                if value is None:
                    raise ConfigError(f"Environment variable not set: {var_name}")
                result = result.replace(f"${{{var_name}}}", value)

            return result
        else:
            return data
