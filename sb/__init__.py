"""Security Bench - Security testing for LLM pipelines.

A comprehensive CLI tool for testing LLM applications against security
vulnerabilities including prompt injection, jailbreaks, and data leakage.
"""
from .config import PipelineConfig, EndpointConfig, InputConfig, OutputConfig, ConfigError
from .bench import SecurityBench, SecurityTest, ScanResults, TestResult
from .runner import TestRunner, RunResult
from .loader import TestLoader, LoaderError
from .evaluators import PatternEvaluator, EvaluationResult
from .cli import main

__version__ = "0.2.13"

__all__ = [
    # Config
    "PipelineConfig",
    "EndpointConfig",
    "InputConfig",
    "OutputConfig",
    "ConfigError",
    # Bench
    "SecurityBench",
    "SecurityTest",
    "ScanResults",
    "TestResult",
    # Runner
    "TestRunner",
    "RunResult",
    # Loader
    "TestLoader",
    "LoaderError",
    # Evaluator
    "PatternEvaluator",
    "EvaluationResult",
    # CLI
    "main",
]
