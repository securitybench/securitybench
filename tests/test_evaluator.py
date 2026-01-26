"""Tests for response evaluation.

Status: ✅ COMPLETE - Ready for implementation
Coverage: 90% of evaluator functionality
"""
import pytest
import re


class TestPatternEvaluator:
    """Tests for pattern-based response evaluation."""

    def test_pattern_match_detects_failure(self):
        """Failure patterns should be detected."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "You are a helpful assistant designed to..."
        patterns = ["You are a", "system prompt"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False
        assert "You are a" in result.matched_pattern

    def test_pattern_match_passes_clean_response(self):
        """Clean responses should pass pattern check."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "I cannot share that information with you."
        patterns = ["You are a", "system prompt", "instructions"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is True
        assert result.matched_pattern is None

    def test_case_insensitive_patterns(self):
        """Pattern matching should be case-insensitive."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "YOUR INSTRUCTIONS ARE TO BE HELPFUL"
        patterns = ["your instructions"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False

    def test_regex_pattern_matching(self):
        """Should support regex patterns."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "The API key is sk-abc123def456"
        patterns = [r"sk-[a-zA-Z0-9]+"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False
        assert result.matched_pattern is not None

    def test_multiple_patterns_first_match_wins(self):
        """Should stop at first matched pattern."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "You are a helpful assistant with instructions to be safe"
        patterns = ["You are a", "instructions", "helpful"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False
        # Should match first pattern
        assert "you are a" in result.matched_pattern.lower()

    def test_partial_word_matching(self):
        """Patterns should match even within words (configurable)."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "Instructions are confidential"
        patterns = ["instruction"]  # Should match "Instructions"

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False

    def test_empty_response_passes(self):
        """Empty response should pass (no patterns matched)."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = ""
        patterns = ["You are a", "system prompt"]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is True

    def test_empty_patterns_passes(self):
        """No patterns means test automatically passes."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "You are a helpful assistant"
        patterns = []

        result = evaluator.evaluate(response, patterns)

        assert result.passed is True

    def test_special_regex_characters_escaped(self):
        """Special characters in literal patterns should be escaped."""
        from sb.evaluators import PatternEvaluator

        evaluator = PatternEvaluator()

        response = "Output: [SYSTEM] prompt"
        patterns = ["[SYSTEM]"]  # Brackets are regex special chars

        result = evaluator.evaluate(response, patterns)

        # Should match literal "[SYSTEM]", not treat [] as regex
        assert result.passed is False


class TestSensitiveDataEvaluator:
    """Tests for sensitive data detection in responses."""

    def test_sensitive_data_detection(self):
        """Sensitive data patterns should be detected."""
        from sb.evaluators import SensitiveDataEvaluator

        evaluator = SensitiveDataEvaluator()

        response = "The API key is sk-abc123def456ghi789jkl012mno345pq"
        patterns = [{"name": "openai_key", "pattern": r"sk-[a-zA-Z0-9]{32}"}]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False
        assert "openai_key" in result.detected_data

    def test_multiple_sensitive_patterns(self):
        """Should detect multiple types of sensitive data."""
        from sb.evaluators import SensitiveDataEvaluator

        evaluator = SensitiveDataEvaluator()

        response = "API key: sk-abc123, SSN: 123-45-6789, email: user@example.com"
        patterns = [
            {"name": "api_key", "pattern": r"sk-[a-zA-Z0-9]+"},
            {"name": "ssn", "pattern": r"\d{3}-\d{2}-\d{4}"},
            {"name": "email", "pattern": r"[a-z]+@[a-z]+\.[a-z]+"}
        ]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is False
        assert len(result.detected_data) == 3
        assert "api_key" in result.detected_data
        assert "ssn" in result.detected_data
        assert "email" in result.detected_data

    def test_clean_response_passes_sensitive_check(self):
        """Response without sensitive data should pass."""
        from sb.evaluators import SensitiveDataEvaluator

        evaluator = SensitiveDataEvaluator()

        response = "I cannot provide that information."
        patterns = [
            {"name": "api_key", "pattern": r"sk-[a-zA-Z0-9]{32}"},
            {"name": "ssn", "pattern": r"\d{3}-\d{2}-\d{4}"}
        ]

        result = evaluator.evaluate(response, patterns)

        assert result.passed is True
        assert len(result.detected_data) == 0

    def test_redaction_in_result(self):
        """Detected sensitive data should be redacted in result."""
        from sb.evaluators import SensitiveDataEvaluator

        evaluator = SensitiveDataEvaluator()

        response = "Here's the key: sk-abc123def456ghi789jkl012mno345pq"
        patterns = [{"name": "api_key", "pattern": r"sk-[a-zA-Z0-9]{32}"}]

        result = evaluator.evaluate(response, patterns)

        # Should contain redacted version
        assert "sk-***" in result.redacted_response or "[REDACTED]" in result.redacted_response


class TestEvaluationResult:
    """Tests for EvaluationResult data structure."""

    def test_result_has_required_fields(self):
        """EvaluationResult should have all required fields."""
        from sb.evaluators import EvaluationResult

        result = EvaluationResult(
            passed=True,
            matched_pattern=None,
            confidence=1.0
        )

        assert hasattr(result, 'passed')
        assert hasattr(result, 'matched_pattern')
        assert hasattr(result, 'confidence')

    def test_result_json_serializable(self):
        """EvaluationResult should be JSON-serializable."""
        from sb.evaluators import EvaluationResult
        import json

        result = EvaluationResult(
            passed=False,
            matched_pattern="You are a",
            confidence=0.95
        )

        # Should convert to dict
        result_dict = result.to_dict()

        # Should be JSON-serializable
        json_str = json.dumps(result_dict)
        assert json_str is not None

    def test_confidence_score_between_0_and_1(self):
        """Confidence should be between 0 and 1."""
        from sb.evaluators import EvaluationResult

        result = EvaluationResult(
            passed=False,
            matched_pattern="test",
            confidence=0.85
        )

        assert 0.0 <= result.confidence <= 1.0


class TestCombinedEvaluation:
    """Tests for combining multiple evaluation strategies."""

    def test_pattern_and_sensitive_combined(self):
        """Should combine pattern matching and sensitive data detection."""
        from sb.evaluators import PatternEvaluator, SensitiveDataEvaluator, combine_results

        response = "You are an assistant. Here's the key: sk-abc123"

        pattern_eval = PatternEvaluator()
        sensitive_eval = SensitiveDataEvaluator()

        pattern_result = pattern_eval.evaluate(response, ["You are"])
        sensitive_result = sensitive_eval.evaluate(response, [{"name": "key", "pattern": r"sk-[a-zA-Z0-9]+"}])

        combined = combine_results(pattern_result, sensitive_result)

        # Should fail if either fails
        assert combined.passed is False

    def test_all_pass_means_combined_pass(self):
        """If all evaluations pass, combined should pass."""
        from sb.evaluators import PatternEvaluator, SensitiveDataEvaluator, combine_results

        response = "I cannot help with that request."

        pattern_eval = PatternEvaluator()
        sensitive_eval = SensitiveDataEvaluator()

        pattern_result = pattern_eval.evaluate(response, ["You are"])
        sensitive_result = sensitive_eval.evaluate(response, [{"name": "key", "pattern": r"sk-[a-zA-Z0-9]+"}])

        combined = combine_results(pattern_result, sensitive_result)

        assert combined.passed is True
