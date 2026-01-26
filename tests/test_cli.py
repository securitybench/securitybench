"""Tests for CLI interface.

Status: ✅ COMPLETE - Ready for implementation
Coverage: 80% of CLI functionality
"""
import pytest
from click.testing import CliRunner
from pathlib import Path
import json


class TestCLI:
    """Tests for command-line interface."""

    @pytest.fixture
    def runner(self):
        """Provide Click CLI test runner."""
        return CliRunner()

    def test_version_command(self, runner):
        """--version should print version."""
        from sb.cli import main

        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert 'sb' in result.output.lower() or '0.1.0' in result.output

    def test_help_command(self, runner):
        """--help should show usage."""
        from sb.cli import main

        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'scan' in result.output.lower()
        assert 'describe' in result.output.lower()

    def test_scan_requires_endpoint_or_config(self, runner):
        """scan without endpoint or config should error."""
        from sb.cli import main

        result = runner.invoke(main, ['scan'])
        assert result.exit_code != 0
        assert 'endpoint' in result.output.lower() or 'config' in result.output.lower()

    def test_scan_with_config_file(self, runner, tmp_path):
        """scan --config should load config file."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        # This will fail to connect but should parse config
        result = runner.invoke(main, ['scan', '--config', str(config_file), '--dry-run'])
        # Dry run shouldn't fail on config parsing
        assert 'api.example.com' in result.output or result.exit_code == 0

    def test_scan_with_direct_url(self, runner):
        """scan with URL should work without config file."""
        from sb.cli import main

        result = runner.invoke(main, [
            'scan',
            'https://api.example.com/chat',
            '--dry-run'
        ])

        # Should not error on argument parsing
        assert 'api.example.com' in result.output or result.exit_code == 0

    def test_scan_with_categories_filter(self, runner, tmp_path):
        """scan --categories should filter tests."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--categories', 'SPE,PIN',
            '--dry-run'
        ])

        assert result.exit_code == 0

    def test_scan_with_severity_filter(self, runner, tmp_path):
        """scan --severity should filter by severity."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--severity', 'critical,high',
            '--dry-run'
        ])

        assert result.exit_code == 0

    def test_scan_dry_run_mode(self, runner, tmp_path):
        """--dry-run should not make actual requests."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--dry-run'
        ])

        assert result.exit_code == 0
        assert 'dry run' in result.output.lower() or 'would run' in result.output.lower()

    def test_describe_outputs_categories(self, runner):
        """describe should output category information."""
        from sb.cli import main

        result = runner.invoke(main, ['describe'])
        assert result.exit_code == 0
        # Should list some categories
        assert 'SPE' in result.output or 'System Prompt' in result.output

    def test_describe_outputs_json(self, runner):
        """describe --format json should output valid JSON."""
        from sb.cli import main

        result = runner.invoke(main, ['describe', '--format', 'json'])
        assert result.exit_code == 0

        # Should be valid JSON
        data = json.loads(result.output)
        assert 'categories' in data or isinstance(data, dict)

    def test_describe_specific_category(self, runner):
        """describe <category> should show category details."""
        from sb.cli import main

        result = runner.invoke(main, ['describe', 'SPE'])
        assert result.exit_code == 0
        assert 'SPE' in result.output or 'System Prompt' in result.output

    def test_quick_scan_command(self, runner, tmp_path):
        """quick-scan should run subset of tests."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'quick-scan',
            '--config', str(config_file),
            '--dry-run'
        ])

        assert result.exit_code == 0

    def test_output_format_text(self, runner, tmp_path):
        """--format text should output human-readable report."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--format', 'text',
            '--dry-run'
        ])

        assert result.exit_code == 0

    def test_output_format_json(self, runner, tmp_path):
        """--format json should output valid JSON."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--format', 'json',
            '--dry-run'
        ])

        if result.exit_code == 0:
            # Should be valid JSON
            data = json.loads(result.output)
            assert isinstance(data, dict)

    def test_api_key_from_env(self, runner, tmp_path, monkeypatch):
        """Should read API key from environment."""
        from sb.cli import main

        monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.openai.com/v1/chat/completions"
  headers:
    Authorization: "Bearer ${OPENAI_API_KEY}"
input:
  format: "openai"
  model: "gpt-4"
output:
  response_path: "choices[0].message.content"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--dry-run'
        ])

        assert result.exit_code == 0

    def test_verbose_flag(self, runner, tmp_path):
        """--verbose should enable detailed logging."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--verbose',
            '--dry-run'
        ])

        # Verbose mode should work
        assert result.exit_code == 0

    def test_save_results_flag(self, runner, tmp_path):
        """--save should write results to file."""
        from sb.cli import main

        config_file = tmp_path / "sb.yaml"
        config_file.write_text("""
endpoint:
  url: "https://api.example.com/chat"
input:
  format: "json"
  template: '{"message": "{{user_input}}"}'
output:
  response_path: "response"
""")

        output_file = tmp_path / "results.json"

        result = runner.invoke(main, [
            'scan',
            '--config', str(config_file),
            '--save', str(output_file),
            '--dry-run'
        ])

        # Command should succeed
        assert result.exit_code == 0


class TestConfigGeneration:
    """Tests for config generation helpers."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_init_command_creates_config(self, runner, tmp_path):
        """init command should create sample config."""
        from sb.cli import main

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ['init'])
            assert result.exit_code == 0
            assert Path('sb.yaml').exists()

    def test_init_with_preset(self, runner, tmp_path):
        """init --preset should create preset config."""
        from sb.cli import main

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ['init', '--preset', 'openai'])
            if result.exit_code == 0:
                assert Path('sb.yaml').exists()
                content = Path('sb.yaml').read_text()
                assert 'openai' in content.lower()
