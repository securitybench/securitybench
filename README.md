# Security Bench

**Website:** [securitybench.ai](https://securitybench.ai)

Security testing framework for AI/LLM pipelines - Test your AI systems for prompt injection, jailbreaks, data leakage, and other security vulnerabilities.

## Overview

Security Bench is a comprehensive security testing tool designed for real-world AI deployments. Unlike benchmarks that only test base models, Security Bench tests your **entire pipeline** - including RAG systems, tool-calling agents, and multi-component architectures.

### Key Features

- **Two Testing Modes** - LLM endpoint scanning AND local code/config auditing
- **Pipeline-First Testing** - Test deployed systems, not just models
- **Lynis-Style Auditing** - Rich terminal output with grades, findings, and remediation
- **Privacy-Preserving** - 100% local execution, no data leaves your environment
- **Comprehensive Coverage** - 1,400+ LLM tests, 327 local checks across 32 categories
- **Simple to Advanced** - Zero-config for quick scans, detailed config for complex systems

## Quick Start

```bash
# Install
pip3 install securitybench

# Audit local project for security issues
python3 -m sb.cli audit

# Code-only analysis
python3 -m sb.cli code ./src

# Scan an LLM endpoint for vulnerabilities
python3 -m sb.cli scan https://api.example.com/chat --balanced
```

**Note:** Scan results include `passed: null` with judging criteria. Use Claude or another LLM to evaluate pass/fail based on the criteria provided for each test.

### LLM Endpoint Testing

```bash
# Quick security check
sb scan https://api.example.com/chat --header "Authorization: Bearer sk-..." --limit 20

# Balanced scan across all 32 attack categories
sb scan https://api.example.com/chat --balanced

# Full scan with configuration file
sb scan --config securitybench.yaml
```

### Local Security Auditing (Lynis-style)

```bash
# Full audit (code + config + infrastructure)
sb audit

# Code analysis only (prompt injection patterns, secrets, etc.)
sb code

# Configuration checks only (exposed keys, insecure settings)
sb config

# Infrastructure checks only (Docker, K8s, permissions)
sb infra

# Get remediation guidance for a specific finding
sb fix CODE-001
```

## Test Modes

Security Bench provides flexible test modes to balance speed vs. coverage:

| Mode | Tests | Use Case |
|------|-------|----------|
| `--limit 20` | 20 random | Quick smoke test |
| `--limit 50` | 50 random | Default, general testing |
| `--balanced` | 155 (5 × 31 categories) | **Recommended for benchmarking** |
| `--balanced --per-category 10` | 310 | Thorough coverage |
| `--categories SPE,PIN` | Filtered | Focus on specific attacks |

### Balanced Mode (Recommended)

The `--balanced` flag ensures even sampling across all 32 attack categories:

```bash
sb scan https://api.example.com/chat --balanced --delay 2
```

- **Default**: 5 tests per category = 155 tests total
- **Adjustable**: `--per-category 10` for 310 tests
- **Stable**: Always includes all categories, even as the test database grows
- **Comparable**: Results are comparable across models on the leaderboard

### Rate Limiting

Use `--delay` to avoid rate limits when testing external APIs:

```bash
sb scan https://openrouter.ai/api/v1 -m gpt-4 --balanced --delay 2
```

This adds a 2-second pause between API calls (155 tests × 2s ≈ 5 minutes).

## Test Categories (32 Total)

Security Bench provides comprehensive coverage across **32 attack categories** (31 with active tests, 1 uncategorized).

**Balanced mode** (`--balanced`) samples 5 tests per category = 155 tests total, ensuring even coverage.

### Categories

**Injection & Manipulation:**
SPE (System Prompt Extraction), PIN (Prompt Injection), IND (Indirect Injection), JBR (Jailbreak), OBF (Obfuscation), MTM (Multi-Turn Manipulation), GHJ (Goal Hijacking), CTX (Context Manipulation)

**Information & Data:**
ILK (Information Leakage), SEC (Secret Extraction), EXF (Data Exfiltration), MEX (Model Extraction), CEX (Code Execution), OPS (Output Manipulation)

**Agentic & Advanced:**
AGY (Excessive Agency), RAG (RAG/Vector Poisoning), VEC (Vector/Embedding Attacks), MEM (Memory Poisoning), IAT (Inter-Agent Trust), MCP (Model Context Protocol), COT (Chain-of-Thought Manipulation), IMG (Multi-modal Injection)

**Safety & Compliance:**
SOC (Social Engineering), BSE (Bias/Safety Exploitation), CMP (Compliance Violation), HAL (Hallucination Exploitation), RES (Resource Exhaustion)

**Emerging:**
POI (Poisoning Detection), TRG (Backdoor Triggers), AUD (Audit Trail Manipulation), SID (Side-Channel Attacks), UNC (Uncategorized)

## Editions

### Community (Open Source)
- Core testing engine
- ~330 baseline security tests
- CLI and MCP server
- Elastic License 2.0

### PRO (Commercial)
- +750 advanced tests
- Industry-specific attack scenarios
- Continuous updates with latest techniques
- Priority support

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration](docs/configuration.md)
- [MCP Server Setup](docs/mcp-server.md)
- [Test Categories](docs/categories.md)

## Evaluation

Security Bench uses an LLM-as-Judge approach for evaluating test results. The scan command returns responses with judging criteria for each test. An external LLM (e.g., Claude) evaluates whether attacks succeeded based on the provided criteria.

**How it works:**
1. `sb scan` sends attack prompts to your LLM endpoint
2. Responses are collected with `passed: null` (pending judgment)
3. Each test includes `criteria` with pass/fail definitions
4. Use Claude or another LLM to judge pass/fail based on criteria

## Project Status

**Status:** Beta
**Version:** 0.2.11

**Working:**
- ✅ LLM endpoint scanning (`sb scan`)
- ✅ Local security auditing (`sb audit`, `sb code`, `sb config`, `sb infra`)
- ✅ Rich terminal output with grades and findings
- ✅ JSON output for CI/CD integration

**Coming Soon:**
- MCP server for AI assistant integration
- HTML/PDF report generation

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for research inspiration and credits.

## License

Elastic License 2.0 (ELv2) - Free to use, but you may not offer it as a hosted service. See [LICENSE](LICENSE) for details.

---

**Made with ❤️ for the AI security community**
