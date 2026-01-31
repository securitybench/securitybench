# Security Bench - Quick Reference

Security testing CLI for AI/LLM pipelines.

## Installation & Running

```bash
# Install
pip3 install securitybench

# Run commands using python3 -m (works regardless of PATH)
python3 -m sb.cli infra
python3 -m sb.cli audit
python3 -m sb.cli code
python3 -m sb.cli config
```

## Commands

| Command | Purpose |
|---------|---------|
| `python3 -m sb.cli infra` | Docker, K8s, permissions checks |
| `python3 -m sb.cli code` | Secrets, injection patterns, prompt security |
| `python3 -m sb.cli config` | API keys, CORS, logging issues |
| `python3 -m sb.cli audit` | All of the above |
| `python3 -m sb.cli fix <id>` | Remediation guidance for a finding |
| `python3 -m sb.cli update` | Download latest tests/checks |
| `python3 -m sb.cli man` | Open manual in browser |

## Options

- `--format json` - Machine-readable output
- `--verbose / -v` - Detailed findings
- `--save <file>` - Save results to file

## LLM Endpoint Testing

```bash
python3 -m sb.cli scan <url> -m <model>
python3 -m sb.cli scan <url> -m <model> --balanced   # Even sampling across 31 categories
python3 -m sb.cli scan <url> -m <model> --limit 20   # Quick test
```

**URL Format:** Use base URL without `/v1` suffix:
- Correct: `http://192.168.1.50:11434`
- Wrong: `http://192.168.1.50:11434/v1`

**Evaluation:** Scans return `passed: null` with criteria for LLM judging. Use Claude or another LLM to evaluate pass/fail based on the provided criteria.

## What It Checks

- 327 local security checks (infra, code, config)
- 1,400+ LLM attack prompts (32 categories)
- Docker/K8s misconfigurations
- Hardcoded secrets and credentials
- Prompt injection vulnerabilities
- API key exposure

## License

Elastic License 2.0 (free use, no hosted service)
