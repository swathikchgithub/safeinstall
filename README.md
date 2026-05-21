# safeinstall

Multi-layered npm package risk scanner with LLM-powered code analysis. Combines OSV's known-malicious database, npm registry metadata, static pattern matching, and LLM code review into a single risk score with a clear verdict (ALLOW / WARN / BLOCK).

Built in response to the 2025-2026 wave of supply-chain attacks targeting agentic AI infrastructure (Shai-Hulud, CanisterWorm).

## Setup

    git clone https://github.com/swathikchgithub/safeinstall.git
    cd safeinstall
    npm install
    export OPENROUTER_API_KEY="sk-or-v1-..."

## Usage

    npm run dev npm <package>[@version]

## Example output

Known malicious package — instant block:

    $ npm run dev npm scan4all@3.0.0
    Risk: 100/100   Verdict: BLOCK   (716ms)
    [KNOWN MALICIOUS] MAL-2024-2986: Malicious code in scan4all (npm)
    [METADATA] Version 3.0.0 not found

Legitimate package — LLM summarizes what it does:

    $ npm run dev npm axios
    axios@1.16.1
    Risk: 3/100   Verdict: ALLOW   (18s)
    [LLM REVIEW] Axios is a legitimate HTTP client library...

## Architecture

Four checks run in parallel and aggregate into a weighted risk score:

1. **OSV.dev malicious-package DB + CVE lookup** — catches known-bad packages by exact name+version match
2. **npm registry metadata** — flags install hooks (preinstall/postinstall), brand-new packages, deprecation
3. **Tarball static scan** — downloads the package, scans for obfuscation patterns (eval+base64, network+exec combinations, hex-encoded payloads)
4. **LLM code review** — passes the package's main entry file to an LLM via OpenRouter for plain-English security analysis

Auto-escalates to 100/BLOCK when a package is both flagged malicious AND removed from the registry.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OPENROUTER_API_KEY` | required | OpenRouter API key for LLM analysis |
| `SAFEINSTALL_MODEL` | `minimax/minimax-m2.7` | Override the LLM model |

## Scoring

| Verdict | Threshold | Meaning |
|---|---|---|
| BLOCK | ≥ 70 | Do not install |
| WARN | 30 – 69 | Review before installing |
| ALLOW | < 30 | Likely safe |

Weights: critical = 50, high = 25, medium = 10, low = 3.

## Roadmap

- [ ] pip / PyPI support
- [ ] VirusTotal hash check for binary releases
- [ ] Result caching
- [ ] `safeinstall audit` — scan every package in node_modules
- [ ] GitHub Action for CI

## License

MIT
