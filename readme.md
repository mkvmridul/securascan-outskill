# 🛡️ SecuraScan

AI-powered security scanner that analyses codebases for OWASP Top 10 vulnerabilities using LLMs.

## Features

- **12 specialist security agents** — secrets, SQLi, XSS, auth, injection, IDOR, misconfig, crypto, logging, PII logging, exception handling
- **AI orchestrator** — analyses your codebase and decides which agents to run
- **Multi-provider** — supports Anthropic, OpenAI, and Google Gemini
- **Dual mode** — `basic` (fast, lightweight) or `advanced` (deep analysis)
- **Rate limited** — sequential execution with 1s delay between LLM calls
- **HTML reports** — styled vulnerability report with risk scoring

## Setup

```bash
# Install dependencies
npm install

# Copy env template and add your API key
cp .env.example .env
```

Add your API key to `.env`:

```dotenv
# Pick one:
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIzaSy...
```

## Configuration

```bash
# Configure provider and model
node cli.js config --provider anthropic --model claude-haiku-4-5-20251001

# For Gemini
node cli.js config --provider gemini --model gemini-2.0-flash

# For OpenAI
node cli.js config --provider openai --model gpt-4o

# Check current config
node cli.js status
```

## Usage

```bash
# Scan a local directory (basic mode - default)
node cli.js scan .

# Scan with advanced mode (deeper analysis, more tokens)
node cli.js scan ./my-project --mode advanced

# Scan with verbose output
node cli.js scan . --verbose

# Save JSON + HTML report
node cli.js scan ./my-project --output report.json

# Generate HTML report only
node cli.js scan . --html report.html

# Output raw JSON
node cli.js scan . --json

# Scan a GitHub repository
node cli.js scan-github https://github.com/owner/repo

# Scan a ZIP archive
node cli.js scan-zip ./project.zip
```

## Commands

| Command | Description |
|---------|-------------|
| `config` | Configure provider, model, and API key |
| `scan <path>` | Scan a local directory |
| `scan-github <url>` | Scan a GitHub repository |
| `scan-zip <file>` | Scan a ZIP archive |
| `status` | Show current configuration |
| `help` | Show help message |

## Options

| Flag | Description |
|------|-------------|
| `--provider <name>` | `anthropic`, `openai`, or `gemini` |
| `--model <name>` | Model to use (e.g. `claude-haiku-4-5-20251001`) |
| `--mode <mode>` | `basic` (fast) or `advanced` (deep) — default: `basic` |
| `--output, -o <file>` | Save report as JSON + HTML |
| `--html <file>` | Save HTML report only |
| `--json` | Output raw JSON to stdout |
| `--verbose, -v` | Show detailed progress |

## How It Works

```
1. INGESTION     → Reads and filters source files (max 40 files, 150KB)
2. ORCHESTRATOR  → LLM analyses code, picks relevant agents (1 API call)
3. AGENTS        → Each agent scans for specific vulnerabilities (1 call each)
4. REPORT        → Aggregates findings, calculates risk score (no API call)
5. OUTPUT        → JSON + styled HTML report
```

## Project Structure

```
securascan/
├── cli.js                      # CLI entry point
├── agents/
│   ├── orchestrator.js         # Triage agent
│   ├── prompts/
│   │   ├── basic.js            # Lightweight prompts (~100 tokens)
│   │   └── advanced.js         # Detailed prompts (~500-1000 tokens)
│   └── specialists/
│       ├── secrets.js          # Hardcoded credentials
│       ├── sqli.js             # SQL injection
│       ├── xss.js              # Cross-site scripting
│       ├── auth.js             # Auth & session flaws
│       ├── injection.js        # Command/code injection
│       ├── idor.js             # Broken access control
│       ├── misconfig.js        # Security misconfiguration
│       ├── crypto.js           # Weak cryptography
│       ├── logging.js          # Missing security logs
│       ├── piiLogging.js       # Sensitive data in logs
│       ├── exception.js        # Unsafe error handling
│       └── report.js           # Report generator
├── ingestion/
│   ├── localScanner.js         # Directory scanner
│   ├── githubFetcher.js        # GitHub repo fetcher
│   └── zipParser.js            # ZIP archive parser
└── utils/
    ├── llmClient.js            # LLM client (Anthropic/OpenAI/Gemini)
    └── htmlGenerator.js        # HTML report generator
```

## License

MIT
