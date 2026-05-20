# CodeGuard — AI-Powered Multi-Agent Code Review System

## Overview

CodeGuard is an end-to-end AI code review platform that submits code through a sequential pipeline of five specialized AI agents, each responsible for a distinct aspect of software quality. Within roughly 45–60 seconds of submission, a developer receives:

- A full security vulnerability report with severity ratings
- A code quality analysis with a scored rubric
- Ready-to-run unit tests for their code
- A complete rewrite of the code with all issues fixed
- A compiled executive summary report
- A context-aware chat assistant for follow-up questions

The problem CodeGuard solves is the gap between writing code and knowing whether it is safe, maintainable, and tested. Junior developers, solo founders, and teams without dedicated security engineers can run production-grade code reviews on demand.

---

## Architecture

### Multi-Agent Pipeline

CodeGuard uses a **sequential LangGraph pipeline** where each agent writes its findings into a shared state dictionary that all downstream agents can read. This mirrors how a real engineering review process works: the quality reviewer reads the security findings before writing their own, the fix agent reads both, and the summary agent compiles everything.

```
User Code Input
      |
      v
 [Guardrails]  <-- Input validation, prompt injection check, PII detection
      |
      v
[Language Detector]  <-- Identifies programming language (1 API call)
      |
      v
[Security Agent]  <-- Scans for vulnerabilities, outputs SEVERITY + ISSUES
      |
      v
[Quality Agent]  <-- Reviews quality, reads security findings to avoid duplication
      |
      v
[Test Agent]  <-- Generates unit tests (pytest / Jest / JUnit)
      |
      v
[Fix Agent]  <-- Rewrites code with ALL security + quality issues resolved
      |
      v
[Summary Agent]  <-- Compiles final structured report with OVERALL SCORE
      |
      v
  [SQLite DB]  <-- Persists full review for history tab
      |
      v
[Streamlit UI]  <-- Displays results, enables chat follow-up
```

### State Management

LangGraph manages execution as a `StateGraph` over a typed `CodeReviewState` dictionary:

```python
class CodeReviewState(TypedDict):
    code: str
    language: str
    security_findings: str
    quality_findings: str
    test_findings: str
    fixed_code: str
    final_report: str
```

Each agent receives the full state, adds its findings to the relevant field, and returns the updated state. This eliminates the need for inter-agent messaging or shared memory objects.

### Why Sequential Over Parallel?

The agents have deliberate **data dependencies**:
- Quality Agent reads `security_findings` to avoid repeating security issues as quality issues
- Fix Agent reads both `security_findings` and `quality_findings` to address all problems
- Summary Agent reads all four findings to produce a coherent report

Running them in parallel would break these dependencies and produce lower-quality, redundant output.

---

## Features

| Feature | Description |
|---|---|
| **Language Detection** | Automatically identifies the programming language before any agent runs |
| **Security Scanning** | Detects SQL injection, hardcoded secrets, XSS, unsafe input handling, and insecure imports |
| **Code Quality Analysis** | Scores code 1-10 and identifies naming issues, missing error handling, complexity, duplication |
| **Unit Test Generation** | Generates runnable pytest / Jest / JUnit tests covering normal, edge, and error cases |
| **AI Code Fixing** | Rewrites the entire submitted code with all security and quality issues resolved |
| **Review Reports** | Structured plain-text report with Overall Score, Priority Actions, and Executive Summary |
| **Chat Assistant** | Context-aware conversation agent that can answer follow-up questions about any finding |
| **Review History** | All reviews persisted to SQLite and viewable in a searchable history dashboard |
| **Guardrails** | Multi-layer input validation, prompt injection detection, and PII scanning |
| **Real-time Progress** | Live per-agent status indicators (Pending → Running → Complete) during review |

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **AI Backbone** | Anthropic Claude claude-sonnet-4-5 | All agents and language detection |
| **Agent Orchestration** | LangGraph 1.2 | Pipeline graph, state management, execution flow |
| **LLM Framework** | LangChain 1.3 | Prompt templates, chains, message history |
| **Frontend** | Streamlit 1.37 | UI, real-time updates, chat interface |
| **Database** | SQLite (stdlib) | Review history persistence |
| **Secrets** | python-dotenv | Environment variable management |
| **Deployment** | Docker + Azure App Service | Production containerized deployment |
| **Language** | Python 3.12 | Runtime |

---

## Security and Guardrails

CodeGuard implements four layers of guardrails before any user input reaches the AI agents:

### Layer 1 — Input Validation (`guardrails/validators.py`)
- **Empty check**: Rejects blank submissions
- **Length check**: Enforces 10–10,000 character range to prevent abuse
- **Code check**: Requires at least 2 recognizable code indicators (`def`, `import`, `{`, `}`, etc.) to reject plain text or spam
- **Prompt injection check**: Scans for 10+ known injection patterns (`ignore previous instructions`, `jailbreak`, `act as`, `system prompt`, etc.) using regex

### Layer 2 — PII Detection
Scans submitted code for personally identifiable information before sending to any AI agent:
- Email addresses
- US phone numbers
- Social Security Numbers
- Credit card numbers

PII detection does not block the review — it surfaces a warning banner so the user is aware their code may contain sensitive data.

### Layer 3 — Output Validation
The final report is validated before being shown to the user. Reports shorter than 50 characters (indicating a malformed or empty response) are flagged and the user is asked to resubmit.

### Layer 4 — API Key Management
The Anthropic API key is never hardcoded. It is loaded from a `.env` file (excluded from version control) using `python-dotenv`. In production, it is injected as an environment variable via Azure App Service configuration.

---

## Project Structure

```
codeguard/
│
├── agents/                     # The five AI review agents + chat agent
│   ├── __init__.py
│   ├── security_agent.py       # Vulnerability scanner (SEVERITY: HIGH/MEDIUM/LOW)
│   ├── quality_agent.py        # Code quality reviewer (QUALITY_SCORE: 1-10)
│   ├── test_agent.py           # Unit test generator (pytest / Jest / JUnit)
│   ├── fix_agent.py            # Code rewriter with all fixes applied
│   ├── summary_agent.py        # Final report compiler (OVERALL SCORE: 1-10)
│   └── chat_agent.py           # Context-aware follow-up chat assistant
│
├── pipeline/                   # LangGraph orchestration
│   ├── __init__.py
│   └── graph.py                # StateGraph definition, agent wiring, pipeline runner
│
├── guardrails/                 # Input/output safety layer
│   ├── __init__.py
│   └── validators.py           # validate_input, check_pii, validate_output
│
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── e2e_test.py             # End-to-end pipeline + guardrails + DB tests
│   └── test_guardrails.py      # Unit tests for validators
│
├── .streamlit/
│   └── config.toml             # Dark theme, server settings
│
├── app.py                      # Streamlit frontend (single-file UI)
├── database.py                 # SQLite init, save_review, get_all_reviews, get_review_by_id
├── utils.py                    # Language detection utility
│
├── Dockerfile                  # Production container definition
├── .dockerignore
├── requirements.txt            # Pinned Python dependencies
├── .gitignore
└── README.md
```

---

## Setup and Installation

### Prerequisites
- Python 3.10+ (3.12 recommended)
- An Anthropic API key — get one at [console.anthropic.com](https://console.anthropic.com)
- Conda or pip

### 1. Clone the repository

```bash
git clone https://github.com/ashrithaumd/codeguard.git
cd codeguard
```

### 2. Create and activate a conda environment

```bash
conda create -n codeguard python=3.12 -y
conda activate codeguard
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```bash
# .env
ANTHROPIC_API_KEY=your_api_key_here
```

> The `.env` file is excluded from version control via `.gitignore`. Never commit your API key.

### 5. Run the application

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`.

---

## Running with Docker

```bash
# Build the image
docker build -t codeguard .

# Run with your API key injected
docker run -p 8501:8501 -e ANTHROPIC_API_KEY=your_key_here codeguard
```

---

## Live Deployment

| Platform | URL |
|---|---|
| **Azure Container Apps** | https://codeguard-app.kindsea-113305b4.eastus.azurecontainerapps.io |

Deployed as a containerized app using the `Dockerfile` in this repository, hosted on Azure Container Apps in the `eastus` region.

---

## Running Tests

```bash
# Fast tests — guardrails + database only (no API calls)
python tests/e2e_test.py

# Full pipeline test — all 5 agents, uses API (~60 seconds)
RUN_PIPELINE=1 python tests/e2e_test.py
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic Claude API key for all AI agents |

All agents use the same API key. The key is loaded once per module via `python-dotenv` at startup.

---

## Multi-Agent Design Decisions

### Why LangGraph over CrewAI or AutoGen?

**LangGraph** was chosen because it gives precise, code-level control over the execution graph. The pipeline needs deterministic sequential ordering with typed shared state — LangGraph's `StateGraph` models this exactly. CrewAI and AutoGen are designed for autonomous, self-directing agents that debate and delegate tasks; that pattern adds unpredictability and cost overhead that is unnecessary for a structured review pipeline where every step is known in advance.

### Why Sequential over Parallel Execution?

The agents have intentional data dependencies: the Quality Agent reads Security findings before writing its own, and the Fix Agent reads both. Running in parallel would require a second round of agent calls to incorporate cross-agent context, making the system more complex and more expensive without meaningful time savings for code of typical review size.

### Why Anthropic Claude over GPT-4?

- **Claude claude-sonnet-4-5** consistently follows complex structured output formats (the `SEVERITY: HIGH / ISSUES: / RECOMMENDATION:` pattern) with fewer hallucinated format deviations than GPT-4 Turbo in testing
- Claude has a 200K context window, which is valuable as the pipeline accumulates findings across agents
- Anthropic's API has competitive pricing for the token volume a 5-agent pipeline consumes per review

### Why One LLM Instance per Agent Module?

Each agent module instantiates its own `ChatAnthropic` client at import time. This is intentional: it means each agent has independent configuration (different `max_tokens` limits suited to its output size) without sharing mutable state between agents.

---

## Future Improvements

| Improvement | Description |
|---|---|
| **Parallel execution** | Security and Quality agents have no dependencies on each other; they could run in parallel with LangGraph's fan-out edges, cutting pipeline time by ~30% |
| **Multi-file support** | Accept a ZIP archive or GitHub repo URL and review an entire codebase |
| **GitHub PR integration** | Webhook that triggers a CodeGuard review on every pull request and posts findings as PR comments |
| **Fine-tuned security model** | Replace the general-purpose Claude call in the Security Agent with a model fine-tuned on CVE data and OWASP vulnerability patterns |
| **Streaming output** | Stream agent findings to the UI in real time as each agent completes, rather than waiting for the full pipeline |
| **Configurable severity thresholds** | Let teams define which severity levels block a PR vs. only warn |
| **SARIF export** | Export security findings in SARIF format for integration with GitHub Advanced Security and VS Code |

---

## Author

Built by **Ashritha** as part of the Wipro Junior FDE Pre-screening Assignment.

- GitHub: [github.com/ashrithaumd](https://github.com/ashrithaumd)
- Email: ashritha@umd.edu
