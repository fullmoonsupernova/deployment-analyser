# SRE Production Deployment Risk Analyzer

> **"A deployment can pass unit tests, integration tests, security checks, and staging without any obvious problem, and still trigger a critical incident in production."**

The **SRE Production Deployment Risk Analyzer** evaluates planned software releases against real production conditions. It analyzes code diffs, infrastructure manifests, database migrations, configuration shifts, dependency updates, and external service interactions to estimate deployment risk, model failure modes, and prescribe safer rollout strategies.

---

## 🏛️ Core Architecture & Principle

### **DETERMINISTIC EVIDENCE FIRST → AI REASONING SECOND**

```text
GitHub Repository URL
       ↓
GitHub REST API
       ↓
Deployment Diff (Candidate vs Analysis Baseline)
       ↓
Deterministic Risk Scanner
       ↓
Evidence JSON (Normalized Intermediate Representation)
       ↓
Historical Incident Pattern Matching
       ↓
Groq AI (Configurable LLM reasoning only on verified findings)
       ↓
Production Failure Modes & Cascading Failure Chains
       ↓
Safer Phased Rollout Roadmap & Rollback Criteria
```

- **The deterministic scanner discovers what actually changed.** It extracts verifiable signals (dropped columns, reduced replicas, missing socket timeouts, major library updates).
- **The AI reasons strictly about how those verified factors interact under production scale.**
- **Hallucination Control**: Every AI-generated failure scenario must reference valid deterministic `evidence_ids`. The AI is never permitted to invent repository facts.

---

## 🚀 Quickstart

### 1. Requirements
- Python 3.10+ (tested on Python 3.10 – 3.14)
- **Zero Node.js / Zero npm / Zero Webpack / Zero Vite** — The application runs entirely from Python with server-rendered Jinja2 templates, standard HTML5/CSS3, and vanilla JavaScript.

### 2. Installation & Run
```bash
# Clone the repository
git clone <repo-url>
cd BITnBUILD

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the SRE Risk Analyzer
uvicorn app.main:app --reload
```

The application will be live at: **[http://localhost:8000](http://localhost:8000)**

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory (or copy `.env.example`):

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | *(optional)* | Personal GitHub token. Raises GitHub API rate limits from 60 to 5,000 requests/hr. |
| `GROQ_API_KEY` | *(optional)* | Groq API Key. Enables high-speed AI reasoning over deterministic evidence. |
| `GROQ_MODEL` | `openai/gpt-oss-20b` | Groq model identifier (e.g. `openai/gpt-oss-20b`, `llama-3.3-70b-versatile`). |
| `PORT` | `8000` | Application server port. |
| `HOST` | `0.0.0.0` | Application bind host. |

> **Offline / Keyless Demo Mode**:
> If `GROQ_API_KEY` is not provided or if Groq hits rate limits, the system automatically falls back to its **Deterministic SRE Reasoning Engine**, guaranteeing complete, high-fidelity failure scenarios and rollout plans without ever crashing or halting!

---

## 🔍 Deterministic Risk Scanners

| Scanner | Module | Signals Detected |
|---|---|---|
| **Database Migrations** | `scanner/database.py` | `ALTER TABLE DROP COLUMN`, `DROP TABLE`, `NOT NULL` without `DEFAULT`, type mutations, table/column renames, expand/contract rolling deployment hazards. |
| **Infrastructure & Redundancy** | `scanner/infrastructure.py` | Single replica reduction (`replicas: 3 → 1`), CPU/memory limits slash, probe removals, privileged container flags. |
| **Dependencies** | `scanner/dependencies.py` | Major version upgrades (e.g., `stripe 10.x → 12.x`), database driver replacements, newly added/removed packages. |
| **Configuration & Secrets** | `scanner/configuration.py` | Sudden `DB_POOL_SIZE` jumps (20 → 100), socket timeouts, retry multipliers, debug mode enabled in prod. Automatic credential scrubbing. |
| **External Services** | `scanner/external_services.py` | Third-party integrations (Stripe, AWS, Twilio, Redis, Postgres), synchronous HTTP calls without socket timeouts. |
| **Traffic Patterns** | `scanner/traffic.py` | Unbounded `SELECT *` without `LIMIT`, full ORM reads (`.all()`), missing pagination, retry storms. |
| **Service Topology** | `scanner/services.py` | Inferred service dependency graph with confidence metrics and blast-radius tracing. |
| **Incident Matcher** | `incidents/matcher.py` | Deterministic correlation against curated post-mortem incident archetypes (`database.json`). |

---

## 📊 Live Demo Scenarios (1-Click Evaluation)

The dashboard includes 5 pre-built test scenarios representing classic real-world production outage patterns:

1. **Scenario 1: Destructive Database Migration**
   - *Change*: `ALTER TABLE users DROP COLUMN legacy_token;` in rolling deploy.
   - *Result*: `CRITICAL RISK` — Old application pods query missing column during container cutover; HTTP 500 errors spike.
   - *Rollout Recommendation*: Phased Expand/Contract rollout roadmap.
2. **Scenario 2: Reduced Redundancy**
   - *Change*: Kubernetes deployment manifest slashes `replicas: 3 → 1` and cuts CPU limit.
   - *Result*: `HIGH RISK` — Single replica eliminates zero-downtime rolling restart guarantees; HTTP 503 unavailability during container startup.
3. **Scenario 3: Major Dependency Upgrade**
   - *Change*: `stripe 10.2.0 → 12.1.0` in `requirements.txt`.
   - *Result*: `HIGH RISK` — Breaking runtime webhook parameter/signature discrepancies that pass unit test mocks.
4. **Scenario 4: Traffic Amplification & Missing Timeout**
   - *Change*: New HTTP endpoint orchestrates unindexed full-table DB query and synchronous external CRM call without timeout.
   - *Result*: `HIGH RISK` — Thread starvation and connection pool exhaustion under concurrent production traffic.
5. **Scenario 5: Combined High-Blast-Radius Release**
   - *Change*: Multi-vector release combining destructive DB migration, single replica scaling, major payment SDK upgrade, and missing timeouts.
   - *Result*: `CRITICAL RISK` — Multi-system cascading failure modes.

---

## 🧪 Automated Test Suite

Run the full automated test suite:

```bash
./.venv/bin/pytest -v
```

19 comprehensive tests verifying:
- File classification and regex parsers
- Destructive migration and expand/contract hazard detection
- Dependency semver upgrade comparators
- Infrastructure single-replica risk detectors
- Configuration connection pool shift and secret redactors
- Traffic composite hazard and unbounded query analyzers
- Service topology graph construction
- Historical incident pattern matching
- End-to-end FastAPI HTTP routes and HTML rendering

---

## 🛡️ Security & Privacy
- **Automatic Secret Redaction**: All API keys, passwords, database credentials, AWS keys, JWTs, and private keys are scrubbed before analysis.
- **No Arbitrary Code Execution**: The system never runs `git clone`, executes user code, or requires Docker-in-Docker.
- **Safe Outbound Calls**: External calls occur solely server-side to the official GitHub REST API and Groq completions API.
# deployment-analyser
