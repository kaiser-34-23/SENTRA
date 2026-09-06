# SENTRA

SENTRA is an authorized security assessment workspace built around one question: **show me the attack, not an alert list.** It turns observed HTTP controls into evidence-backed findings, correlates them into attack paths, and shows which fixes break those paths.

Read-only checks are the default. Bounded active canaries are available only for explicitly allowlisted, disposable staging targets.

## Features

- Live URL, hostname, and IP target input with authorization confirmation, URL normalization, and request timeouts
- A bounded read-only scan that inspects one response without downloading its body or crawling the target
- Checks for HTTPS/HSTS, CSP, MIME sniffing protection, unsafe credentialed CORS, technology banners, and `Secure`, `HttpOnly`, and `SameSite` cookie flags
- Deterministic correlation rules, ranked attack paths, a 0–100 security score, severity counts, and category scores
- Interactive attack graph with path filtering and node details for evidence, confidence, attacker role, impact, and recommended action
- MITRE ATT&CK annotations on findings and attack paths
- Prioritized remediation guidance with code snippets where available
- Non-persistent what-if remediation that recalculates the graph and score, identifies removed edges, and shows which paths a fix breaks
- Evidence-constrained AI summaries with a deterministic local fallback; AI explains validated results but cannot create findings or paths
- Server-sent event (SSE) progress updates and MongoDB persistence for scan results
- Opt-in `POST`/`PUT` staging canaries with strict host/path allowlisting, an endpoint handshake, rate limiting, same-origin cleanup, and an eight-request maximum

## How scanning works

For a normal assessment, SENTRA makes one bounded `GET` request to the supplied HTTP(S) URL and evaluates response metadata. It does not crawl, guess credentials, submit exploits, or consume the response body. The deterministic engine then applies the rules in `backend/engine/rules.json`, calculates the score, builds the graph, and persists the result.

Target type, profile, scope, and analysis goals are stored with the assessment. The current live scanner evaluates the single supplied HTTP(S) URL; it is not a network port scanner or cloud-account scanner.

## Run locally

### Prerequisites

- Python 3.10+
- Node.js and npm (or Yarn 1)
- MongoDB

### Backend

Create a virtual environment, install the dependencies, and start the API:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
MONGO_URL=mongodb://127.0.0.1:27017 DB_NAME=sentra CORS_ORIGINS='*' uvicorn server:app --reload --port 8001
```

`EMERGENT_LLM_KEY` is optional. Without the AI integration, SENTRA uses its evidence-based deterministic narrator and the assessment engine remains fully functional.

### Frontend

In another terminal, install and start the React app:

```bash
cd frontend
npm install
npm start
```

Open `http://localhost:3000`. The frontend proxies `/api` to the backend. To use a separately hosted API, set `REACT_APP_BACKEND_URL` before starting or building the frontend.

## Active staging checks

Active mode can change data and is intended only for disposable staging systems. Explicitly allow each staging hostname in the API environment:

```bash
SENTRA_ACTIVE_TARGET_ALLOWLIST=staging.example.internal,localhost
```

The selected endpoint must answer `OPTIONS` with `X-SENTRA-Active-Contract: true` and an `X-SENTRA-Cleanup-Path` header. Only then does SENTRA send the approved `POST` and/or `PUT` canary, followed by a same-origin `DELETE` cleanup request. Paths must be explicit and cannot contain wildcards, queries, or `..`. If the contract is absent, no write is attempted.

## Tests

Run the deterministic engine tests from the repository root:

```bash
pytest backend/tests/test_engine.py
```

The API integration suite uses `REACT_APP_BACKEND_URL` when set and otherwise targets the configured hosted preview:

```bash
REACT_APP_BACKEND_URL=http://127.0.0.1:8001 pytest backend/tests/test_api.py
```

## Responsible use

Only assess systems you own or have explicit permission to test. Review active-canary audit results and verify cleanup before proceeding with further testing.

## License

SENTRA is available under the [MIT License](LICENSE).
