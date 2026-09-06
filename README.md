# SENTRA

SENTRA is an authorized security assessment workspace built around one question: **show me the attack, not an alert list.** Read-only checks are the default; bounded active canaries are available only for explicitly allowlisted staging targets.

Enter a real URL in the assessment form, confirm authorization, and SENTRA will inspect the target's reachable HTTP response. The result is a deterministic attack graph with evidence, confidence, business impact, and a prioritized remediation queue.

## What is implemented

- Real target input with URL normalization and bounded, read-only requests
- Deterministic correlation rules that turn independent observations into validated attack paths
- Interactive graph nodes: evidence, why it matters, attacker role, what the weakness enables, and confidence
- MITRE ATT&CK context on findings and attack paths
- What-if remediation: simulate a fix, recalculate the score, and see broken paths disappear without changing the original assessment
- Optional AI narrative layer that only explains validated evidence and never creates paths

## Run locally

Start MongoDB, then run the API and frontend:

```bash
cd backend
MONGO_URL=mongodb://127.0.0.1:27017 DB_NAME=sentra CORS_ORIGINS='*' uvicorn server:app --reload --port 8001
```

In another terminal:

```bash
cd frontend
npm install
npm start
```

Open `http://localhost:3000`. The frontend proxies `/api` to the backend, so one browser origin is enough.

Only assess targets you own or have explicit permission to test.

## Active staging checks

Read-only mode is the default. To enable bounded active canaries, explicitly
allow staging hosts in the API environment:

```bash
SENTRA_ACTIVE_TARGET_ALLOWLIST=staging.example.internal,localhost
```

The staging endpoint must answer `OPTIONS` with
`X-SENTRA-Active-Contract: true` and an `X-SENTRA-Cleanup-Path` header. SENTRA
then sends only the selected `POST`/`PUT` canary requests, rate-limits them,
and issues same-origin cleanup requests. If the contract is absent, no write
is attempted.
