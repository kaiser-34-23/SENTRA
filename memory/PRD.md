# SENTRA — Autonomous Security Intelligence (MVP)

## Original problem statement
Demo-ready web dashboard that turns synthetic security findings into a visual attack story, an AI-explained business impact, and a prioritized fix list. Positioned as an "AI security engineer", not a scanner. Targets Builder Fest judges (30-second wow) and security engineers (enough evidence to trust it).

## User choices
- Accent: electric cyan (#00F0FF), dark SOC/terminal aesthetic
- AI: Gemini 3 Flash (`gemini-3-flash-preview`) via Emergent LLM key
- Wordmark: typography only (SENTRA + lucide ShieldAlert)
- Scan duration: ~7 seconds

## Architecture
- **Frontend**: React 19 (JS/JSX, CRA + craco), Tailwind, shadcn/ui, Recharts (gauge/bars), @xyflow/react 12 (attack graph), EventSource SSE client. Routes: `/`, `/scan/:id`, `/results/:id`, `/incident`.
- **Backend**: FastAPI. `environments.py` (3 synthetic envs, assets + topology + findings), `engine/rules.json` (16 correlation rules), `engine/correlation.py` (edges, DFS attack paths, layered graph), `engine/scoring.py` (deterministic exp-decay score), `ai_analyst.py` (Gemini narrative, JSON in/out, sanitize guardrail drops invented ids), `incident.py` (preloaded incident).
- **Endpoints**: `GET /api/environments`, `POST /api/scans`, `GET /api/scans/{id}/stream` (SSE), `POST /api/scans/{id}/complete`, `GET /api/scans/{id}/results`, `POST /api/scans/{id}/ai-analysis`, `GET /api/incident/demo`, `GET /api/rules`.
- **MongoDB**: `synthetic_environments`, `scan_runs`, `findings`, `attack_paths`, `ai_analyses`.
- **Tests**: `backend/tests/test_engine.py` (engine unit tests), `backend/tests/test_api.py` (API tests, added by testing agent).

## Hard rules baked in
- LLM never determines path existence; only narrates ranked paths from the engine. Unknown finding/path ids in AI output are dropped.
- Every AI panel separates "Observed evidence · deterministic" from "AI interpretation".
- Score is deterministic from severity weights + path penalty.
- SYNTHETIC badge in top bar, on every target card, and in incident mode.

## Implemented (2026-06)
- Landing with 3 synthetic targets + authorization checkbox + launch
- SSE live scan (~7s, 17 staged log lines, stage indicators, progress bar) → auto-transition to results
- Results: score gauge + 5 category bars, AI analyst (compact + full tab), React Flow attack graph with animated edge draw-in, path highlighting, node side panel (evidence, relationships w/ rule explanations, chains), findings grouped by severity with filters + "Locate in graph", Remediation Center ordered P0→P3 with copyable snippets
- Demo Incident Mode: 5-step auto-advancing replay (Detect → Investigate → Correlate → Explain → Recommend)
- Testing agent iteration 1: backend 100%, frontend 100%

## Implemented (2026-09)
- Interactive remediation loop: apply or undo simulated controls from the graph, remediation center, or what-if panel
- Deterministic graph, path, score, and risk recalculation with an explicit before/after security-state explanation
- Simulation entry boundaries remain pinned to the original assessment so downstream internal findings cannot become artificial internet entry points

## Backlog
- P1: Stream AI narrative token-by-token into the panel
- P1: Per-finding AI explanation on demand in the node panel
- P2: Scan history list; report export (PDF/markdown); environment switcher in top bar
- P2: Real domain scanning + auth + domain ownership verification (explicitly out of MVP scope)
- P3: Integrations (GitHub/SIEM/Slack) as clean interfaces

## Notes
- Frontend is JS/JSX (template default) rather than TypeScript as in the spec; functionally identical.
- No auth in MVP; `memory/test_credentials.md` intentionally has no accounts.
