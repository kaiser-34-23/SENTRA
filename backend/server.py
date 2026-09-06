from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, BeforeValidator
from typing import Annotated, Optional
from datetime import datetime, timezone
from pathlib import Path
import os
import json
import asyncio
import logging
import uuid

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from environments import ENVIRONMENTS, get_environment  # noqa: E402
from engine.correlation import build_edges, build_attack_paths, build_graph, load_rules  # noqa: E402
from engine.scoring import compute_score  # noqa: E402
from engine.remediation import simulate_controls  # noqa: E402
from engine.mitre import annotate_findings  # noqa: E402
from incident import DEMO_INCIDENT  # noqa: E402
import ai_analyst  # noqa: E402
from real_scanner import ALLOWED_TARGET_TYPES, normalize_target, scan_target, validate_active_policy  # noqa: E402

client = AsyncIOMotorClient(os.environ['MONGO_URL'])
db = client[os.environ['DB_NAME']]
logger = logging.getLogger("sentra")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="SENTRA API")
api = APIRouter(prefix="/api")

PyObjectId = Annotated[str, BeforeValidator(str)]


class BaseDocument(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")

    model_config = {"populate_by_name": True}

    def to_mongo(self):
        d = self.model_dump(by_alias=True, exclude_none=True)
        d.pop("_id", None)
        return d

    @classmethod
    def from_mongo(cls, doc):
        return cls(**doc) if doc else None


class ScanRun(BaseDocument):
    scan_id: str
    environment_id: Optional[str] = None
    target: Optional[str] = None
    target_type: str = "web"
    scope: Optional[str] = None
    profile: str = "standard"
    goals: list[str] = []
    assessment_mode: str = "read_only"
    active_methods: list[str] = []
    active_paths: list[str] = []
    active_confirmed: bool = False
    environment: Optional[dict] = None
    status: str
    authorized: bool
    created_at: str
    completed_at: Optional[str] = None
    score: Optional[dict] = None
    graph: Optional[dict] = None
    log: list = []


class ScanFinding(BaseDocument):
    scan_id: str
    data: dict


class AttackPath(BaseDocument):
    scan_id: str
    data: dict


class AIAnalysis(BaseDocument):
    scan_id: str
    model: str
    input: dict
    output: dict
    raw: str
    created_at: str


class StartScanRequest(BaseModel):
    # environment_id remains optional for clients of the old demo API. New
    # assessments always submit a target supplied by the user.
    target: Optional[str] = None
    target_type: str = "web"
    scope: Optional[str] = None
    profile: str = "standard"
    goals: list[str] = []
    environment_id: Optional[str] = None
    authorized: bool
    assessment_mode: str = "read_only"
    active_methods: list[str] = []
    active_paths: list[str] = []
    active_confirmed: bool = False


class RemediationSimulationRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def public_env(e):
    findings = e.get("findings", [])
    # Legacy built-in environments predate the live-target path and have no
    # target field; keep their metadata explicitly marked as synthetic.
    is_synthetic = bool(e.get("synthetic", "target" not in e))
    return {k: v for k, v in e.items() if k != "findings"} | {"finding_count": len(findings), "synthetic": is_synthetic}


@app.on_event("startup")
async def seed():
    for env in ENVIRONMENTS:
        await db.synthetic_environments.update_one({"id": env["id"]}, {"$set": {**env, "synthetic": True}}, upsert=True)
    await db.scan_runs.create_index("scan_id", unique=True)
    await db.findings.create_index("scan_id")
    await db.attack_paths.create_index("scan_id")
    await db.ai_analyses.create_index("scan_id")


@api.get("/")
async def root():
    return {"service": "SENTRA", "mode": "authorized read-only or bounded active assessments"}


@api.get("/environments")
async def list_environments():
    return [public_env(e) for e in ENVIRONMENTS]


@api.get("/rules")
async def get_rules():
    return load_rules()


@api.post("/scans")
async def start_scan(req: StartScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Authorization confirmation required")
    if req.target is not None:
        try:
            target = normalize_target(req.target)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if req.target_type not in ALLOWED_TARGET_TYPES:
            raise HTTPException(422, f"target_type must be one of: {', '.join(sorted(ALLOWED_TARGET_TYPES))}")
        if req.profile not in {"safe", "standard", "deep"}:
            raise HTTPException(422, "profile must be one of: safe, standard, deep")
        if req.assessment_mode not in {"read_only", "active"}:
            raise HTTPException(422, "assessment_mode must be read_only or active")
        if req.assessment_mode == "active":
            try:
                validate_active_policy(target, req.active_methods, req.active_paths, req.active_confirmed)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
        allowed_goals = {"surface", "headers", "correlation", "impact", "remediation"}
        if any(goal not in allowed_goals for goal in req.goals):
            raise HTTPException(422, "goals contains an unsupported analysis goal")
        run = ScanRun(
            scan_id=str(uuid.uuid4()), target=target, target_type=req.target_type,
            scope=req.scope, profile=req.profile, goals=req.goals, assessment_mode=req.assessment_mode,
            active_methods=req.active_methods, active_paths=req.active_paths, active_confirmed=req.active_confirmed,
            status="queued",
            authorized=True, created_at=now_iso(), environment=None,
        )
    else:
        # Backwards-compatible route for the original synthetic API. The UI no
        # longer exposes this; keeping it avoids breaking existing integrations.
        env = get_environment(req.environment_id or "")
        if not env:
            raise HTTPException(404, "Target not found")
        run = ScanRun(scan_id=str(uuid.uuid4()), environment_id=env["id"], status="queued", authorized=True, created_at=now_iso(), environment=env)
    await db.scan_runs.insert_one(run.to_mongo())
    return {"scan_id": run.scan_id, "target": run.target, "environment_id": run.environment_id, "status": "queued"}


def run_engine(env):
    findings = annotate_findings(env["findings"])
    edges = build_edges(findings, env["assets"])
    paths = build_attack_paths(findings, edges)
    score = compute_score(findings, paths)
    graph = build_graph(env, findings, edges, paths)
    return findings, edges, paths, score, graph


def remediation_for(findings, paths, fixed_ids=None):
    fixed_ids = fixed_ids or set()
    path_ids = {node_id for path in paths for node_id in path["node_ids"]}
    return sorted(
        [{
            "finding_id": f["id"], "title": f["title"], "severity": f["severity"],
            "asset_id": f["asset_id"], **f["remediation"], "on_path": f["id"] in path_ids,
            "mitre": f.get("mitre", []), "attack_role": f.get("attack_role", "Control weakness"),
            "fixed": f["id"] in fixed_ids,
        } for f in findings],
        key=lambda r: (r["fixed"], r["priority"], ["critical", "high", "medium", "low", "info"].index(r["severity"])),
    )


def environment_for_run(run: ScanRun):
    return run.environment or get_environment(run.environment_id or "")


async def persist_results(scan_id, env, findings, paths, score, graph, log):
    await db.findings.delete_many({"scan_id": scan_id})
    await db.attack_paths.delete_many({"scan_id": scan_id})
    if findings:
        await db.findings.insert_many([ScanFinding(scan_id=scan_id, data=f).to_mongo() for f in findings])
    if paths:
        await db.attack_paths.insert_many([AttackPath(scan_id=scan_id, data=p).to_mongo() for p in paths])
    await db.scan_runs.update_one({"scan_id": scan_id}, {"$set": {"status": "complete", "completed_at": now_iso(), "score": score, "graph": graph, "log": log, "environment": env}})


def build_stages(env, findings, edges, paths, score, live=False):
    counts = score["severity_counts"]
    tls = [f for f in findings if f["category"] == "transport"]
    auth = [f for f in findings if f["category"] == "auth"]
    web = [f for f in findings if f["category"] == "web"]
    public_assets = [a for a in env["assets"] if a["exposure"] == "public"]
    transport_detail = "headers and redirect policy" if live else "protocol floor & cipher suites"
    exposure_count = sum(1 for f in findings if f["category"] == "exposure")
    auth_level = "crit" if any(f["severity"] == "critical" for f in auth) else "warn" if auth else "ok"
    auth_message = f"{len(auth)} auth/access weakness(es) · " + ", ".join(f"{f['id']}[{f['severity']}]" for f in auth) if auth else "No authentication weakness observed in the supplied response"
    assessment_mode = env.get("observed", {}).get("assessment_mode", "read_only")
    run_mode = "BOUNDED ACTIVE" if assessment_mode == "active" else "AUTHORIZED READ-ONLY" if live else "SYNTHETIC COMPATIBILITY"
    return [
        ("init", "INIT", "info", f"SENTRA engine v1.0 · target={env.get('target', env['id'])} · mode={run_mode}", 0.35),
        ("init", "TARGET", "info", f"Loaded target: {len(env['assets'])} asset(s), {len(public_assets)} internet-facing · {env['infra']}", 0.45),
        ("tls", "TLS", "info", f"{'Inspecting observed transport response' if live else 'Negotiating TLS'} on {len(public_assets)} public endpoint(s) · {transport_detail}", 0.55),
        ("tls", "TLS", "warn" if tls else "ok", f"{len(tls)} transport weakness(es) recorded" if tls else "Transport layer clean", 0.4),
        ("headers", "HEADERS", "info", "Inspecting observed security headers: CSP, HSTS, X-Frame-Options, cookie flags", 0.5),
        ("headers", "HEADERS", "warn" if web else "ok", f"{len(web)} web-layer weakness(es) · " + ", ".join(f["id"] for f in web), 0.4),
        ("endpoints", "ENUM", "info", f"Checking supplied target and configured scope · {env['endpoint_count']} endpoint(s) observed across {len(env['assets'])} asset(s)", 0.55),
        ("endpoints", "ENUM", "warn" if exposure_count else "ok", f"{exposure_count} exposure finding(s) on public surfaces" if exposure_count else "No exposure finding observed", 0.4),
        ("auth", "AUTH", "info", "Reviewing authentication-related response controls (read-only; no credentials submitted)", 0.55),
        ("auth", "AUTH", auth_level, auth_message, 0.45),
        ("correlate", "CORRELATE", "info", f"Applying {len(load_rules()['rules'])} deterministic correlation rules to {len(findings)} findings", 0.55),
        ("correlate", "CORRELATE", "ok", f"{len(edges)} validated relationships · 0 inferred by AI", 0.4),
        ("graph", "GRAPH", "info", f"Building attack graph · {len(paths)} attack path(s) reach sensitive data", 0.55),
        ("graph", "GRAPH", "crit" if paths else "ok", f"Top path: {paths[0]['entry']} → … → {paths[0]['impact']} (likelihood {paths[0]['likelihood']:.2f})" if paths else "No multi-step paths", 0.45),
        ("score", "SCORE", "info", f"Security score {score['overall']}/100 ({score['grade']}) · {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low · {counts['info']} info", 0.4),
        ("ai", "AI", "info", "Handing observed evidence to AI analyst for narrative only (no path inference)", 0.35),
        ("done", "COMPLETE", "ok", "Scan complete · results ready", 0.15),
    ]


@api.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    env = environment_for_run(run)
    if not env and not run.target:
        raise HTTPException(404, "Target not found")

    async def gen():
        current_env = env
        if run.target:
            live = await scan_target(
                run.target, run.target_type, run.scope,
                assessment_mode=run.assessment_mode, active_methods=run.active_methods,
                active_paths=run.active_paths, active_confirmed=run.active_confirmed,
            )
            current_env = live.environment
            current_env["profile"] = run.profile
            current_env["goals"] = run.goals
            findings = annotate_findings(live.findings)
            edges = build_edges(findings, current_env["assets"])
            paths = build_attack_paths(findings, edges)
            score = compute_score(findings, paths)
            graph = build_graph(current_env, findings, edges, paths)
        else:
            findings, edges, paths, score, graph = run_engine(current_env)
        await db.scan_runs.update_one({"scan_id": scan_id}, {"$set": {"status": "running"}})
        stages = build_stages(current_env, findings, edges, paths, score, live=bool(run.target))
        total = len(stages)
        log = []
        t0 = asyncio.get_event_loop().time()
        for i, (stage, tag, level, msg, delay) in enumerate(stages):
            await asyncio.sleep(delay)
            entry = {"type": "log", "stage": stage, "tag": tag, "level": level, "message": msg, "t": round(asyncio.get_event_loop().time() - t0, 2), "progress": round((i + 1) / total * 100)}
            log.append(entry)
            yield f"data: {json.dumps(entry)}\n\n"
        await persist_results(scan_id, current_env, findings, paths, score, graph, log)
        yield f"data: {json.dumps({'type': 'complete', 'scan_id': scan_id, 'score': score['overall']})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@api.post("/scans/{scan_id}/complete")
async def complete_scan_sync(scan_id: str):
    """Non-streaming fallback: run the engine and persist immediately."""
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    env = environment_for_run(run)
    if run.target:
        live = await scan_target(
            run.target, run.target_type, run.scope,
            assessment_mode=run.assessment_mode, active_methods=run.active_methods,
            active_paths=run.active_paths, active_confirmed=run.active_confirmed,
        )
        env = live.environment
        env["profile"] = run.profile
        env["goals"] = run.goals
        findings = annotate_findings(live.findings)
        edges = build_edges(findings, env["assets"])
        paths = build_attack_paths(findings, edges)
        score = compute_score(findings, paths)
        graph = build_graph(env, findings, edges, paths)
    else:
        findings, edges, paths, score, graph = run_engine(env)
    await persist_results(scan_id, env, findings, paths, score, graph, [])
    return {"scan_id": scan_id, "status": "complete"}


@api.get("/scans/{scan_id}/results")
async def get_results(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    if run.status != "complete":
        return {"scan_id": scan_id, "status": run.status}
    env = environment_for_run(run)
    findings = annotate_findings([ScanFinding.from_mongo(d).data for d in await db.findings.find({"scan_id": scan_id}).to_list(200)])
    paths = [AttackPath.from_mongo(d).data for d in await db.attack_paths.find({"scan_id": scan_id}).to_list(50)]
    paths.sort(key=lambda p: p["rank"])
    ai = await db.ai_analyses.find_one({"scan_id": scan_id}, sort=[("created_at", -1)])
    remediation = remediation_for(findings, paths)
    return {
        "scan_id": scan_id,
        "status": "complete",
        "assessment_mode": run.assessment_mode,
        "synthetic": bool(env.get("synthetic", "target" not in env)),
        "environment": {**public_env(env), "finding_count": len(findings)},
        "score": run.score,
        "findings": findings,
        "attack_paths": paths,
        "graph": run.graph,
        "remediation": remediation,
        "rules": load_rules()["rules"],
        "ai_analysis": AIAnalysis.from_mongo(ai).output if ai else None,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
    }


@api.post("/scans/{scan_id}/simulate-remediation")
async def simulate_remediation(scan_id: str, req: RemediationSimulationRequest):
    """Re-run deterministic correlation with selected findings removed.

    This is intentionally a non-persistent what-if calculation. It gives a
    reviewer a truthful answer to "what changes if we fix this first?" while
    keeping the original observed assessment intact.
    """
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run or run.status != "complete":
        raise HTTPException(404, "Scan results not available")
    env = environment_for_run(run)
    all_findings = annotate_findings([ScanFinding.from_mongo(d).data for d in await db.findings.find({"scan_id": scan_id}).to_list(200)])
    original_paths = sorted(
        [AttackPath.from_mongo(d).data for d in await db.attack_paths.find({"scan_id": scan_id}).to_list(50)],
        key=lambda path: path["rank"],
    )
    try:
        simulation = simulate_controls(
            env,
            all_findings,
            req.finding_ids,
            baseline_paths=original_paths,
            baseline_score=run.score,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    fixed_ids = set(simulation["fixed_finding_ids"])
    return {
        "scan_id": scan_id,
        "status": "simulated",
        "synthetic": bool(env.get("synthetic", "target" not in env)),
        "environment": {**public_env(env), "finding_count": len(simulation["findings"])},
        **simulation,
        "remediation": remediation_for(all_findings, simulation["attack_paths"], fixed_ids),
        "rules": load_rules()["rules"],
    }


@api.post("/scans/{scan_id}/ai-analysis")
async def ai_analysis(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run or run.status != "complete":
        raise HTTPException(404, "Scan results not available")
    env = environment_for_run(run)
    findings = annotate_findings([ScanFinding.from_mongo(d).data for d in await db.findings.find({"scan_id": scan_id}).to_list(200)])
    paths = sorted([AttackPath.from_mongo(d).data for d in await db.attack_paths.find({"scan_id": scan_id}).to_list(50)], key=lambda p: p["rank"])
    ai_input = ai_analyst.build_ai_input(env, findings, paths, run.score)
    try:
        output, raw = await asyncio.wait_for(ai_analyst.generate_analysis(f"sentra-{scan_id}", ai_input, findings, paths), timeout=60)
    except Exception as e:  # noqa: BLE001
        logger.exception("AI analysis failed")
        raise HTTPException(502, f"AI analyst unavailable: {type(e).__name__}")
    doc = AIAnalysis(scan_id=scan_id, model=ai_analyst.ACTIVE_MODEL, input=ai_input, output=output, raw=raw, created_at=now_iso())
    await db.ai_analyses.insert_one(doc.to_mongo())
    return {"scan_id": scan_id, "model": doc.model, "analysis": output, "input_summary": {"findings": len(findings), "paths": len(paths)}}


@api.get("/incident/demo")
async def demo_incident():
    env = get_environment(DEMO_INCIDENT["environment_id"])
    findings, edges, paths, score, graph = run_engine(env)
    by_id = {f["id"]: f for f in findings}
    return {**DEMO_INCIDENT, "environment": public_env(env), "findings": by_id, "score": score, "graph": graph, "attack_paths": paths}


app.include_router(api)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
