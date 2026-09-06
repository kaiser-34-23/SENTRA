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
from incident import DEMO_INCIDENT  # noqa: E402
import ai_analyst  # noqa: E402

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
    environment_id: str
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
    environment_id: str
    authorized: bool


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def public_env(e):
    return {k: v for k, v in e.items() if k != "findings"} | {"finding_count": len(e["findings"]), "synthetic": True}


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
    return {"service": "SENTRA", "synthetic": True}


@api.get("/environments")
async def list_environments():
    return [public_env(e) for e in ENVIRONMENTS]


@api.get("/rules")
async def get_rules():
    return load_rules()


@api.post("/scans")
async def start_scan(req: StartScanRequest):
    env = get_environment(req.environment_id)
    if not env:
        raise HTTPException(404, "Unknown environment")
    if not req.authorized:
        raise HTTPException(400, "Authorization confirmation required")
    run = ScanRun(scan_id=str(uuid.uuid4()), environment_id=env["id"], status="queued", authorized=True, created_at=now_iso())
    await db.scan_runs.insert_one(run.to_mongo())
    return {"scan_id": run.scan_id, "environment_id": env["id"], "status": "queued"}


def run_engine(env):
    findings = env["findings"]
    edges = build_edges(findings, env["assets"])
    paths = build_attack_paths(findings, edges)
    score = compute_score(findings, paths)
    graph = build_graph(env, findings, edges, paths)
    return findings, edges, paths, score, graph


async def persist_results(scan_id, findings, paths, score, graph, log):
    await db.findings.delete_many({"scan_id": scan_id})
    await db.attack_paths.delete_many({"scan_id": scan_id})
    if findings:
        await db.findings.insert_many([ScanFinding(scan_id=scan_id, data=f).to_mongo() for f in findings])
    if paths:
        await db.attack_paths.insert_many([AttackPath(scan_id=scan_id, data=p).to_mongo() for p in paths])
    await db.scan_runs.update_one({"scan_id": scan_id}, {"$set": {"status": "complete", "completed_at": now_iso(), "score": score, "graph": graph, "log": log}})


def build_stages(env, findings, edges, paths, score):
    counts = score["severity_counts"]
    tls = [f for f in findings if f["category"] == "transport"]
    auth = [f for f in findings if f["category"] == "auth"]
    web = [f for f in findings if f["category"] == "web"]
    public_assets = [a for a in env["assets"] if a["exposure"] == "public"]
    return [
        ("init", "INIT", "info", f"SENTRA engine v0.9 · target={env['id']} · mode=SYNTHETIC (no real traffic)", 0.35),
        ("init", "TARGET", "info", f"Loaded topology: {len(env['assets'])} assets, {len(public_assets)} internet-facing · {env['infra']}", 0.45),
        ("tls", "TLS", "info", f"Negotiating TLS on {len(public_assets)} public endpoints · checking protocol floor & cipher suites", 0.55),
        ("tls", "TLS", "warn" if tls else "ok", f"{len(tls)} transport weakness(es) recorded" if tls else "Transport layer clean", 0.4),
        ("headers", "HEADERS", "info", "Inspecting security headers: CSP, HSTS, X-Frame-Options, cookie flags", 0.5),
        ("headers", "HEADERS", "warn" if web else "ok", f"{len(web)} web-layer weakness(es) · " + ", ".join(f["id"] for f in web), 0.4),
        ("endpoints", "ENUM", "info", f"Enumerating routes · {env['endpoint_count']} endpoints discovered across {len(env['assets'])} assets", 0.55),
        ("endpoints", "ENUM", "warn", f"{sum(1 for f in findings if f['category'] == 'exposure')} exposure finding(s) on public surfaces", 0.4),
        ("auth", "AUTH", "info", "Testing authentication controls · credentials, throttling, token validation", 0.55),
        ("auth", "AUTH", "crit" if any(f["severity"] == "critical" for f in auth) else "warn", f"{len(auth)} auth/access weakness(es) · " + ", ".join(f"{f['id']}[{f['severity']}]" for f in auth), 0.45),
        ("correlate", "CORRELATE", "info", f"Applying {len(load_rules()['rules'])} deterministic correlation rules to {len(findings)} findings", 0.55),
        ("correlate", "CORRELATE", "ok", f"{len(edges)} validated relationships · 0 inferred by AI", 0.4),
        ("graph", "GRAPH", "info", f"Building attack graph · {len(paths)} attack path(s) reach sensitive data", 0.55),
        ("graph", "GRAPH", "crit" if paths else "ok", f"Top path: {paths[0]['entry']} → … → {paths[0]['impact']} (likelihood {paths[0]['likelihood']:.2f})" if paths else "No multi-step paths", 0.45),
        ("score", "SCORE", "info", f"Security score {score['overall']}/100 ({score['grade']}) · {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low · {counts['info']} info", 0.4),
        ("ai", "AI", "info", "Handing validated graph to AI analyst for narrative only (no path inference)", 0.35),
        ("done", "COMPLETE", "ok", "Scan complete · results ready", 0.15),
    ]


@api.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    env = get_environment(run.environment_id)

    async def gen():
        findings, edges, paths, score, graph = run_engine(env)
        await db.scan_runs.update_one({"scan_id": scan_id}, {"$set": {"status": "running"}})
        stages = build_stages(env, findings, edges, paths, score)
        total = len(stages)
        log = []
        t0 = asyncio.get_event_loop().time()
        for i, (stage, tag, level, msg, delay) in enumerate(stages):
            await asyncio.sleep(delay)
            entry = {"type": "log", "stage": stage, "tag": tag, "level": level, "message": msg, "t": round(asyncio.get_event_loop().time() - t0, 2), "progress": round((i + 1) / total * 100)}
            log.append(entry)
            yield f"data: {json.dumps(entry)}\n\n"
        await persist_results(scan_id, findings, paths, score, graph, log)
        yield f"data: {json.dumps({'type': 'complete', 'scan_id': scan_id, 'score': score['overall']})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


@api.post("/scans/{scan_id}/complete")
async def complete_scan_sync(scan_id: str):
    """Non-streaming fallback: run the engine and persist immediately."""
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    env = get_environment(run.environment_id)
    findings, edges, paths, score, graph = run_engine(env)
    await persist_results(scan_id, findings, paths, score, graph, [])
    return {"scan_id": scan_id, "status": "complete"}


@api.get("/scans/{scan_id}/results")
async def get_results(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run:
        raise HTTPException(404, "Scan not found")
    if run.status != "complete":
        return {"scan_id": scan_id, "status": run.status}
    env = get_environment(run.environment_id)
    findings = [ScanFinding.from_mongo(d).data for d in await db.findings.find({"scan_id": scan_id}).to_list(200)]
    paths = [AttackPath.from_mongo(d).data for d in await db.attack_paths.find({"scan_id": scan_id}).to_list(50)]
    paths.sort(key=lambda p: p["rank"])
    ai = await db.ai_analyses.find_one({"scan_id": scan_id}, sort=[("created_at", -1)])
    remediation = sorted(
        [{"finding_id": f["id"], "title": f["title"], "severity": f["severity"], "asset_id": f["asset_id"], **f["remediation"], "on_path": any(f["id"] in p["node_ids"] for p in paths)} for f in findings],
        key=lambda r: (r["priority"], ["critical", "high", "medium", "low", "info"].index(r["severity"])),
    )
    return {
        "scan_id": scan_id,
        "status": "complete",
        "synthetic": True,
        "environment": public_env(env),
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


@api.post("/scans/{scan_id}/ai-analysis")
async def ai_analysis(scan_id: str):
    run = ScanRun.from_mongo(await db.scan_runs.find_one({"scan_id": scan_id}))
    if not run or run.status != "complete":
        raise HTTPException(404, "Scan results not available")
    env = get_environment(run.environment_id)
    findings = [ScanFinding.from_mongo(d).data for d in await db.findings.find({"scan_id": scan_id}).to_list(200)]
    paths = sorted([AttackPath.from_mongo(d).data for d in await db.attack_paths.find({"scan_id": scan_id}).to_list(50)], key=lambda p: p["rank"])
    ai_input = ai_analyst.build_ai_input(env, findings, paths, run.score)
    try:
        output, raw = await asyncio.wait_for(ai_analyst.generate_analysis(f"sentra-{scan_id}", ai_input, findings, paths), timeout=60)
    except Exception as e:  # noqa: BLE001
        logger.exception("AI analysis failed")
        raise HTTPException(502, f"AI analyst unavailable: {type(e).__name__}")
    doc = AIAnalysis(scan_id=scan_id, model=ai_analyst.MODEL[1], input=ai_input, output=output, raw=raw, created_at=now_iso())
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
