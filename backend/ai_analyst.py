"""Gemini narrative layer. Structured JSON in, structured JSON out. Never decides whether a path exists."""
import json
import os
import re
from emergentintegrations.llm.chat import LlmChat, UserMessage, TextDelta, StreamDone

MODEL = ("gemini", "gemini-3-flash-preview")

SYSTEM_PROMPT = """You are SENTRA's security analyst narrator. You receive a JSON document containing security findings and attack paths that were ALREADY VALIDATED by a deterministic correlation engine.

HARD RULES:
1. Reason ONLY over the provided evidence. Never invent findings, assets, CVEs, or attack paths that are not in the input.
2. Never decide whether an attack path exists. Only narrate the paths given, referencing them by their exact path id.
3. Never provide exploit instructions, payloads, or step-by-step attack technique. Describe attacker objectives at a high level only.
4. Write for a business executive first, an engineer second. Plain language, concrete consequences.
5. Every claim must cite finding ids (e.g. "ACME-02") or path ids (e.g. "PATH-1") from the input.
6. Output ONLY a single JSON object matching this schema, no markdown fences, no commentary:
{
  "summary": "2-3 sentence executive summary of the overall posture",
  "business_impact": "3-4 sentences on concrete business consequences (data, money, compliance, trust)",
  "attacker_objective": "1-2 sentences: what an attacker most likely wants here, high-level only",
  "priority": "one of: critical | high | medium | low",
  "path_narratives": [{"path_id": "PATH-1", "title": "short title", "narrative": "2-3 sentences telling the story of this chain, citing finding ids"}],
  "remediation": [{"finding_id": "ACME-02", "action": "one sentence", "reason": "one sentence why this first"}],
  "evidence_cited": ["ACME-01", "PATH-1"],
  "confidence": 0.0-1.0
}"""


def build_ai_input(env, findings, paths, score):
    return {
        "environment": {"id": env["id"], "name": env["name"], "sector": env["sector"], "synthetic": True},
        "score": {"overall": score["overall"], "grade": score["grade"], "categories": [{"label": c["label"], "score": c["score"]} for c in score["categories"]]},
        "findings": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"], "category": f["category"], "asset_id": f["asset_id"], "confidence": f["confidence"], "evidence": f["evidence"][:400], "tags": f["tags"]}
            for f in findings
        ],
        "attack_paths": [
            {"id": p["id"], "rank": p["rank"], "likelihood": p["likelihood"], "chain": p["node_ids"], "steps": p["steps"], "impact_asset_id": p["impact_asset_id"]}
            for p in paths
        ],
    }


def _extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def sanitize(result, findings, paths):
    """Guardrail: drop any reference the model invented."""
    fids = {f["id"] for f in findings}
    pids = {p["id"] for p in paths}
    result["path_narratives"] = [n for n in result.get("path_narratives", []) if n.get("path_id") in pids]
    result["remediation"] = [r for r in result.get("remediation", []) if r.get("finding_id") in fids]
    result["evidence_cited"] = [e for e in result.get("evidence_cited", []) if e in fids or e in pids]
    if result.get("priority") not in {"critical", "high", "medium", "low"}:
        result["priority"] = "high"
    try:
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.7))))
    except (TypeError, ValueError):
        result["confidence"] = 0.7
    for k in ("summary", "business_impact", "attacker_objective"):
        result[k] = str(result.get(k, "")).strip()
    return result


async def generate_analysis(session_id, ai_input, findings, paths):
    chat = LlmChat(api_key=os.environ["EMERGENT_LLM_KEY"], session_id=session_id, system_message=SYSTEM_PROMPT).with_model(*MODEL)
    text = ""
    async for ev in chat.stream_message(UserMessage(text=json.dumps(ai_input))):
        if isinstance(ev, TextDelta):
            text += ev.content
        elif isinstance(ev, StreamDone):
            break
    return sanitize(_extract_json(text), findings, paths), text
