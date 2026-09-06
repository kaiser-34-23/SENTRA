"""Gemini narrative layer. Structured JSON in, structured JSON out. Never decides whether a path exists."""
import json
import os
import re
try:
    from emergentintegrations.llm.chat import LlmChat, UserMessage, TextDelta, StreamDone
except ImportError:  # Optional in local-only deployments; deterministic scan still works.
    LlmChat = UserMessage = TextDelta = StreamDone = None

MODEL = ("gemini", "gemini-3-flash-preview")
ACTIVE_MODEL = MODEL[1] if LlmChat is not None else "deterministic-evidence-narrator"

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
        "environment": {
            "id": env["id"],
            "name": env["name"],
            "sector": env["sector"],
            "target": env.get("target"),
            "synthetic": bool(env.get("synthetic", "target" not in env)),
        },
        "score": {"overall": score["overall"], "grade": score["grade"], "categories": [{"label": c["label"], "score": c["score"]} for c in score["categories"]]},
        "findings": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"], "category": f["category"], "asset_id": f["asset_id"], "confidence": f["confidence"], "evidence": f["evidence"][:400], "tags": f["tags"], "attack_role": f.get("attack_role"), "mitre": f.get("mitre", [])}
            for f in findings
        ],
        "attack_paths": [
            {"id": p["id"], "rank": p["rank"], "likelihood": p["likelihood"], "chain": p["node_ids"], "steps": p["steps"], "impact_asset_id": p["impact_asset_id"], "techniques": p.get("techniques", []), "roles": p.get("roles", [])}
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
    if LlmChat is None:
        # Keep the product useful in local/offline deployments. This fallback
        # is deliberately templated from observed evidence; it never pretends
        # that an LLM was called or invents a path.
        severity_order = ["critical", "high", "medium", "low", "info"]
        priority = min((f["severity"] for f in findings), key=severity_order.index, default="low")
        top = paths[0] if paths else None
        chain_ids = top["node_ids"] if top else []
        chain_text = " → ".join(chain_ids) if chain_ids else "no multi-step chain"
        result = {
            "summary": f"SENTRA observed {len(findings)} finding(s) and validated {len(paths)} attack path(s) from the supplied evidence. The deterministic engine places the highest-priority work on breaking the most exposed chain.",
            "business_impact": f"A validated chain can turn an externally reachable weakness into access to a sensitive asset. The current model contains {len(paths)} path(s) reaching sensitive data; impact depends on the target's real data and identity controls. Fixing a link removes that relationship from the model and should be verified with a follow-up assessment.",
            "attacker_objective": f"The modeled objective is to move from the observed entry point to the terminal asset via {chain_text}.",
            "priority": priority,
            "path_narratives": [
                {"path_id": p["id"], "title": f"{p['entry']} to {p['impact']}", "narrative": f"This validated chain connects {', '.join(p['node_ids'])}. It ends at {p['impact']} and has a modeled likelihood of {p['likelihood']:.0%}."}
                for p in paths
            ],
            "remediation": [
                {"finding_id": f["id"], "action": f["recommended_action"], "reason": "This is the highest-priority observed control weakness in the current model." if i == 0 else "Fixing it reduces the remaining finding or path risk."}
                for i, f in enumerate(sorted(findings, key=lambda f: (severity_order.index(f["severity"]), f["id"])))
            ],
            "evidence_cited": [f["id"] for f in findings[:8]] + [p["id"] for p in paths[:4]],
            "confidence": min((float(f.get("confidence", 0.7)) for f in findings), default=0.7),
            "mode": "deterministic fallback",
        }
        return sanitize(result, findings, paths), json.dumps(result)
    chat = LlmChat(api_key=os.environ["EMERGENT_LLM_KEY"], session_id=session_id, system_message=SYSTEM_PROMPT).with_model(*MODEL)
    text = ""
    async for ev in chat.stream_message(UserMessage(text=json.dumps(ai_input))):
        if isinstance(ev, TextDelta):
            text += ev.content
        elif isinstance(ev, StreamDone):
            break
    return sanitize(_extract_json(text), findings, paths), text
