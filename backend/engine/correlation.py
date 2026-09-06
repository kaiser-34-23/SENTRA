"""Deterministic correlation engine: findings + topology -> graph edges + attack paths. No AI here."""
import json
from pathlib import Path

RULES_PATH = Path(__file__).parent / "rules.json"
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3, "info": 0.1}


def load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)


def _in_scope(rule, fa, fb, assets):
    if fa["id"] == fb["id"]:
        return False
    if fa["asset_id"] == fb["asset_id"]:
        return True
    if rule["scope"] == "same_asset":
        return False
    return fb["asset_id"] in assets[fa["asset_id"]]["connects_to"]


def build_edges(findings, assets_list, rules=None):
    rules = rules or load_rules()
    assets = {a["id"]: a for a in assets_list}
    edges, seen = [], set()
    for rule in rules["rules"]:
        for fa in findings:
            if rule["source_tag"] not in fa["tags"]:
                continue
            for fb in findings:
                if rule["target_tag"] not in fb["tags"] or not _in_scope(rule, fa, fb, assets):
                    continue
                key = (fa["id"], fb["id"])
                if key in seen:
                    continue
                seen.add(key)
                edges.append({
                    "id": f"{fa['id']}->{fb['id']}",
                    "source": fa["id"],
                    "target": fb["id"],
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "relation": rule["relation"],
                    "explanation": rule["explanation"],
                })
    return edges


def build_attack_paths(findings, edges, rules=None, max_paths=8):
    rules = rules or load_rules()
    impact_tags = set(rules["impact_tags"])
    by_id = {f["id"]: f for f in findings}
    out = {}
    for e in edges:
        out.setdefault(e["source"], []).append(e)
    has_in = {e["target"] for e in edges}
    entries = [f["id"] for f in findings if f["id"] in out and f["id"] not in has_in]

    paths = []

    def dfs_start(entry):
        for e in out.get(entry, []):
            chain = [e]
            visited = {entry, e["target"]}
            if impact_tags & set(by_id[e["target"]]["tags"]) and not out.get(e["target"]):
                paths.append(list(chain))
            else:
                _walk(e["target"], visited, chain)

    def _walk(node, visited, chain):
        nxt = [e for e in out.get(node, []) if e["target"] not in visited]
        if not nxt:
            if impact_tags & set(by_id[node]["tags"]):
                paths.append(list(chain))
            return
        if impact_tags & set(by_id[node]["tags"]):
            paths.append(list(chain))
        for e in nxt:
            chain.append(e)
            visited.add(e["target"])
            _walk(e["target"], visited, chain)
            visited.discard(e["target"])
            chain.pop()

    for entry in sorted(entries):
        dfs_start(entry)

    # dedupe (drop strict prefixes of longer chains) and score
    keyed = {tuple([c[0]["source"]] + [e["target"] for e in c]): c for c in paths}
    keys = list(keyed)
    result = []
    for key in keys:
        if any(other != key and other[:len(key)] == key for other in keys):
            continue
        chain = keyed[key]
        node_ids = list(key)
        sev = max(SEVERITY_WEIGHT[by_id[n]["severity"]] for n in node_ids)
        conf = min(by_id[n]["confidence"] for n in node_ids)
        likelihood = round(sev * conf * (1 - 0.05 * (len(chain) - 1)), 2)
        target = by_id[node_ids[-1]]
        result.append({
            "id": f"PATH-{len(result) + 1}",
            "node_ids": node_ids,
            "edge_ids": [e["id"] for e in chain],
            "steps": [{"from": e["source"], "to": e["target"], "relation": e["relation"], "rule_id": e["rule_id"]} for e in chain],
            "entry": by_id[node_ids[0]]["title"],
            "impact": target["title"],
            "impact_asset_id": target["asset_id"],
            "hops": len(chain),
            "likelihood": likelihood,
            "max_severity": max((by_id[n]["severity"] for n in node_ids), key=lambda s: SEVERITY_WEIGHT[s]),
        })
    result.sort(key=lambda p: (-p["likelihood"], -p["hops"], p["node_ids"]))
    result = result[:max_paths]
    for i, p in enumerate(result):
        p["id"] = f"PATH-{i + 1}"
        p["rank"] = i + 1
    return result


def build_graph(env, findings, edges, paths):
    """Graph nodes = attacker + findings + crown-jewel assets. Layered by longest path depth."""
    by_id = {f["id"]: f for f in findings}
    incoming = {f["id"]: [] for f in findings}
    for e in edges:
        incoming[e["target"]].append(e["source"])
    depth = {}

    def d(n, stack=()):
        if n in depth:
            return depth[n]
        if n in stack:
            return 0
        v = 0 if not incoming[n] else 1 + max(d(p, stack + (n,)) for p in incoming[n])
        depth[n] = v
        return v

    for f in findings:
        d(f["id"])
    path_nodes = {n for p in paths for n in p["node_ids"]}
    entry_ids = sorted({p["node_ids"][0] for p in paths})
    impact_assets = sorted({p["impact_asset_id"] for p in paths})
    max_depth = max(depth.values()) if depth else 0

    nodes = [{"id": "attacker", "type": "attacker", "label": "External Attacker", "layer": 0}]
    for f in sorted(findings, key=lambda x: (depth[x["id"]], x["id"])):
        nodes.append({
            "id": f["id"], "type": "finding", "label": f["title"], "severity": f["severity"],
            "asset_id": f["asset_id"], "layer": depth[f["id"]] + 1, "on_path": f["id"] in path_nodes,
            "is_entry": f["id"] in entry_ids,
        })
    assets = {a["id"]: a for a in env["assets"]}
    for aid in impact_assets:
        nodes.append({"id": f"asset:{aid}", "type": "asset", "label": assets[aid]["name"], "layer": max_depth + 2, "asset_id": aid})

    graph_edges = [{**e, "kind": "correlation", "on_path": any(e["id"] in p["edge_ids"] for p in paths)} for e in edges]
    for eid in entry_ids:
        graph_edges.append({"id": f"attacker->{eid}", "source": "attacker", "target": eid, "kind": "entry", "relation": "targets", "explanation": "Internet-facing weakness reachable by an anonymous attacker.", "on_path": True})
    for p in paths:
        last = p["node_ids"][-1]
        eid = f"{last}->asset:{p['impact_asset_id']}"
        if not any(g["id"] == eid for g in graph_edges):
            graph_edges.append({"id": eid, "source": last, "target": f"asset:{p['impact_asset_id']}", "kind": "impact", "relation": "compromises", "explanation": "Final step reaches the asset holding sensitive data.", "on_path": True})
    return {"nodes": nodes, "edges": graph_edges}
