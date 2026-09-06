import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environments import ENVIRONMENTS, get_environment  # noqa: E402
from engine.correlation import build_edges, build_attack_paths, build_graph, load_rules  # noqa: E402
from engine.scoring import compute_score  # noqa: E402


def _run(env_id):
    env = get_environment(env_id)
    edges = build_edges(env["findings"], env["assets"])
    paths = build_attack_paths(env["findings"], edges)
    return env, edges, paths


def test_rules_load():
    rules = load_rules()
    assert len(rules["rules"]) >= 10
    assert "pii_store" in rules["impact_tags"]


def test_no_self_edges_and_deterministic():
    for env in ENVIRONMENTS:
        e1 = build_edges(env["findings"], env["assets"])
        e2 = build_edges(env["findings"], env["assets"])
        assert e1 == e2
        assert all(e["source"] != e["target"] for e in e1)
        assert len({(e["source"], e["target"]) for e in e1}) == len(e1)


def test_acme_admin_chain():
    env, edges, paths = _run("acme-retail")
    ids = {(e["source"], e["target"]) for e in edges}
    assert ("ACME-01", "ACME-02") in ids
    assert ("ACME-02", "ACME-08") in ids
    chains = [p["node_ids"] for p in paths]
    assert ["ACME-01", "ACME-02", "ACME-08"] in chains


def test_fincorp_deep_chain():
    env, edges, paths = _run("fincorp-bank")
    chains = [p["node_ids"] for p in paths]
    assert ["FIN-08", "FIN-02", "FIN-03", "FIN-05", "FIN-09"] in chains


def test_paths_end_at_impact():
    rules = load_rules()
    for env in ENVIRONMENTS:
        _, _, paths = _run(env["id"])
        by_id = {f["id"]: f for f in env["findings"]}
        assert paths, env["id"]
        for p in paths:
            assert set(rules["impact_tags"]) & set(by_id[p["node_ids"][-1]]["tags"])
            assert 0 < p["likelihood"] <= 1


def test_score_bounds_and_monotonic():
    env, edges, paths = _run("acme-retail")
    s = compute_score(env["findings"], paths)
    assert 0 <= s["overall"] <= 100
    assert len(s["categories"]) == 5
    fewer = compute_score(env["findings"][:3], [])
    assert fewer["overall"] > s["overall"]
    assert compute_score([], [])["overall"] == 100


def test_graph_shape():
    env, edges, paths = _run("healthops")
    g = build_graph(env, env["findings"], edges, paths)
    node_ids = {n["id"] for n in g["nodes"]}
    assert "attacker" in node_ids
    assert any(n["type"] == "asset" for n in g["nodes"])
    for e in g["edges"]:
        assert e["source"] in node_ids and e["target"] in node_ids
