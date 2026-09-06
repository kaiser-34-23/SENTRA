"""SENTRA backend API integration tests."""
import os
import json
import time
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://sentra-intel.preview.emergentagent.com').rstrip('/')
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def s():
    return requests.Session()


# Environments
def test_environments_list(s):
    r = s.get(f"{API}/environments", timeout=15)
    assert r.status_code == 200
    envs = r.json()
    ids = {e["id"] for e in envs}
    assert ids == {"acme-retail", "fincorp-bank", "healthops"}
    for e in envs:
        assert e.get("synthetic") is True
        assert "finding_count" in e
        assert "findings" not in e
        assert "assets" in e


# Scan errors
def test_scan_unauthorized(s):
    r = s.post(f"{API}/scans", json={"environment_id": "acme-retail", "authorized": False}, timeout=15)
    assert r.status_code == 400


def test_scan_unknown_env(s):
    r = s.post(f"{API}/scans", json={"environment_id": "does-not-exist", "authorized": True}, timeout=15)
    assert r.status_code == 404


def test_bad_results_404(s):
    r = s.get(f"{API}/scans/nonexistent-id/results", timeout=15)
    assert r.status_code == 404


# SSE + results per env
def _run_scan(s, env_id):
    r = s.post(f"{API}/scans", json={"environment_id": env_id, "authorized": True}, timeout=15)
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]
    # Stream SSE
    events = []
    t0 = time.time()
    with s.get(f"{API}/scans/{scan_id}/stream", stream=True, timeout=30) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        for line in resp.iter_lines(decode_unicode=True):
            if line and line.startswith("data: "):
                events.append(json.loads(line[6:]))
                if events[-1].get("type") == "complete":
                    break
    elapsed = time.time() - t0
    return scan_id, events, elapsed


@pytest.fixture(scope="module")
def acme_scan(s):
    return _run_scan(s, "acme-retail")


def test_sse_stream_acme(acme_scan):
    scan_id, events, elapsed = acme_scan
    logs = [e for e in events if e.get("type") == "log"]
    completes = [e for e in events if e.get("type") == "complete"]
    assert len(logs) >= 15, f"expected ~17 log events, got {len(logs)}"
    assert len(completes) == 1
    assert 5 <= elapsed <= 15, f"scan took {elapsed}s, expected ~7s"


def test_results_acme(s, acme_scan):
    scan_id, _, _ = acme_scan
    r = s.get(f"{API}/scans/{scan_id}/results", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "complete"
    assert len(data["findings"]) == 11
    assert len(data["attack_paths"]) >= 4
    score = data["score"]
    assert 0 <= score["overall"] <= 100
    assert "grade" in score
    assert len(score["categories"]) == 5
    assert set(score["severity_counts"].keys()) >= {"critical", "high", "medium", "low", "info"}
    graph = data["graph"]
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "attacker" in node_ids
    assert any(nid.startswith("asset:") for nid in node_ids)
    # remediation P0 first
    prios = [r_["priority"] for r_ in data["remediation"]]
    assert prios == sorted(prios)
    # attack path fields
    for p in data["attack_paths"]:
        assert "node_ids" in p and "edge_ids" in p and "steps" in p
        assert 0 < p["likelihood"] <= 1
        assert "rank" in p


def test_results_fincorp(s):
    scan_id, _, _ = _run_scan(s, "fincorp-bank")
    r = s.get(f"{API}/scans/{scan_id}/results", timeout=15)
    data = r.json()
    assert len(data["findings"]) == 10
    assert len(data["attack_paths"]) >= 4


def test_results_healthops(s):
    scan_id, _, _ = _run_scan(s, "healthops")
    r = s.get(f"{API}/scans/{scan_id}/results", timeout=15)
    data = r.json()
    assert len(data["findings"]) == 10
    assert len(data["attack_paths"]) >= 4


# Determinism
def test_determinism_acme(s, acme_scan):
    scan_id1, _, _ = acme_scan
    r1 = s.get(f"{API}/scans/{scan_id1}/results", timeout=15).json()
    scan_id2, _, _ = _run_scan(s, "acme-retail")
    r2 = s.get(f"{API}/scans/{scan_id2}/results", timeout=15).json()
    assert r1["score"]["overall"] == r2["score"]["overall"]
    p1 = [p["node_ids"] for p in r1["attack_paths"]]
    p2 = [p["node_ids"] for p in r2["attack_paths"]]
    assert p1 == p2
    assert len(r1["graph"]["edges"]) == len(r2["graph"]["edges"])


# AI analysis
def test_ai_analysis(s, acme_scan):
    scan_id, _, _ = acme_scan
    r = s.post(f"{API}/scans/{scan_id}/ai-analysis", timeout=90)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "analysis" in data
    a = data["analysis"]
    for k in ["summary", "business_impact", "attacker_objective", "priority", "path_narratives", "remediation", "evidence_cited", "confidence"]:
        assert k in a, f"missing key: {k}"
    assert 0 <= a["confidence"] <= 1
    # Validate path/finding id references
    results = s.get(f"{API}/scans/{scan_id}/results", timeout=15).json()
    path_ids = {p["id"] for p in results["attack_paths"]}
    finding_ids = {f["id"] for f in results["findings"]}
    for pn in a["path_narratives"]:
        assert pn.get("path_id") in path_ids
    for rm in a["remediation"]:
        assert rm.get("finding_id") in finding_ids
    # ai_analysis now non-null
    assert results["ai_analysis"] is not None


# Incident demo
def test_incident_demo(s):
    r = s.get(f"{API}/incident/demo", timeout=15)
    assert r.status_code == 200
    data = r.json()
    step_keys = [s["key"] for s in data["steps"]]
    assert step_keys == ["detect", "investigate", "correlate", "explain", "recommend"]
    assert "findings" in data and isinstance(data["findings"], dict)
    assert "environment" in data
    assert "attack_paths" in data
