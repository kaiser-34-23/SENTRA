"""Pure, deterministic remediation simulation for an existing assessment."""

from engine.correlation import build_attack_paths, build_edges, build_graph
from engine.scoring import compute_score


def _path_signature(path):
    return tuple(path["node_ids"])


def simulate_controls(env, all_findings, fixed_ids, baseline_paths=None, baseline_score=None):
    """Remove selected findings and return the recalculated security state.

    The target is never changed. This models the effect of controls against the
    already-observed evidence and keeps the original assessment's entry points
    fixed so internal nodes cannot become artificial internet entry points.
    """
    known_ids = {finding["id"] for finding in all_findings}
    fixed_ids = set(fixed_ids)
    unknown = sorted(fixed_ids - known_ids)
    if unknown:
        raise ValueError(f"Unknown finding id(s): {', '.join(unknown)}")

    baseline_edges = build_edges(all_findings, env["assets"])
    baseline_paths = baseline_paths if baseline_paths is not None else build_attack_paths(all_findings, baseline_edges)
    baseline_score = baseline_score if baseline_score is not None else compute_score(all_findings, baseline_paths)
    baseline_entries = {path["node_ids"][0] for path in baseline_paths if path["node_ids"]}
    baseline_graph = build_graph(env, all_findings, baseline_edges, baseline_paths)

    active_findings = [finding for finding in all_findings if finding["id"] not in fixed_ids]
    active_edges = build_edges(active_findings, env["assets"])
    active_paths = build_attack_paths(active_findings, active_edges, entry_ids=baseline_entries)
    active_score = compute_score(active_findings, active_paths)
    active_graph = build_graph(env, active_findings, active_edges, active_paths)

    active_signatures = {_path_signature(path) for path in active_paths}
    broken_paths = [path for path in baseline_paths if _path_signature(path) not in active_signatures]
    fixed_on_paths = sorted({
        finding_id
        for path in baseline_paths
        for finding_id in path["node_ids"]
        if finding_id in fixed_ids
    })
    removed_edge_ids = sorted(
        {edge["id"] for edge in baseline_graph["edges"]}
        - {edge["id"] for edge in active_graph["edges"]}
    )
    score_delta = active_score["overall"] - baseline_score["overall"]
    risk_before = 100 - baseline_score["overall"]
    risk_after = 100 - active_score["overall"]

    if not fixed_ids:
        explanation = "No controls selected. The original security state is unchanged."
    elif not active_paths and baseline_paths:
        explanation = (
            f"The selected remediation breaks all {len(baseline_paths)} validated attack paths. "
            "No modeled route to a sensitive asset remains."
        )
    elif broken_paths:
        explanation = (
            f"The selected remediation breaks {len(broken_paths)} validated attack "
            f"path{'s' if len(broken_paths) != 1 else ''}, but {len(active_paths)} "
            f"secondary path{'s' if len(active_paths) != 1 else ''} remain."
        )
    else:
        explanation = (
            "The selected remediation reduces finding risk, but it does not break a "
            "validated path to a sensitive asset."
        )

    return {
        "findings": active_findings,
        "attack_paths": active_paths,
        "score": active_score,
        "graph": active_graph,
        "fixed_finding_ids": sorted(fixed_ids),
        "comparison": {
            "baseline_score": baseline_score["overall"],
            "simulated_score": active_score["overall"],
            "score_delta": score_delta,
            "risk_before": risk_before,
            "risk_after": risk_after,
            "baseline_path_count": len(baseline_paths),
            "remaining_path_count": len(active_paths),
            "broken_path_count": len(broken_paths),
            "broken_path_ids": [path["id"] for path in broken_paths],
            "fixed_on_path_ids": fixed_on_paths,
            "removed_edge_ids": removed_edge_ids,
            "explanation": explanation,
        },
    }
