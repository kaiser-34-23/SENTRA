"""Deterministic security scoring. Score = 100 * exp(-risk / k). No AI."""
import math

SEVERITY_POINTS = {"critical": 18.0, "high": 9.0, "medium": 4.0, "low": 1.5, "info": 0.5}
PATH_PENALTY = 3.0
PATH_PENALTY_CAP = 15.0
OVERALL_K = 90.0
CATEGORY_K = 22.0
CATEGORY_LABELS = {"web": "Web", "transport": "Transport", "auth": "Auth/Access", "config": "Configuration", "exposure": "Exposure"}


def grade(score):
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Weak"
    return "Critical"


def compute_score(findings, paths):
    finding_risk = sum(SEVERITY_POINTS[f["severity"]] for f in findings)
    path_risk = min(PATH_PENALTY * len(paths), PATH_PENALTY_CAP)
    overall = round(100 * math.exp(-(finding_risk + path_risk) / OVERALL_K))
    categories = []
    for key, label in CATEGORY_LABELS.items():
        cat = [f for f in findings if f["category"] == key]
        risk = sum(SEVERITY_POINTS[f["severity"]] for f in cat)
        s = round(100 * math.exp(-risk / CATEGORY_K))
        categories.append({"key": key, "label": label, "score": s, "grade": grade(s), "finding_count": len(cat)})
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ["critical", "high", "medium", "low", "info"]}
    return {
        "overall": overall,
        "grade": grade(overall),
        "finding_risk": round(finding_risk, 1),
        "path_risk": round(path_risk, 1),
        "categories": categories,
        "severity_counts": counts,
    }
