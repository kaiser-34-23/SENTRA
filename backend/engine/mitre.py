"""Small, deterministic MITRE ATT&CK layer for observed findings.

SENTRA does not claim that a response proves an ATT&CK technique.  These
labels explain which attacker objective a finding supports, and are kept
deterministic so the graph remains auditable.
"""

TECHNIQUES = {
    "public_exposure": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "default_creds": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    "auth_weakness": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    "no_rate_limit": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "idor": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "ssrf": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "weak_ssh": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "weak_tls": {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "cookie_insecure": {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    "cors_misconfig": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    "info_leak": {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "banner": {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "excessive_privilege": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "data_access": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    "pii_store": {"id": "T1530", "name": "Data from Cloud Storage Object", "tactic": "Collection"},
    "session_store": {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    "jwt_weak": {"id": "T1134", "name": "Access Token Manipulation", "tactic": "Defense Evasion"},
    "no_auth_service": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
}

ROLE_BY_TAG = {
    "public_exposure": "Initial access",
    "default_creds": "Initial access",
    "auth_weakness": "Initial access",
    "no_rate_limit": "Credential access",
    "weak_ssh": "Credential access",
    "weak_tls": "Credential access",
    "cookie_insecure": "Credential access",
    "session_store": "Credential access",
    "idor": "Initial access",
    "ssrf": "Initial access",
    "cors_misconfig": "Initial access",
    "jwt_weak": "Defense evasion",
    "excessive_privilege": "Privilege escalation",
    "info_leak": "Reconnaissance",
    "banner": "Reconnaissance",
    "data_access": "Collection",
    "pii_store": "Collection",
    "no_auth_service": "Lateral movement",
}


def _techniques(finding):
    seen = set()
    result = []
    for tag in finding.get("tags", []):
        technique = TECHNIQUES.get(tag)
        if technique and technique["id"] not in seen:
            result.append(dict(technique))
            seen.add(technique["id"])
    return result


def annotate_findings(findings):
    """Return findings with explanation metadata, without mutating source data."""
    annotated = []
    for finding in findings:
        item = dict(finding)
        techniques = _techniques(item)
        item["mitre"] = techniques
        item["attack_role"] = next((ROLE_BY_TAG[tag] for tag in item.get("tags", []) if tag in ROLE_BY_TAG), "Control weakness")
        item["enables"] = {
            "Initial access": "a foothold from the public attack surface",
            "Credential access": "session or account compromise",
            "Privilege escalation": "a higher-privilege execution context",
            "Collection": "access to sensitive data",
            "Reconnaissance": "faster discovery of the next attack step",
            "Defense evasion": "identity or control bypass",
            "Lateral movement": "reach into an internal service",
            "Control weakness": "additional attack surface",
        }.get(item["attack_role"], "additional attack surface")
        annotated.append(item)
    return annotated
