"""Small, read-only HTTP reconnaissance for user supplied targets.

This deliberately does not attempt exploits, credential guessing, crawling, or
state-changing requests. Every finding is based on what the target returns for
one normal GET request to the configured URL.
"""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


ALLOWED_TARGET_TYPES = {"web", "api", "network", "cloud"}
ACTIVE_METHODS = {"POST", "PUT"}
MAX_ACTIVE_PATHS = 4
MAX_ACTIVE_REQUESTS = 8
ACTIVE_RATE_LIMIT_SECONDS = 0.35
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def active_allowlist() -> set[str]:
    """Hosts explicitly approved by the operator for state-changing probes."""
    return {item.strip().lower() for item in os.environ.get("SENTRA_ACTIVE_TARGET_ALLOWLIST", "").split(",") if item.strip()}


def validate_active_policy(target: str, methods: list[str], paths: list[str], confirmed: bool) -> tuple[list[str], list[str]]:
    """Validate the narrow active-check contract before any write is sent."""
    host = (urlsplit(target).hostname or "").lower()
    if host not in active_allowlist():
        raise ValueError("Active mode is disabled for this target. Add its staging hostname to SENTRA_ACTIVE_TARGET_ALLOWLIST.")
    if not confirmed:
        raise ValueError("Active mode requires staging authorization confirmation.")
    normalized_methods = [method.strip().upper() for method in methods if method.strip()]
    if not normalized_methods or any(method not in ACTIVE_METHODS for method in normalized_methods):
        raise ValueError("Active checks allow only the approved POST and PUT methods.")
    normalized_paths = []
    for path in paths:
        path = path.strip()
        if not path.startswith("/") or ".." in path or "*" in path or "?" in path:
            raise ValueError("Active paths must be explicit absolute paths without wildcards, queries, or '..'.")
        if not re.fullmatch(r"/[A-Za-z0-9._~!$&'()+,;=:@/%-]+", path):
            raise ValueError("Active paths contain unsupported characters.")
        normalized_paths.append(path)
    normalized_paths = list(dict.fromkeys(normalized_paths))
    if not normalized_paths or len(normalized_paths) > MAX_ACTIVE_PATHS:
        raise ValueError(f"Choose between 1 and {MAX_ACTIVE_PATHS} approved active paths.")
    if len(normalized_methods) * len(normalized_paths) > MAX_ACTIVE_REQUESTS:
        raise ValueError(f"Active checks are limited to {MAX_ACTIVE_REQUESTS} requests per scan.")
    return list(dict.fromkeys(normalized_methods)), normalized_paths


def normalize_target(value: str) -> str:
    """Return a canonical URL and reject non-HTTP targets."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("A target is required")
    if "://" in raw:
        candidate = raw
    else:
        # Bare private/IP targets are commonly exposed over HTTP in an
        # internal lab. Public hostnames default to HTTPS.
        bare_host = urlsplit(f"//{raw}").hostname
        try:
            is_ip = bare_host is not None and bool(ipaddress.ip_address(bare_host))
        except ValueError:
            is_ip = False
        candidate = f"http://{raw}" if is_ip or (bare_host or "").lower() == "localhost" else f"https://{raw}"
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a hostname, IP address, or http(s) URL")
    host = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host in {"metadata.google.internal", "metadata"} or (address and address in ipaddress.ip_network("169.254.0.0/16")):
        raise ValueError("Cloud metadata link-local addresses are not valid assessment targets")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Target contains an invalid port") from exc
    if parsed.username or parsed.password:
        raise ValueError("Targets with embedded credentials are not allowed")
    if parsed.fragment:
        raise ValueError("URL fragments are not sent to the target and are not allowed")
    # Keep a path if the user supplied one (for example /api), but remove a
    # trailing slash so the value is stable in the scan record.
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def _asset(target: str, target_type: str) -> dict[str, Any]:
    parsed = urlsplit(target)
    host = parsed.hostname or parsed.netloc
    return {
        "id": "target",
        "name": host,
        "type": target_type,
        "exposure": "public",
        "connects_to": [],
        "target": target,
    }


def _finding(
    fid: str,
    asset: str,
    title: str,
    severity: str,
    category: str,
    tags: list[str],
    evidence: str,
    why: str,
    action: str,
    priority: str,
) -> dict[str, Any]:
    return {
        "id": fid,
        "asset_id": asset,
        "title": title,
        "severity": severity,
        "category": category,
        "tags": tags,
        "evidence": evidence,
        "why_it_matters": why,
        "confidence": 0.99,
        "recommended_action": action,
        "remediation": {
            "priority": priority,
            "explanation": action,
            "snippet_language": None,
            "snippet": None,
        },
    }


def _header(headers: httpx.Headers, key: str) -> str | None:
    value = headers.get(key)
    return value.strip() if value else None


def _cookie_findings(response: httpx.Response) -> list[dict[str, Any]]:
    # ``Headers`` combines repeated Set-Cookie values inconsistently across
    # httpx versions, so use the raw header list when available.
    values: list[str] = []
    for key, value in response.headers.multi_items():
        if key.lower() == "set-cookie":
            values.append(value)
    if not values:
        return []
    insecure = [v.split(";", 1)[0].split("=", 1)[0] for v in values if "secure" not in v.lower()]
    no_http_only = [v.split(";", 1)[0].split("=", 1)[0] for v in values if "httponly" not in v.lower()]
    no_samesite = [v.split(";", 1)[0].split("=", 1)[0] for v in values if "samesite" not in v.lower()]
    findings: list[dict[str, Any]] = []
    if insecure:
        findings.append(_finding(
            "LIVE-COOKIE-SECURE", "target", "Session cookies are missing the Secure flag", "medium", "web",
            ["cookie_insecure"], f"Set-Cookie names without Secure: {', '.join(insecure[:8])}",
            "A browser may send these cookies over an unencrypted connection, allowing session capture on hostile networks.",
            "Set Secure on every session cookie and redirect all HTTP traffic to HTTPS.", "P1",
        ))
    if no_http_only:
        findings.append(_finding(
            "LIVE-COOKIE-HTTPONLY", "target", "Session cookies are readable by client-side scripts", "low", "web",
            ["cookie_insecure"], f"Set-Cookie names without HttpOnly: {', '.join(no_http_only[:8])}",
            "An injected script could read and replay these cookies.",
            "Set HttpOnly on authentication and session cookies.", "P2",
        ))
    if no_samesite:
        findings.append(_finding(
            "LIVE-COOKIE-SAMESITE", "target", "Session cookies do not declare SameSite", "low", "web",
            ["cookie_insecure"], f"Set-Cookie names without SameSite: {', '.join(no_samesite[:8])}",
            "Explicit SameSite policy reduces cross-site request and login CSRF risk.",
            "Set SameSite=Lax (or Strict where compatible) on session cookies.", "P2",
        ))
    return findings


async def _active_checks(client: httpx.AsyncClient, target: str, methods: list[str], paths: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run opt-in canary writes only when the endpoint advertises cleanup support."""
    origin = urlsplit(target)
    findings: list[dict[str, Any]] = []
    records = []
    for path in paths:
        url = urlunsplit((origin.scheme, origin.netloc, path, "", ""))
        # An OPTIONS preflight is required: the application must explicitly
        # advertise the SENTRA active-test contract before any write occurs.
        preflight = await client.options(url, headers={"X-SENTRA-Active-Check": "preflight"}, follow_redirects=False)
        contract = (preflight.headers.get("x-sentra-active-contract") or "").lower() == "true"
        cleanup_template = preflight.headers.get("x-sentra-cleanup-path") or ""
        cleanup_declared = bool(cleanup_template)
        if preflight.status_code >= 400 or not contract or not cleanup_declared:
            records.append({"path": path, "status": "skipped", "reason": "endpoint did not advertise X-SENTRA active contract and cleanup path"})
            findings.append(_finding(
                f"LIVE-ACTIVE-SKIP-{len(findings) + 1}", "target", "Active probe skipped by endpoint contract", "info", "config", ["active_probe"],
                f"OPTIONS {path} → {preflight.status_code}; active_contract={contract}; cleanup_path={cleanup_declared}",
                "SENTRA will not send a write unless the staging endpoint explicitly advertises a cleanup contract.",
                "Add the SENTRA active-test contract to the disposable staging endpoint, or keep this assessment read-only.", "P3",
            ))
            await asyncio.sleep(ACTIVE_RATE_LIMIT_SECONDS)
            continue

        for method in methods:
            probe_id = secrets.token_urlsafe(12)
            response = await client.request(
                method, url, json={"sentra_probe": True, "sentra_probe_id": probe_id},
                headers={"X-SENTRA-Active-Check": "canary", "X-SENTRA-Probe-ID": probe_id},
                follow_redirects=False,
            )
            cleanup_raw = response.headers.get("x-sentra-cleanup-path") or response.headers.get("location") or cleanup_template.replace("{probe_id}", probe_id)
            cleanup_url = urljoin(url, cleanup_raw) if cleanup_raw else ""
            cleanup_ok = False
            cleanup_status = None
            if 200 <= response.status_code < 300 and cleanup_url:
                cleanup_parts = urlsplit(cleanup_url)
                same_origin = cleanup_parts.scheme == origin.scheme and cleanup_parts.netloc == origin.netloc
                if same_origin:
                    cleanup = await client.request(
                        "DELETE", cleanup_url, json={"sentra_probe_id": probe_id},
                        headers={"X-SENTRA-Active-Check": "cleanup", "X-SENTRA-Probe-ID": probe_id},
                        follow_redirects=False,
                    )
                    cleanup_status = cleanup.status_code
                    cleanup_ok = 200 <= cleanup.status_code < 300 or cleanup.status_code == 404
            records.append({"method": method, "path": path, "status": response.status_code, "cleanup_status": cleanup_status, "cleaned": cleanup_ok})
            if 200 <= response.status_code < 300 and cleanup_ok:
                title, severity, why, action = "Active canary completed and cleaned up", "info", "The approved staging endpoint accepted a controlled canary and SENTRA removed it immediately.", "Review the canary audit trail if the endpoint is expected to reject test writes."
            elif 200 <= response.status_code < 300:
                title, severity, why, action = "Active canary cleanup failed", "high", "A staging write succeeded but the endpoint did not provide a same-origin cleanup result.", "Stop active checks and manually remove the canary before continuing."
            else:
                title, severity, why, action = "Active canary was rejected", "info", "The approved staging endpoint rejected the controlled request; no successful write was observed.", "Review the endpoint contract and test fixture if an active check is expected."
            findings.append(_finding(
                f"LIVE-ACTIVE-{len(findings) + 1}", "target", title, severity, "config", ["active_probe"],
                f"{method} {path} → {response.status_code}; cleanup={cleanup_status if cleanup_status is not None else 'not attempted'}; probe_id={probe_id}",
                why, action, "P1" if severity == "high" else "P3",
            ))
            await asyncio.sleep(ACTIVE_RATE_LIMIT_SECONDS)
    return findings, {"requests": records, "cleaned": all(r.get("cleaned", True) for r in records)}


def _environment(target: str, target_type: str, scope: str | None, response: httpx.Response | None, error: str | None) -> dict[str, Any]:
    parsed = urlsplit(target)
    host = parsed.hostname or parsed.netloc
    return {
        "id": f"target-{host}",
        "name": host,
        "tagline": "Authorized read-only assessment",
        "sector": "User supplied target",
        "infra": f"{parsed.scheme.upper()} · {target_type.title()}",
        "description": "A live assessment generated from the target supplied by the user.",
        "endpoint_count": 1,
        "assets": [_asset(target, target_type)],
        "target": target,
        "target_type": target_type,
        "scope": scope or "",
        "synthetic": False,
        "observed": {
            "status_code": response.status_code if response else None,
            "final_url": str(response.url) if response else None,
            "server": _header(response.headers, "server") if response else None,
            "error": error,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@dataclass
class LiveScan:
    environment: dict[str, Any]
    findings: list[dict[str, Any]]
    observation: dict[str, Any]


async def scan_target(
    target: str, target_type: str = "web", scope: str | None = None, timeout: float = 10.0,
    assessment_mode: str = "read_only", active_methods: list[str] | None = None,
    active_paths: list[str] | None = None, active_confirmed: bool = False,
) -> LiveScan:
    """Perform one bounded GET and turn observed controls into findings."""
    target = normalize_target(target)
    target_type = target_type if target_type in ALLOWED_TARGET_TYPES else "web"
    if assessment_mode not in {"read_only", "active"}:
        raise ValueError("assessment_mode must be read_only or active")
    methods, paths = [], []
    if assessment_mode == "active":
        methods, paths = validate_active_policy(target, active_methods or [], active_paths or [], active_confirmed)
    findings: list[dict[str, Any]] = []
    response: httpx.Response | None = None
    error: str | None = None
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            headers={"User-Agent": "SENTRA-authorized-security-assessment/1.0"},
        ) as client:
            # Stream the response and intentionally do not consume its body;
            # this keeps a "safe" assessment from downloading an unbounded
            # export or backup just to inspect response controls.
            async with client.stream("GET", target) as streamed:
                response = streamed
                await streamed.aclose()
            active_records = {"requests": [], "cleaned": True}
            if assessment_mode == "active" and response is not None:
                active_findings, active_records = await _active_checks(client, target, methods, paths)
                findings.extend(active_findings)
    except (httpx.HTTPError, OSError) as exc:
        error = f"{type(exc).__name__}: {str(exc)[:180]}"

    env = _environment(target, target_type, scope, response, error)
    if error:
        findings.append(_finding(
            "LIVE-UNREACHABLE", "target", "Target could not be reached", "info", "exposure", ["unreachable"],
            error, "No security conclusion can be made until the target is reachable from the assessment runner.",
            "Verify DNS, routing, firewall rules, and that the supplied URL is the intended authorized target.", "P3",
        ))
        return LiveScan(env, findings, {"reachable": False, "error": error})

    headers = response.headers
    final_url = str(response.url)
    parsed_final = urlsplit(final_url)
    if parsed_final.scheme != "https":
        findings.append(_finding(
            "LIVE-HTTP", "target", "Target accepts unencrypted HTTP", "high", "transport", ["weak_tls", "public_exposure"],
            f"Final URL: {final_url} · scheme={parsed_final.scheme}",
            "Requests and cookies can be observed or modified in transit when HTTPS is not enforced.",
            "Serve the application over HTTPS and redirect HTTP to HTTPS with HSTS.", "P0",
        ))
    elif not _header(headers, "strict-transport-security"):
        findings.append(_finding(
            "LIVE-HSTS", "target", "HSTS is not enabled", "medium", "transport", ["missing_hsts"],
            "Strict-Transport-Security response header was not present.",
            "Browsers can be downgraded to HTTP on a first visit, exposing sessions on hostile networks.",
            "Set Strict-Transport-Security with an appropriate max-age after validating HTTPS coverage.", "P1",
        ))
    if not _header(headers, "content-security-policy"):
        findings.append(_finding(
            "LIVE-CSP", "target", "Content-Security-Policy is not enabled", "low", "web", ["missing_headers"],
            "Content-Security-Policy response header was not present.",
            "A CSP limits the impact of an HTML injection or cross-site scripting bug.",
            "Deploy a restrictive Content-Security-Policy and iterate from report-only mode.", "P2",
        ))
    if not _header(headers, "x-content-type-options"):
        findings.append(_finding(
            "LIVE-NOSNIFF", "target", "MIME sniffing protection is missing", "low", "web", ["missing_headers"],
            "X-Content-Type-Options response header was not present.",
            "Some browsers may interpret responses as a different content type than intended.",
            "Set X-Content-Type-Options: nosniff on web responses.", "P3",
        ))
    if _header(headers, "access-control-allow-origin") == "*" and (_header(headers, "access-control-allow-credentials") or "").lower() == "true":
        findings.append(_finding(
            "LIVE-CORS", "target", "CORS allows every origin with credentials", "high", "web", ["cors_misconfig", "data_access"],
            "Access-Control-Allow-Origin: * · Access-Control-Allow-Credentials: true",
            "Untrusted websites may be able to read authenticated responses from the browser.",
            "Allow-list trusted origins and never combine wildcard origins with credentials.", "P0",
        ))
    server = _header(headers, "server") or _header(headers, "x-powered-by")
    if server:
        findings.append(_finding(
            "LIVE-BANNER", "target", "Server technology is disclosed in response headers", "info", "config", ["banner"],
            f"Server/X-Powered-By: {server}",
            "Technology and version details help attackers select targeted follow-up research.",
            "Suppress framework and version banners in production responses.", "P3",
        ))
    findings.extend(_cookie_findings(response))
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["id"]))
    env["endpoint_count"] = 1
    env["observed"]["assessment_mode"] = assessment_mode
    env["observed"]["active"] = active_records
    return LiveScan(env, findings, {"reachable": True, "status_code": response.status_code, "final_url": final_url, "assessment_mode": assessment_mode, "active": active_records})
