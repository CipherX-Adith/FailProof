import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import SessionLocal
from app.core.config import get_settings
from app.models import ApiEndpoint, ApiSpecification, ApiTarget, GeneratedTest, GitHubImportFile, GitHubRepository, ProjectScanConfig, SecurityEvidence, SecurityFinding, SecurityScan, TestResult, TestRun
from app.services.http_execution import DEMO_ORIGIN, execute_case
from app.services.scanner_adapters import AdapterResult, sanitize_output, scan_dependencies, scan_static
from app.services.github_import import resolve_snapshot_root
from app.services.test_generation import generate_for_endpoint


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
ALLOWED_STATUSES = {"confirmed", "suspected", "not_reproduced", "verification_blocked", "resolved"}
SECRET_KEY = re.compile(r"(?i)authorization|auth|cookie|token|secret|password|credential|api[_-]?key|session")
SECRET_VALUE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")


def _now():
    return datetime.now(timezone.utc)


def allowed_roots() -> list[Path]:
    raw = get_settings().scan_allowed_roots or os.environ.get("FAILPROOF_SCAN_ALLOWED_ROOTS", "")
    paths = []
    for item in raw.split(os.pathsep):
        item = item.strip()
        if not item:
            continue
        try:
            path = Path(item).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if path.is_dir():
            paths.append(path)
    return paths


def validate_source_path(raw_path: str, *, roots: list[Path] | None = None) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Enter an absolute directory path.")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("The selected source directory does not exist or cannot be read.") from exc
    if not resolved.is_dir() or resolved == Path(resolved.anchor):
        raise ValueError("Select a project directory, not a file or filesystem root.")
    permitted = roots if roots is not None else allowed_roots()
    if not permitted:
        raise ValueError("No scan allowlist is configured. Set FAILPROOF_SCAN_ALLOWED_ROOTS on the backend first.")
    for root in permitted:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise ValueError("The selected directory is outside the backend scan allowlist.")


def source_is_still_authorized(config: ProjectScanConfig) -> Path:
    if not config.authorized:
        raise ValueError("A source directory has not been explicitly authorized.")
    return validate_source_path(config.source_root)


def _safe(value, *, depth: int = 0):
    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        output = {}
        for key, item in list(value.items())[:100]:
            name = str(key)[:200]
            output[name] = "[REDACTED]" if SECRET_KEY.search(name) else _safe(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_safe(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return sanitize_output(SECRET_VALUE.sub(r"\1[REDACTED]", value), 4000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:500]


def finding_fingerprint(project_id: str, issue: dict) -> str:
    provenance = (issue.get("details") or {}).get("github_provenance") if isinstance(issue.get("details"), dict) else None
    identity = [
        project_id,
        str(issue.get("scan_type", "")),
        str(issue.get("source", "")),
        str(issue.get("scanner", "")),
        str(issue.get("rule_id", "")),
        str(issue.get("affected_resource", "")),
        str(issue.get("cve_id") or ""),
        str(provenance.get("repository_import_id", "")) if isinstance(provenance, dict) else "",
        str(provenance.get("commit_sha", "")) if isinstance(provenance, dict) else "",
    ]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def persist_issues(db: Session, scan: SecurityScan, issues: list[dict], *, reconcile: bool = False) -> list[SecurityFinding]:
    observed: set[str] = set()
    persisted: list[SecurityFinding] = []
    now = _now()
    for issue in issues:
        issue = dict(issue)
        issue.setdefault("scan_type", scan.scan_type)
        severity = str(issue.get("severity", "unknown")).lower()
        status = str(issue.get("status", "suspected"))
        if severity not in ALLOWED_SEVERITIES:
            severity = "unknown"
        if status not in ALLOWED_STATUSES:
            status = "suspected"
        fingerprint = finding_fingerprint(scan.project_id, issue)
        if fingerprint in observed:
            continue
        observed.add(fingerprint)
        finding = db.scalar(select(SecurityFinding).where(SecurityFinding.fingerprint == fingerprint))
        if finding is None:
            finding = SecurityFinding(project_id=scan.project_id, fingerprint=fingerprint, title=str(issue.get("title", "Security signal"))[:300], description=str(issue.get("description", ""))[:4000], category=str(issue.get("category", "unknown"))[:40], severity=severity, confidence=str(issue.get("confidence", "unknown"))[:20], status=status, source=str(issue.get("source", "unknown"))[:32], scan_type=scan.scan_type, scanner=str(issue.get("scanner", "unknown"))[:80], rule_id=str(issue.get("rule_id", "unknown"))[:200], affected_resource=str(issue.get("affected_resource", ""))[:1000], cwe_id=str(issue["cwe_id"])[:32] if issue.get("cwe_id") else None, cve_id=str(issue["cve_id"])[:32] if issue.get("cve_id") else None, remediation=str(issue.get("remediation", "Review the evidence and scanner guidance."))[:4000], references=list(issue.get("references", []))[:20], first_detected_at=now, last_observed_at=now, last_scan_id=scan.id)
            db.add(finding)
            db.flush()
        else:
            finding.title = str(issue.get("title", finding.title))[:300]
            finding.description = str(issue.get("description", finding.description))[:4000]
            finding.severity = severity
            finding.confidence = str(issue.get("confidence", finding.confidence))[:20]
            finding.status = status
            finding.last_observed_at = now
            finding.last_scan_id = scan.id
            finding.remediation = str(issue.get("remediation", finding.remediation))[:4000]
            finding.references = list(issue.get("references", finding.references or []))[:20]
        evidence = SecurityEvidence(finding_id=finding.id, scan_id=scan.id, evidence_type=str(issue.get("evidence_type", "scanner"))[:40], details=_safe(issue.get("details", {})), expected_result=str(issue["expected_result"])[:4000] if issue.get("expected_result") is not None else None, actual_result=str(issue["actual_result"])[:4000] if issue.get("actual_result") is not None else None, relative_path=str(issue["relative_path"])[:1000] if issue.get("relative_path") else None, line_number=issue.get("line_number") if isinstance(issue.get("line_number"), int) else None, redacted=bool(issue.get("redacted", True)), truncated=bool(issue.get("truncated", False)))
        db.add(evidence)
        persisted.append(finding)
    scan.finding_count = len(observed)
    if reconcile and scan.status == "completed":
        previous = db.scalars(select(SecurityFinding).where(SecurityFinding.project_id == scan.project_id, SecurityFinding.scan_type == scan.scan_type, SecurityFinding.status.in_(("confirmed", "suspected", "not_reproduced")))).all()
        source_kind = scan.configuration.get("source_kind", "local")
        github_import_id = scan.configuration.get("github_repository_id")
        for finding in previous:
            previous_scan = db.get(SecurityScan, finding.last_scan_id) if finding.last_scan_id else None
            previous_config = previous_scan.configuration if previous_scan and isinstance(previous_scan.configuration, dict) else {}
            previous_kind = previous_config.get("source_kind", "local")
            if previous_kind != source_kind or (source_kind == "github" and previous_config.get("github_repository_id") != github_import_id):
                continue
            if finding.fingerprint in observed:
                continue
            finding.status = "resolved"
            finding.last_scan_id = scan.id
    db.flush()
    return persisted


def _severity_for_api(category: str) -> str:
    if category == "authorization":
        return "high"
    if category in {"duplicate-operation", "negative-amount", "business-rule"}:
        return "medium"
    if category in {"boundary-value", "missing-required", "incorrect-type", "missing-required-parameter"}:
        return "low"
    return "informational"


def _api_issue(case: GeneratedTest, endpoint: ApiEndpoint, result: TestResult, scan_type: str) -> dict:
    category = case.category
    is_business = scan_type == "business_logic"
    source = "business_logic" if is_business else "api_security"
    strongly_confirmed = category in {"authorization", "duplicate-operation", "negative-amount"}
    actual = f"Expected HTTP status {', '.join(case.expected_statuses)}; observed {result.actual_status}."
    authorization_scope = " The demo has no authenticated principal; this confirms the synthetic contract mismatch, not cross-account access in an authenticated service." if category == "authorization" else ""
    return {"scan_type": scan_type, "title": case.name, "description": f"{case.expected_behavior} Observed response did not match the registered rule. This result is limited to the synthetic local demo target.{authorization_scope}", "category": category if not is_business else "business-logic", "severity": _severity_for_api(category), "confidence": "high" if strongly_confirmed else "medium", "status": "confirmed" if strongly_confirmed else "suspected", "source": source, "scanner": "FailProof deterministic API rule", "rule_id": f"demo:{endpoint.operation_id or endpoint.path}:{category}", "affected_resource": f"{endpoint.method} {endpoint.path}", "cwe_id": None, "cve_id": None, "remediation": case.rationale[:4000], "references": [], "evidence_type": "http-test", "details": {"request": result.evidence.get("request", {}), "responses": result.evidence.get("responses", []), "expected_statuses": case.expected_statuses, "test_name": case.name, "scope": "synthetic-loopback-demo", "authenticated_principal_present": False if category == "authorization" else None}, "expected_result": case.expected_behavior, "actual_result": actual, "redacted": True}


def _header_signal(result: TestResult) -> dict | None:
    responses = result.evidence.get("responses", [])
    if not responses or result.state != "passed":
        return None
    headers = responses[-1].get("headers", {}) if isinstance(responses[-1], dict) else {}
    if "x-content-type-options" in headers:
        return None
    return {"scan_type": "api_security", "title": "X-Content-Type-Options header is absent", "description": "The synthetic JSON health response did not include X-Content-Type-Options. This is a low-confidence hardening signal; the missing header alone does not establish exploitability.", "category": "security-header", "severity": "informational", "confidence": "low", "status": "suspected", "source": "api_security", "scanner": "FailProof response-header check", "rule_id": "demo:health:x-content-type-options", "affected_resource": "GET /health", "cwe_id": None, "cve_id": None, "remediation": "Consider returning X-Content-Type-Options: nosniff where appropriate for the API response context.", "references": [], "evidence_type": "http-response", "details": {"status": responses[-1].get("status"), "captured_headers": headers}, "expected_result": "A JSON API response may include X-Content-Type-Options: nosniff as a hardening control.", "actual_result": "The header was absent from the observed response; this is not treated as a confirmed vulnerability.", "redacted": True}


def _run_demo_checks(db: Session, scan: SecurityScan, *, approve_state_changes: bool, transport: httpx.BaseTransport | None = None) -> AdapterResult:
    target = db.scalar(select(ApiTarget).where(ApiTarget.project_id == scan.project_id, ApiTarget.base_url == DEMO_ORIGIN, ApiTarget.authorized.is_(True), ApiTarget.status == "ready").order_by(ApiTarget.registered_at.desc()).limit(1))
    if target is None:
        return AdapterResult(status="blocked", availability={"local_demo_api": "unavailable"}, errors=["No authorized, specification-ready local demo target is registered for this project."], summary="Demo API checks are blocked because the controlled local target is not ready.")
    spec = db.scalar(select(ApiSpecification).where(ApiSpecification.target_id == target.id).order_by(ApiSpecification.imported_at.desc()).limit(1))
    if spec is None:
        return AdapterResult(status="blocked", availability={"local_demo_api": "unavailable"}, errors=["Import an OpenAPI contract for the authorized local demo target before running these checks."], summary="Demo API checks are blocked because no contract is imported.")
    endpoints = db.scalars(select(ApiEndpoint).where(ApiEndpoint.target_id == target.id, ApiEndpoint.specification_id == spec.id)).all()
    cases: list[GeneratedTest] = []
    included = {"authorization", "missing-required", "incorrect-type", "boundary-value", "invalid-parameter"} if scan.scan_type == "api_security" else {"negative-amount", "duplicate-operation"}
    case_endpoints: dict[str, ApiEndpoint] = {}
    for endpoint in endpoints:
        for case in generate_for_endpoint(target, endpoint, endpoint.configured_rules):
            if case.category in included or (scan.scan_type == "api_security" and endpoint.operation_id == "health" and case.category == "valid"):
                merged_case = db.merge(case)
                cases.append(merged_case)
                case_endpoints[case.id] = endpoint
    if scan.scan_type == "api_security":
        health = next((endpoint for endpoint in endpoints if endpoint.operation_id == "health" and endpoint.method == "GET"), None)
        if health is not None:
            probe = ApiEndpoint(id=health.id, target_id=health.target_id, specification_id=health.specification_id, path=health.path, method="OPTIONS", operation_id=health.operation_id, summary=health.summary, parameters=[], request_schema=None, required_fields=[], responses={})
            probe_id = hashlib.sha256(f"{target.id}:OPTIONS:{health.path}:unsupported-method".encode()).hexdigest()[:32]
            probe_case = GeneratedTest(id=probe_id, target_id=target.id, endpoint_id=health.id, name="Reject unregistered OPTIONS method", category="unsupported-method", parameters={}, request_body=None, expected_statuses=["405"], expected_behavior="An HTTP method not declared by the imported API contract should not perform an operation.", rationale="Non-destructive method handling check against the registered local demo target.", requires_approval=False, repetitions=1)
            cases.append(db.merge(probe_case))
            case_endpoints[probe_id] = probe
    db.flush()
    if not cases:
        return AdapterResult(status="blocked", availability={"local_demo_api": "available"}, errors=["The imported specification does not define any supported deterministic checks for this scan type."], summary="No supported checks were available for this demo scan.")
    run = TestRun(target_id=target.id, status="running")
    db.add(run)
    db.flush()
    endpoint_map = {endpoint.id: endpoint for endpoint in endpoints}
    remaining = 50
    blocked = errors = executed = 0
    issues = []
    for case in cases[:50]:
        endpoint = case_endpoints.get(case.id) or endpoint_map.get(case.endpoint_id)
        if endpoint is None:
            outcome = {"state": "error", "error_detail": "Endpoint is no longer available.", "actual_status": None, "duration_ms": None, "evidence": {}}
        else:
            cost = max(1, min(case.repetitions, 3))
            if cost > remaining:
                outcome = {"state": "not-run", "error_detail": "This scan reached its 50-request limit.", "actual_status": None, "duration_ms": None, "evidence": {}}
            else:
                approved = bool(approve_state_changes and target.config.get("approve_non_safe_methods", False))
                outcome = execute_case(target, endpoint, case, run_id=run.id, approve_non_safe=approved, transport=transport)
                remaining -= cost
        result = TestResult(run_id=run.id, test_id=case.id, endpoint_path=endpoint.path if endpoint else "", method=endpoint.method if endpoint else "", **outcome)
        db.add(result)
        db.flush()
        if outcome["state"] == "blocked":
            blocked += 1
        elif outcome["state"] in {"error", "not-run"}:
            errors += 1
        else:
            executed += 1
        if scan.scan_type == "api_security" and case.category == "valid" and endpoint is not None and endpoint.operation_id == "health":
            signal = _header_signal(result)
            if signal:
                issues.append(signal)
        if outcome["state"] == "failed" and endpoint is not None:
            issues.append(_api_issue(case, endpoint, result, scan.scan_type))
    run.status = "completed"
    run.result_count = len(cases[:50])
    run.completed_at = _now()
    db.flush()
    if blocked or errors:
        status = "completed_with_errors" if executed else "blocked"
    else:
        status = "completed"
    return AdapterResult(status=status, availability={"local_demo_api": "available"}, findings=issues, errors=[f"{blocked} check(s) were blocked by missing per-run or target approval."] if blocked else [], warnings=[f"{errors} check(s) could not produce an execution result."] if errors else [], summary=f"Executed {executed} deterministic HTTP checks and observed {len(issues)} mismatch(es). Persisted API test run {run.id}.")


def run_scan_job(scan_id: str, session_factory: sessionmaker = SessionLocal, *, scanner_runner: Callable | None = None) -> None:
    db = session_factory()
    try:
        scan = db.get(SecurityScan, scan_id)
        if scan is None:
            return
        if scan.status != "queued":
            return
        scan.status = "running"
        scan.summary = "Scan is running."
        db.commit()
        try:
            if scan.scan_type in {"static", "dependencies"}:
                if scan.configuration.get("source_kind") == "github":
                    imported = db.get(GitHubRepository, scan.configuration.get("github_repository_id"))
                    settings = get_settings()
                    workspace = Path(settings.github_workspace_dir or (Path(__file__).resolve().parents[3] / ".failproof" / "github")).expanduser().resolve()
                    try:
                        if imported is None or imported.project_id != scan.project_id or imported.status not in {"completed", "completed_partial"} or scan.scan_type not in (imported.supported_scan_types or []):
                            raise ValueError("The selected GitHub snapshot is no longer completed and authorized.")
                        if not imported.workspace_relpath:
                            raise ValueError("The stored GitHub snapshot path is invalid.")
                        root = resolve_snapshot_root(workspace, imported.workspace_relpath)
                    except (OSError, ValueError, RuntimeError):
                        result = AdapterResult(status="blocked", errors=["The selected GitHub snapshot is unavailable or outside the managed repository workspace."], availability={}, summary="Scan blocked because the imported snapshot could not be validated.")
                    else:
                        runner_kwargs = {"runner": scanner_runner} if scanner_runner else {}
                        result = scan_static(root, **runner_kwargs) if scan.scan_type == "static" else scan_dependencies(root, **runner_kwargs)
                        for issue in result.findings:
                            path = issue.get("relative_path") or issue.get("affected_resource", "")
                            file_record = db.scalar(select(GitHubImportFile).where(GitHubImportFile.repository_link_id == imported.id, GitHubImportFile.relative_path == path))
                            if file_record:
                                details = dict(issue.get("details") or {})
                                details["github_provenance"] = {"repository_import_id": imported.id, "repository": imported.full_name, "commit_sha": imported.commit_sha, "path": path, "blob_sha": file_record.blob_sha, "content_sha256": file_record.content_sha256}
                                issue["details"] = details
                elif (config := db.get(ProjectScanConfig, scan.project_id)) is None:
                    result = AdapterResult(status="blocked", errors=["Register and authorize a local project directory before scanning source or dependencies."], availability={}, summary="Scan blocked because no source directory is registered.")
                else:
                    try:
                        root = source_is_still_authorized(config)
                    except ValueError as exc:
                        result = AdapterResult(status="blocked", errors=[str(exc)], availability={}, summary="Scan blocked because the source directory is no longer authorized or available.")
                    else:
                        runner_kwargs = {"runner": scanner_runner} if scanner_runner else {}
                        if scan.scan_type == "static":
                            result = scan_static(root, **runner_kwargs)
                        else:
                            result = scan_dependencies(root, **runner_kwargs)
            else:
                result = _run_demo_checks(db, scan, approve_state_changes=bool(scan.configuration.get("approve_state_changes")))
            scan.status = result.status
            scan.scanner_availability = result.availability
            scan.errors = [_safe(error) for error in result.errors[:40]]
            scan.warnings = [_safe(warning) for warning in result.warnings[:40]]
            scan.summary = result.summary[:2000]
            scan.completed_at = _now()
            persist_issues(db, scan, result.findings, reconcile=result.status == "completed")
            db.commit()
        except Exception as exc:
            db.rollback()
            scan = db.get(SecurityScan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.completed_at = _now()
                scan.errors = [f"Scan execution failed ({exc.__class__.__name__})."]
                scan.summary = "The scan failed before completing its checks. No clean result is implied."
                db.commit()
    finally:
        db.close()

