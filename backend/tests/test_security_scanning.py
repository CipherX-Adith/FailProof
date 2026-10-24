import json
import os
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.models import ApiEndpoint, ApiSpecification, ApiTarget, Project, ProjectScanConfig, SecurityEvidence, SecurityFinding, SecurityScan
from app.services.scanner_adapters import AdapterResult, CommandResult, run_bounded, scan_dependencies, scan_static
from app.services.security_scanning import _run_demo_checks, finding_fingerprint, persist_issues, validate_source_path
from app.services.openapi_import import parse_openapi, persist_endpoint


FIXTURE = Path(__file__).parent / "fixtures" / "security"
DEMO_SPEC = Path(__file__).parents[2] / "demo_api" / "openapi.yaml"


def test_bandit_detects_synthetic_shell_execution_and_clean_fixture_is_clear():
    if __import__("importlib").util.find_spec("bandit") is None:
        pytest.skip("Bandit is optional; install backend/requirements-security.txt to run this integration test.")
    result = scan_static(FIXTURE)
    assert result.status == "completed"
    assert result.availability["bandit"] == "available"
    assert any(item["rule_id"] == "B602" and item["affected_resource"] == "vulnerable.py" and item["line_number"] == 5 for item in result.findings)
    assert next(item for item in result.findings if item["rule_id"] == "B602")["relative_path"] == "vulnerable.py"
    assert not any(item["affected_resource"] == "clean.py" for item in result.findings)
    assert all(item["status"] == "suspected" for item in result.findings)


def test_static_scanner_reports_unavailable_instead_of_clean():
    result = scan_static(FIXTURE, module_available=lambda _module: False)
    assert result.status == "blocked"
    assert result.availability["bandit"] == "unavailable"
    assert result.findings == []
    assert "not installed" in result.errors[0]


def test_bounded_runner_enforces_timeout_and_output_limit(tmp_path):
    normal = run_bounded([sys.executable, "-c", "print('ok')"], cwd=tmp_path, timeout=3, output_limit=128)
    assert normal.returncode == 0 and normal.output.strip() == "ok"
    timed = run_bounded([sys.executable, "-c", "import time; time.sleep(2)"], cwd=tmp_path, timeout=1, output_limit=128)
    assert timed.timed_out is True
    large = run_bounded([sys.executable, "-c", "print('x' * 100000)"], cwd=tmp_path, timeout=3, output_limit=128)
    assert large.truncated is True
    assert len(large.output) <= 128


def test_dependency_adapters_normalize_only_scanner_reported_advisories(tmp_path):
    (tmp_path / "requirements.txt").write_text("sample-package==1.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"fixture","version":"1"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/sample-js": {"version": "1.2.0"}}}), encoding="utf-8")
    pip_report = {"dependencies": [{"name": "sample-package", "version": "1.0", "vulns": [{"id": "TEST-ADVISORY-1", "fix_versions": ["1.1"], "aliases": [], "description": "controlled parser fixture"}]}]}
    npm_report = {"metadata": {"vulnerabilities": {"total": 1}}, "vulnerabilities": {"sample-js": {"severity": "high", "range": "<2.0.0", "nodes": ["node_modules/sample-js"], "via": [{"source": "TEST-ADVISORY-2", "title": "controlled parser fixture", "cwe": ["CWE-79"]}], "fixAvailable": {"version": "2.0.0"}}}}

    def runner(args, **_kwargs):
        report = pip_report if "pip_audit" in args else npm_report
        return CommandResult(1 if report is pip_report or report is npm_report else 0, json.dumps(report))

    result = scan_dependencies(tmp_path, runner=runner, module_available=lambda _module: True, npm_available=lambda: True)
    assert result.status == "completed"
    assert len(result.findings) == 2
    python_finding = next(item for item in result.findings if item["source"] == "pip-audit")
    javascript_finding = next(item for item in result.findings if item["source"] == "npm-audit")
    assert python_finding["relative_path"] == "requirements.txt"
    assert javascript_finding["relative_path"] == "package-lock.json"
    assert python_finding["rule_id"] == "TEST-ADVISORY-1"
    assert python_finding["cve_id"] is None
    assert python_finding["details"]["fix_versions"] == ["1.1"]
    assert javascript_finding["affected_resource"] == "sample-js 1.2.0"
    assert javascript_finding["cwe_id"] == "CWE-79"


def test_dependency_advisory_service_failure_is_incomplete_not_clean(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"fixture","version":"1"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"packages":{"":{}}}', encoding="utf-8")
    failed = scan_dependencies(tmp_path, runner=lambda *_args, **_kwargs: CommandResult(None, "getaddrinfo ENOTFOUND registry.npmjs.org", error="network unavailable"), npm_available=lambda: True)
    assert failed.status == "blocked"
    assert failed.availability["npm-audit"] == "advisory_service_or_execution_error"
    assert failed.findings == []
    assert "complete advisory report" in failed.errors[0]


def test_source_registration_enforces_configured_root_and_canonical_path(tmp_path):
    allowed = tmp_path / "approved"
    project = allowed / "project"
    project.mkdir(parents=True)
    outside = tmp_path / "private"
    outside.mkdir()
    assert validate_source_path(str(project), roots=[allowed]) == project.resolve()
    with pytest.raises(ValueError, match="outside"):
        validate_source_path(str(outside), roots=[allowed])
    with pytest.raises(ValueError, match="absolute"):
        validate_source_path("relative/project", roots=[allowed])


def test_fingerprint_upsert_preserves_first_seen_and_evidence_and_only_resolves_complete_scan(db):
    project = Project(name="Security persistence", description="")
    db.add(project); db.flush()
    first_scan = SecurityScan(project_id=project.id, scan_type="static", status="completed", summary="completed")
    db.add(first_scan); db.flush()
    issue = {"scan_type": "static", "source": "bandit", "scanner": "Bandit", "rule_id": "B602", "affected_resource": "src/main.py", "title": "Shell use", "description": "Signal", "category": "static-analysis", "severity": "high", "confidence": "high", "status": "suspected", "details": {"authorization": "Bearer topsecret", "code": "password='secret-value'"}, "relative_path": "src/main.py", "line_number": 4}
    finding_id = finding_fingerprint(project.id, issue)
    first = persist_issues(db, first_scan, [issue])[0]
    db.commit()
    first_detected = first.first_detected_at
    repeat_scan = SecurityScan(project_id=project.id, scan_type="static", status="completed", summary="completed")
    db.add(repeat_scan); db.flush()
    repeated = persist_issues(db, repeat_scan, [issue])[0]
    assert repeated.id == first.id
    assert repeated.first_detected_at == first_detected
    db.commit()
    assert db.scalar(select(SecurityFinding).where(SecurityFinding.fingerprint == finding_id)) is not None
    evidence = db.scalars(select(SecurityEvidence).where(SecurityEvidence.finding_id == first.id)).all()
    assert len(evidence) == 2
    serialized = json.dumps(evidence[0].details)
    assert "topsecret" not in serialized and "secret-value" not in serialized
    incomplete = SecurityScan(project_id=project.id, scan_type="static", status="completed_with_errors", summary="partial")
    db.add(incomplete); db.flush()
    persist_issues(db, incomplete, [], reconcile=True)
    db.commit()
    assert repeated.status == "suspected"
    complete = SecurityScan(project_id=project.id, scan_type="static", status="completed", summary="complete clean retest")
    db.add(complete); db.flush()
    persist_issues(db, complete, [], reconcile=True)
    db.commit()
    assert repeated.status == "resolved"


def test_demo_security_scan_uses_existing_bounded_executor_and_persists_observed_failure(db):
    project = Project(name="Demo checks", description="")
    db.add(project); db.flush()
    target = ApiTarget(project_id=project.id, name="Demo", base_url="http://127.0.0.1:8765", authorized=True, status="ready", config={"approve_non_safe_methods": True})
    db.add(target); db.flush()
    parsed = parse_openapi(DEMO_SPEC.read_bytes(), "openapi.yaml")
    specification = ApiSpecification(target_id=target.id, openapi_version=parsed.version, title=parsed.title, source_filename="openapi.yaml", sha256=parsed.digest)
    db.add(specification); db.flush()
    for item in parsed.endpoints:
        db.add(persist_endpoint(target.id, specification.id, item))
    db.flush()
    scan = SecurityScan(project_id=project.id, scan_type="business_logic", status="running", configuration={"approve_state_changes": True})
    db.add(scan); db.flush()
    handler_calls = []

    per_order: dict[str, int] = {}

    def handler(request):
        handler_calls.append((request.method, request.url.path, request.content))
        if request.url.path.endswith("/capture"):
            order_id = request.url.path.rsplit("/", 2)[-2]
            per_order[order_id] = per_order.get(order_id, 0) + 1
            return httpx.Response(201 if per_order[order_id] == 1 else 200, json={"capture_count": per_order[order_id]})
        return httpx.Response(200)

    result = _run_demo_checks(db, scan, approve_state_changes=True, transport=httpx.MockTransport(handler))
    assert result.status == "completed"
    assert len(result.findings) == 2
    assert {item["category"] for item in result.findings} == {"business-logic"}
    assert {item["rule_id"].rsplit(":", 1)[-1] for item in result.findings} == {"negative-amount", "duplicate-operation"}
    assert all(item["status"] == "confirmed" for item in result.findings)
    assert all("responses" in item["details"] for item in result.findings)
    assert len(handler_calls) == 3


def test_demo_api_scan_without_registered_target_is_blocked(db):
    project = Project(name="No demo", description="")
    db.add(project); db.flush()
    scan = SecurityScan(project_id=project.id, scan_type="api_security", status="running")
    db.add(scan); db.flush()
    result = _run_demo_checks(db, scan, approve_state_changes=False)
    assert result.status == "blocked"
    assert result.findings == []
    assert "No authorized" in result.errors[0]


def test_api_security_rules_separate_confirmed_access_failure_from_header_signal(db):
    project = Project(name="Demo API security", description="")
    db.add(project); db.flush()
    target = ApiTarget(project_id=project.id, name="Demo", base_url="http://127.0.0.1:8765", authorized=True, status="ready", config={"approve_non_safe_methods": False})
    db.add(target); db.flush()
    parsed = parse_openapi(DEMO_SPEC.read_bytes(), "openapi.yaml")
    specification = ApiSpecification(target_id=target.id, openapi_version=parsed.version, title=parsed.title, source_filename="openapi.yaml", sha256=parsed.digest)
    db.add(specification); db.flush()
    for item in parsed.endpoints:
        db.add(persist_endpoint(target.id, specification.id, item))
    db.flush()
    scan = SecurityScan(project_id=project.id, scan_type="api_security", status="running")
    db.add(scan); db.flush()
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.method == "OPTIONS":
            return httpx.Response(405, headers={"Allow": "GET"})
        if "/documents/" in request.url.path:
            return httpx.Response(200, json={"requested_by": "alice", "document": {"owner": "bob", "title": "Synthetic payroll memo"}})
        return httpx.Response(200, json={"status": "ok", "service": "synthetic-demo"})

    result = _run_demo_checks(db, scan, approve_state_changes=False, transport=httpx.MockTransport(handler))
    ownership = next(item for item in result.findings if item["rule_id"].endswith(":authorization"))
    header = next(item for item in result.findings if item["rule_id"].endswith(":x-content-type-options"))
    assert ownership["status"] == "confirmed" and ownership["severity"] == "high"
    assert "no authenticated principal" in ownership["description"]
    assert ownership["details"]["scope"] == "synthetic-loopback-demo"
    assert ownership["details"]["authenticated_principal_present"] is False
    assert header["status"] == "suspected" and header["confidence"] == "low"
    assert any(method == "OPTIONS" for method, _path in calls)
    assert not any(method == "POST" for method, _path in calls)
    assert result.status == "completed_with_errors"

