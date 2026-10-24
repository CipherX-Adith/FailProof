from fastapi import BackgroundTasks, HTTPException
import pytest

from app.api.security import get_finding, get_scan, get_source, list_findings, register_source, start_scan
from app.core.config import get_settings
from app.models import Project, SecurityEvidence, SecurityFinding, SecurityScan
from app.schemas.security import ScanCreate, SourceRegistration


def test_source_registration_returns_label_but_never_full_path(db, tmp_path, monkeypatch):
    project = Project(name="Source API", description="")
    db.add(project); db.commit()
    allowed = tmp_path / "allow"
    project_dir = allowed / "checkout"
    project_dir.mkdir(parents=True)
    monkeypatch.setenv("FAILPROOF_SCAN_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    try:
        response = register_source(project.id, SourceRegistration(source_path=str(project_dir), authorized=True), db)
        assert response.source_name == "checkout"
        assert str(project_dir) not in response.model_dump_json()
        assert get_source(project.id, db).configured is True
        try:
            register_source(project.id, SourceRegistration(source_path=str(tmp_path), authorized=True), db)
            raise AssertionError("Outside paths must be rejected")
        except HTTPException as error:
            assert error.status_code == 422
    finally:
        get_settings.cache_clear()


def test_scan_routes_report_blocked_runs_and_validate_filters(db):
    project = Project(name="Scan API", description="")
    db.add(project); db.commit()
    with pytest.raises(ValueError):
        ScanCreate(scan_type="shell")
    tasks = BackgroundTasks()
    queued = start_scan(project.id, ScanCreate(scan_type="api_security"), tasks, db)
    assert queued.status == "queued"
    task = tasks.tasks[0]
    task.func(*task.args, **task.kwargs)
    db.expire_all()
    completed = get_scan(queued.id, db)
    assert completed.status == "blocked"
    assert "No authorized" in completed.errors[0]


def test_findings_endpoint_filters_and_returns_attached_evidence(db):
    project = Project(name="Findings API", description="")
    db.add(project); db.flush()
    finding = SecurityFinding(project_id=project.id, fingerprint="a" * 64, title="Observed ownership mismatch", description="Observed from a synthetic request", category="authorization", severity="high", confidence="high", status="confirmed", source="api_security", scan_type="api_security", scanner="FailProof rule", rule_id="demo:ownership", affected_resource="GET /users/{user_id}/documents/{document_id}", remediation="Enforce ownership before returning the resource.")
    db.add(finding); db.flush()
    evidence = SecurityEvidence(finding_id=finding.id, scan_id="scan-id", evidence_type="http-test", details={"response": {"owner": "synthetic-bob"}}, expected_result="403", actual_result="200", redacted=True)
    # This endpoint relationship is protected by a foreign key, so create its scan parent first.
    scan = SecurityScan(id="scan-id", project_id=project.id, scan_type="api_security", status="completed")
    db.add(scan); db.flush()
    db.add(evidence); db.commit()
    rows = list_findings(project.id, severity="high", category=None, finding_status="confirmed", source="api_security", q="ownership", limit=100, db=db)
    assert len(rows) == 1
    assert rows[0].title == finding.title
    assert rows[0].evidence[0].actual_result == "200"
    assert get_finding(finding.id, db).id == finding.id

