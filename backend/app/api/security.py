from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_db
from app.models import Project, ProjectScanConfig, SecurityEvidence, SecurityFinding, SecurityScan
from app.schemas.security import FindingRead, ScanCreate, ScanRead, SourceRead, SourceRegistration
from app.services.security_scanning import run_scan_job, validate_source_path
from app.api.github import SESSION_COOKIE, _connection
from app.models import GitHubRepository


router = APIRouter(prefix="/api")


def _project(db: Session, project_id: str):
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    return project


def _scan(db: Session, scan_id: str):
    scan = db.get(SecurityScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Security scan not found.")
    return scan


@router.get("/projects/{project_id}/security/source", response_model=SourceRead)
def get_source(project_id: str, db: Session = Depends(get_db)):
    _project(db, project_id)
    config = db.get(ProjectScanConfig, project_id)
    if config is None:
        return SourceRead(configured=False)
    return SourceRead(configured=True, source_name=Path(config.source_root).name, authorized=config.authorized, registered_at=config.registered_at)


@router.put("/projects/{project_id}/security/source", response_model=SourceRead)
def register_source(project_id: str, payload: SourceRegistration, db: Session = Depends(get_db)):
    _project(db, project_id)
    try:
        root = validate_source_path(payload.source_path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    config = db.get(ProjectScanConfig, project_id)
    if config is None:
        config = ProjectScanConfig(project_id=project_id, source_root=str(root), authorized=True)
        db.add(config)
    else:
        config.source_root = str(root)
        config.authorized = True
    db.commit()
    db.refresh(config)
    return SourceRead(configured=True, source_name=root.name, authorized=config.authorized, registered_at=config.registered_at)


@router.post("/projects/{project_id}/security/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def start_scan(project_id: str, payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db), session: str | None = Cookie(default=None, alias=SESSION_COOKIE)):
    _project(db, project_id)
    if payload.source_kind == "github" and payload.scan_type not in {"static", "dependencies"}:
        raise HTTPException(status_code=422, detail="GitHub snapshots support only static and dependency scans.")
    if payload.github_repository_id and (payload.source_kind != "github" or payload.scan_type not in {"static", "dependencies"}):
        raise HTTPException(status_code=422, detail="A GitHub snapshot ID is valid only for static or dependency scans that select the GitHub source.")
    configuration = {"approve_state_changes": payload.approve_state_changes, "source_kind": payload.source_kind}
    if payload.scan_type in {"static", "dependencies"} and payload.source_kind == "github":
        imported = db.get(GitHubRepository, payload.github_repository_id) if payload.github_repository_id else None
        if imported is None:
            raise HTTPException(status_code=409, detail="Select a completed GitHub snapshot owned by this connection and project.")
        connection = _connection(db, session, imported.connection_id)
        if imported is None or imported.project_id != project_id or imported.connection_id != connection.id or imported.status not in {"completed", "completed_partial"}:
            raise HTTPException(status_code=409, detail="Select a completed GitHub snapshot owned by this connection and project.")
        if payload.scan_type not in (imported.supported_scan_types or []):
            raise HTTPException(status_code=422, detail="The imported snapshot does not contain the requested scan type.")
        configuration["github_repository_id"] = imported.id
        configuration["github_repository"] = imported.full_name
        configuration["github_commit_sha"] = imported.commit_sha
    scan = SecurityScan(project_id=project_id, scan_type=payload.scan_type, status="queued", scanner_availability={}, errors=[], warnings=[], configuration=configuration, summary="Scan queued.")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    # The worker gets its own session bound to the same application/test database.
    factory = sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False)
    background_tasks.add_task(run_scan_job, scan.id, factory)
    return scan


@router.get("/projects/{project_id}/security/scans", response_model=list[ScanRead])
def list_scans(project_id: str, limit: int = Query(default=30, ge=1, le=100), db: Session = Depends(get_db)):
    _project(db, project_id)
    return db.scalars(select(SecurityScan).where(SecurityScan.project_id == project_id).order_by(SecurityScan.started_at.desc()).limit(limit)).all()


@router.get("/security/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return _scan(db, scan_id)


@router.get("/projects/{project_id}/security/findings", response_model=list[FindingRead])
def list_findings(project_id: str, severity: str | None = None, category: str | None = None, finding_status: str | None = Query(default=None, alias="status"), source: str | None = None, q: str = Query(default="", max_length=200), limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    _project(db, project_id)
    query = select(SecurityFinding).where(SecurityFinding.project_id == project_id)
    if severity:
        if severity not in {"critical", "high", "medium", "low", "informational", "unknown"}:
            raise HTTPException(status_code=422, detail="Unsupported severity filter.")
        query = query.where(SecurityFinding.severity == severity)
    if category:
        query = query.where(SecurityFinding.category == category[:40])
    if finding_status:
        if finding_status not in {"confirmed", "suspected", "not_reproduced", "verification_blocked", "resolved"}:
            raise HTTPException(status_code=422, detail="Unsupported finding status filter.")
        query = query.where(SecurityFinding.status == finding_status)
    if source:
        query = query.where(SecurityFinding.source == source[:32])
    if q:
        needle = f"%{q[:200]}%"
        query = query.where(SecurityFinding.title.ilike(needle) | SecurityFinding.description.ilike(needle) | SecurityFinding.affected_resource.ilike(needle))
    findings = db.scalars(query.order_by(SecurityFinding.last_observed_at.desc()).limit(limit)).all()
    for finding in findings:
        finding.evidence = db.scalars(select(SecurityEvidence).where(SecurityEvidence.finding_id == finding.id).order_by(SecurityEvidence.created_at.desc()).limit(5)).all()
    return findings


@router.get("/security/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(SecurityFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    finding.evidence = db.scalars(select(SecurityEvidence).where(SecurityEvidence.finding_id == finding.id).order_by(SecurityEvidence.created_at.desc()).limit(100)).all()
    return finding
