import logging
from pathlib import PurePath

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import ApiEndpoint, ApiSpecification, ApiTarget, GeneratedTest, Project, TestResult, TestRun
from app.schemas.api_testing import EndpointRead, GeneratedTestRead, RunRequest, SpecificationRead, TargetCreate, TargetRead, TestRunRead
from app.services.http_execution import DEMO_ORIGIN, execute_case
from app.services.openapi_import import MAX_SPEC_BYTES, SpecificationError, parse_openapi, persist_endpoint
from app.services.test_generation import generate_for_endpoint

router = APIRouter(prefix="/api")
audit_logger = logging.getLogger("failproof.execution")


def _require_project(db: Session, project_id: str):
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _require_target(db: Session, target_id: str):
    target = db.get(ApiTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="API target not found")
    return target


@router.post("/projects/{project_id}/targets", response_model=TargetRead, status_code=201)
def register_target(project_id: str, payload: TargetCreate, db: Session = Depends(get_db)):
    _require_project(db, project_id)
    if str(payload.base_url).rstrip("/") != DEMO_ORIGIN:
        raise HTTPException(status_code=400, detail=f"Only the controlled local demo target {DEMO_ORIGIN} is supported in this phase.")
    target = ApiTarget(project_id=project_id, name=payload.name, base_url=DEMO_ORIGIN, spec_source="upload", authorized=True, status="registered", config={"approve_non_safe_methods": payload.approve_non_safe_methods})
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/projects/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: str, db: Session = Depends(get_db)):
    _require_project(db, project_id)
    return db.scalars(select(ApiTarget).where(ApiTarget.project_id == project_id).order_by(ApiTarget.registered_at.desc())).all()


@router.post("/targets/{target_id}/specifications", response_model=SpecificationRead, status_code=201)
async def import_specification(target_id: str, request: Request, filename: str, db: Session = Depends(get_db)):
    target = _require_target(db, target_id)
    if not target.authorized or target.base_url != DEMO_ORIGIN:
        raise HTTPException(status_code=403, detail="Target is not an authorized local demo API.")
    if len(filename) > 255 or PurePath(filename).suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise HTTPException(status_code=415, detail="Upload a .json, .yaml, or .yml specification.")
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > MAX_SPEC_BYTES:
            raise HTTPException(status_code=413, detail="Specification exceeds the 1 MB upload limit.")
    raw = bytes(chunks)
    try:
        parsed = parse_openapi(raw, filename)
    except SpecificationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    spec = ApiSpecification(target_id=target.id, openapi_version=parsed.version, title=parsed.title, source_filename=PurePath(filename).name, sha256=parsed.digest)
    db.add(spec)
    db.flush()
    for item in parsed.endpoints:
        db.merge(persist_endpoint(target.id, spec.id, item))
    target.status = "ready"
    db.commit()
    db.refresh(spec)
    return spec


@router.get("/targets/{target_id}/specifications", response_model=list[SpecificationRead])
def list_specifications(target_id: str, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return db.scalars(select(ApiSpecification).where(ApiSpecification.target_id == target_id).order_by(ApiSpecification.imported_at.desc())).all()


@router.get("/targets/{target_id}/endpoints", response_model=list[EndpointRead])
def list_endpoints(target_id: str, q: str = "", method: str = "", db: Session = Depends(get_db)):
    target = _require_target(db, target_id)
    latest = db.scalar(select(ApiSpecification).where(ApiSpecification.target_id == target_id).order_by(ApiSpecification.imported_at.desc()).limit(1))
    if latest is None:
        return []
    query = select(ApiEndpoint).where(ApiEndpoint.target_id == target_id, ApiEndpoint.specification_id == latest.id)
    if q:
        query = query.where(ApiEndpoint.path.contains(q[:200]))
    if method:
        query = query.where(ApiEndpoint.method == method.upper())
    return db.scalars(query.order_by(ApiEndpoint.path, ApiEndpoint.method)).all()


@router.get("/endpoints/{endpoint_id}/tests", response_model=list[GeneratedTestRead])
def list_endpoint_tests(endpoint_id: str, db: Session = Depends(get_db)):
    if db.get(ApiEndpoint, endpoint_id) is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return db.scalars(select(GeneratedTest).where(GeneratedTest.endpoint_id == endpoint_id).order_by(GeneratedTest.category, GeneratedTest.name)).all()


@router.post("/targets/{target_id}/tests/generate", response_model=list[GeneratedTestRead])
def generate_tests(target_id: str, db: Session = Depends(get_db)):
    target = _require_target(db, target_id)
    latest = db.scalar(select(ApiSpecification).where(ApiSpecification.target_id == target_id).order_by(ApiSpecification.imported_at.desc()).limit(1))
    if latest is None:
        raise HTTPException(status_code=409, detail="Import an OpenAPI specification before generating tests.")
    endpoints = db.scalars(select(ApiEndpoint).where(ApiEndpoint.target_id == target_id, ApiEndpoint.specification_id == latest.id)).all()
    generated = []
    for endpoint in endpoints:
        for case in generate_for_endpoint(target, endpoint, endpoint.configured_rules):
            db.merge(case)
            generated.append(case)
            if len(generated) >= 500:
                break
        if len(generated) >= 500:
            break
    db.commit()
    return generated


@router.get("/targets/{target_id}/tests", response_model=list[GeneratedTestRead])
def list_tests(target_id: str, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return db.scalars(select(GeneratedTest).where(GeneratedTest.target_id == target_id).order_by(GeneratedTest.name)).all()


@router.post("/targets/{target_id}/runs", response_model=TestRunRead, status_code=201)
def run_tests(target_id: str, payload: RunRequest, db: Session = Depends(get_db)):
    target = _require_target(db, target_id)
    if not target.authorized or target.status != "ready":
        raise HTTPException(status_code=409, detail="Target must be authorized and have an imported specification.")
    cases_query = select(GeneratedTest).where(GeneratedTest.target_id == target_id)
    if payload.test_ids is not None:
        cases_query = cases_query.where(GeneratedTest.id.in_(payload.test_ids))
    cases = db.scalars(cases_query.order_by(GeneratedTest.name).limit(50)).all()
    if not cases:
        raise HTTPException(status_code=409, detail="Generate or select at least one test before execution.")
    run = TestRun(target_id=target_id, status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    endpoints = {endpoint.id: endpoint for endpoint in db.scalars(select(ApiEndpoint).where(ApiEndpoint.id.in_({case.endpoint_id for case in cases}))).all()}
    results = []
    remaining_requests = 50
    for case in cases:
        endpoint = endpoints.get(case.endpoint_id)
        request_cost = max(1, min(case.repetitions, 3))
        if request_cost > remaining_requests:
            outcome = {"state": "not-run", "error_detail": "Run request limit reached; this case was not started.", "actual_status": None, "duration_ms": None, "evidence": {}}
        elif endpoint is None:
            outcome = {"state": "error", "error_detail": "Endpoint definition is no longer available.", "actual_status": None, "duration_ms": None, "evidence": {}}
        else:
            outcome = execute_case(target, endpoint, case, run_id=run.id, approve_non_safe=payload.approve_non_safe and target.config.get("approve_non_safe_methods", False))
            remaining_requests -= request_cost
        result = TestResult(run_id=run.id, test_id=case.id, endpoint_path=endpoint.path if endpoint else "", method=endpoint.method if endpoint else "", **outcome)
        db.add(result)
        db.commit()
        results.append(result)
        audit_logger.info("API test result run=%s test=%s state=%s status=%s", run.id, case.id, result.state, result.actual_status)
    run.result_count = len(results)
    run.status = "completed"
    from datetime import datetime, timezone
    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)
    return {"id": run.id, "target_id": run.target_id, "status": run.status, "started_at": run.started_at, "completed_at": run.completed_at, "result_count": run.result_count, "results": results}


@router.get("/targets/{target_id}/runs", response_model=list[TestRunRead])
def list_runs(target_id: str, db: Session = Depends(get_db)):
    _require_target(db, target_id)
    return db.scalars(select(TestRun).where(TestRun.target_id == target_id).order_by(TestRun.started_at.desc())).all()


@router.get("/runs/{run_id}", response_model=TestRunRead)
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(TestRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Test run not found")
    results = db.scalars(select(TestResult).where(TestResult.run_id == run_id).order_by(TestResult.created_at)).all()
    return {"id": run.id, "target_id": run.target_id, "status": run.status, "started_at": run.started_at, "completed_at": run.completed_at, "result_count": run.result_count, "results": results}
