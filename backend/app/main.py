import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import update
from datetime import datetime, timezone

from app.api.routes import router
from app.api.api_testing import router as api_testing_router
from app.api.security import router as security_router
from app.api.investigations import router as investigations_router
from app.api.github import router as github_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.migrations import upgrade_github_connection_sessions, upgrade_patch_proposal_baseline
from app.db.session import engine
from app.db.session import SessionLocal
from app.models.security import SecurityScan
from app.models.github import GitHubRepository
from app import models  # noqa: F401 - register SQLAlchemy models before schema creation

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")
Base.metadata.create_all(bind=engine)
upgrade_patch_proposal_baseline(engine)
upgrade_github_connection_sessions(engine)

app = FastAPI(title="FailProof AI", version="0.1.0", description="Evidence-driven software verification workspace")
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type", "Idempotency-Key"])
app.include_router(router)
app.include_router(api_testing_router)
app.include_router(security_router)
app.include_router(investigations_router)
app.include_router(github_router)


@app.on_event("startup")
def recover_interrupted_scans():
    # In-process background work cannot survive a restart; make interrupted runs explicit.
    with SessionLocal() as db:
        db.execute(update(SecurityScan).where(SecurityScan.status.in_(("queued", "running"))).values(status="failed", completed_at=datetime.now(timezone.utc), errors=["Backend restarted before this scan completed."], summary="The scan was interrupted by a backend restart; no clean result is implied."))
        db.execute(update(GitHubRepository).where(GitHubRepository.status.in_(("queued", "running"))).values(status="failed", error_detail="Backend restarted before this import completed. Retry the pinned commit import."))
        db.commit()
