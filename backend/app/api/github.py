import hashlib
import hmac
import shutil
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import get_db
from app.models import GitHubConnection, GitHubImportFile, GitHubRepository, Project
from app.services.github_import import GitHubFailure, exchange_user_authorization, get_branches, get_repositories, import_semaphore, import_snapshot, new_session_token, resolve_branch, resolve_snapshot_root

router = APIRouter(prefix="/api/github", tags=["GitHub repository import"])
STATE_COOKIE, SESSION_COOKIE = "failproof_github_state", "failproof_github_session"


def _expired(value: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= datetime.now(timezone.utc)


class ImportCreate(BaseModel):
    repository_id: int = Field(gt=0)
    branch: str = Field(min_length=1, max_length=255)
    connection_id: str = Field(min_length=36, max_length=36)


def _configured() -> bool:
    s = get_settings()
    return bool(re.fullmatch(r"\d+", s.github_app_id or "") and re.fullmatch(r"[A-Za-z0-9-]+", s.github_app_slug or "") and s.github_client_id and s.github_client_secret and s.github_app_private_key_path and s.github_callback_url)


def _origin(request: Request):
    origin = request.headers.get("origin")
    if not origin or origin.rstrip("/") != get_settings().frontend_origin.rstrip("/"):
        raise HTTPException(403, "Request origin is missing or does not match the configured local frontend.")


def _connection(db: Session, session_cookie: str | None, connection_id: str | None = None) -> GitHubConnection:
    if not session_cookie:
        raise HTTPException(401, "Connect the GitHub App before using repository import.")
    digest = hashlib.sha256(session_cookie.encode()).hexdigest()
    query = select(GitHubConnection).where(GitHubConnection.session_hash == digest, GitHubConnection.status == "connected")
    if connection_id:
        query = query.where(GitHubConnection.id == connection_id)
    rows = list(db.scalars(query).all())
    rows = [item for item in rows if not _expired(item.expires_at)]
    if len(rows) > 1:
        raise HTTPException(422, "Select a GitHub installation before continuing.")
    row = rows[0] if rows else None
    if row is None:
        raise HTTPException(401, "GitHub connection expired. Connect the GitHub App again.")
    return row


def _github_error(exc: GitHubFailure):
    message = str(exc)
    status = 503 if "not configured" in message.lower() or "dependency" in message.lower() else 429 if "rate limit" in message.lower() else 502
    raise HTTPException(status, message) from exc


@router.get("/status")
def status(session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    settings = get_settings()
    connections = []
    if session:
        digest = hashlib.sha256(session.encode()).hexdigest()
        connections = [c for c in db.scalars(select(GitHubConnection).where(GitHubConnection.session_hash == digest, GitHubConnection.status == "connected")).all() if not _expired(c.expires_at)]
    return {"configured": _configured(), "connected": bool(connections), "installations": [{"id": c.id, "installation_id": c.installation_id, "login": c.account_login, "type": c.account_type} for c in connections], "login": connections[0].github_login if connections else None, "account": connections[0].account_login if len(connections) == 1 else None, "app_slug": settings.github_app_slug if _configured() else None, "read_only": True, "permissions": ["contents:read", "metadata:read"], "message": None if _configured() else "GitHub App OAuth and installation credentials are not configured on the backend."}


@router.get("/connect")
def connect(response: Response):
    settings = get_settings()
    if not _configured():
        raise HTTPException(503, "GitHub App integration is not configured on the backend.")
    state = new_session_token()[0]
    response = RedirectResponse(f"https://github.com/login/oauth/authorize?{urlencode({'client_id': settings.github_client_id, 'redirect_uri': settings.github_callback_url, 'state': state, 'allow_signup': 'false'})}", status_code=302)
    response.set_cookie(STATE_COOKIE, state, httponly=True, secure=settings.github_callback_url.startswith("https://"), samesite="lax", max_age=600, path="/api/github")
    return response


@router.get("/callback")
def callback(code: str = Query(min_length=1, max_length=512), state: str = Query(min_length=20, max_length=200), failproof_github_state: str | None = Cookie(default=None, alias=STATE_COOKIE), session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    settings = get_settings()
    if not _configured() or not settings.github_callback_url:
        raise HTTPException(503, "GitHub App integration is not configured on the backend.")
    if not failproof_github_state or not hmac.compare_digest(state, failproof_github_state):
        raise HTTPException(400, "GitHub setup state is invalid or expired. Restart the connection flow.")
    try:
        user, installations = exchange_user_authorization(code)
    except GitHubFailure as exc:
        _github_error(exc)
    if not installations:
        if session:
            digest = hashlib.sha256(session.encode()).hexdigest()
            for row in db.scalars(select(GitHubConnection).where(GitHubConnection.session_hash == digest, GitHubConnection.status == "connected")).all():
                row.status = "disconnected"
            db.commit()
        target = RedirectResponse(f"{settings.frontend_origin}?github=install_required", status_code=303)
        target.delete_cookie(STATE_COOKIE, path="/api/github")
        return target
    if session:
        digest = hashlib.sha256(session.encode()).hexdigest()
        browser_token = session
    else:
        browser_token, digest = new_session_token()
    existing = {row.installation_id: row for row in db.scalars(select(GitHubConnection).where(GitHubConnection.session_hash == digest)).all()}
    ids = {int(item["installation_id"]) for item in installations}
    for row in existing.values():
        if row.installation_id not in ids:
            row.status = "disconnected"
    for item in installations:
        row = existing.get(int(item["installation_id"]))
        if row is None:
            row = GitHubConnection(session_hash=digest, installation_id=item["installation_id"], github_user_id=user["user_id"], github_login=user["login"], account_login=item["account_login"], account_type=item["account_type"], status="connected", expires_at=datetime.now(timezone.utc) + timedelta(days=14))
            db.add(row)
        else:
            row.github_user_id=user["user_id"]; row.github_login=user["login"]; row.account_login=item["account_login"]; row.account_type=item["account_type"]; row.status="connected"; row.expires_at=datetime.now(timezone.utc) + timedelta(days=14)
    db.commit()
    target = RedirectResponse(settings.frontend_origin, status_code=303)
    secure = settings.github_callback_url.startswith("https://")
    target.delete_cookie(STATE_COOKIE, path="/api/github")
    target.set_cookie(SESSION_COOKIE, browser_token, httponly=True, secure=secure, samesite="lax", max_age=14 * 24 * 3600, path="/api")
    return target


@router.get("/repositories")
def repositories(connection_id: str | None = Query(default=None), session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    connection = _connection(db, session, connection_id)
    try:
        return get_repositories(connection)
    except GitHubFailure as exc:
        _github_error(exc)


@router.get("/repositories/{repository_id}/branches")
def branches(repository_id: int, owner: str = Query(min_length=1, max_length=100), name: str = Query(min_length=1, max_length=100), connection_id: str | None = Query(default=None), session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    connection = _connection(db, session, connection_id)
    try:
        meta = next((repo for repo in get_repositories(connection) if int(repo["id"]) == repository_id), None)
        if not meta or meta["owner"].casefold() != owner.casefold() or meta["name"].casefold() != name.casefold():
            raise HTTPException(403, "Repository is not accessible to this GitHub installation.")
        return get_branches(connection, owner, name, repository_id=repository_id)
    except GitHubFailure as exc:
        _github_error(exc)


def _run_import(repository_id: str, factory):
    db = factory()
    row = None
    destination = None
    created_destination = False
    semaphore = None
    acquired = False
    try:
        row = db.get(GitHubRepository, repository_id)
        if row is None or row.status != "queued":
            return
        row.status = "running"; db.commit()
        connection = db.get(GitHubConnection, row.connection_id)
        if connection is None or connection.status != "connected" or _expired(connection.expires_at):
            raise GitHubFailure("GitHub installation is no longer connected. Reconnect and retry.")
        settings = get_settings()
        semaphore = import_semaphore(settings.github_import_concurrency)
        acquired = semaphore.acquire(blocking=False)
        if not acquired:
            raise GitHubFailure("The configured concurrent GitHub import limit has been reached. Retry when another import finishes.")
        workspace = Path(settings.github_workspace_dir or (Path(__file__).resolve().parents[3] / ".failproof" / "github")).expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        if workspace.is_symlink():
            raise GitHubFailure("Managed GitHub workspace cannot be a symbolic link.")
        snapshots = workspace / "snapshots"
        if snapshots.is_symlink():
            raise GitHubFailure("Managed GitHub snapshot directory cannot be a symbolic link.")
        snapshots.mkdir(exist_ok=True)
        destination = workspace / "snapshots" / row.id
        # New snapshot IDs are unique and must not alias existing user data.
        if destination.exists():
            raise GitHubFailure("Import destination already exists; refusing to overwrite existing files.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir()
        created_destination = True
        def report_progress(indexed, skipped, total):
            row.indexed_file_count = indexed
            row.skipped_file_count = skipped
            row.imported_bytes = total
            db.commit()

        files = import_snapshot(connection, row, destination, settings=settings, on_progress=report_progress)
        row.workspace_relpath = str(destination.relative_to(workspace)).replace("\\", "/")
        db.add_all(GitHubImportFile(repository_link_id=row.id, **item) for item in files)
        row.status = row.status if row.status == "completed_partial" else "completed" if row.supported_scan_types else "unsupported"
        row.imported_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:
        db.rollback()
        if created_destination and destination is not None:
            try:
                shutil.rmtree(destination)
            except OSError:
                pass
        row = db.get(GitHubRepository, repository_id)
        if row is not None:
            row.status = "failed"
            row.error_detail = str(exc)[:1000] if isinstance(exc, GitHubFailure) else "Repository import failed due to an internal error."
            db.commit()
    finally:
        if acquired and semaphore is not None:
            semaphore.release()
        db.close()


@router.post("/projects/{project_id}/imports", status_code=202)
def create_import(project_id: str, payload: ImportCreate, request: Request, background: BackgroundTasks, session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    _origin(request)
    connection = _connection(db, session, payload.connection_id)
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found.")
    try:
        repos = get_repositories(connection)
        meta = next((item for item in repos if int(item["id"]) == payload.repository_id), None)
        if not meta:
            raise HTTPException(403, "Repository is not accessible to this GitHub installation.")
        sha = resolve_branch(connection, meta["owner"], meta["name"], payload.branch, repository_id=payload.repository_id)
    except GitHubFailure as exc:
        _github_error(exc)
    existing = db.scalar(select(GitHubRepository).where(GitHubRepository.project_id == project_id, GitHubRepository.connection_id == connection.id, GitHubRepository.github_repository_id == payload.repository_id, GitHubRepository.commit_sha == sha))
    if existing:
        if existing.status in {"failed", "unsupported"}:
            existing.status = "queued"; existing.error_detail = None
            db.commit()
            background.add_task(_run_import, existing.id, _factory(db))
        return existing
    row = GitHubRepository(project_id=project_id, connection_id=connection.id, github_repository_id=payload.repository_id, owner=meta["owner"], name=meta["name"], full_name=meta["full_name"], html_url=meta["html_url"], default_branch=meta["default_branch"], selected_branch=payload.branch, commit_sha=sha, status="queued")
    db.add(row); db.commit(); db.refresh(row)
    background.add_task(_run_import, row.id, _factory(db))
    return row


def _factory(db):
    return sessionmaker(bind=db.get_bind(), autoflush=False, autocommit=False)


@router.get("/projects/{project_id}/imports")
def project_imports(project_id: str, session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    if db.get(Project, project_id) is None:
        raise HTTPException(404, "Project not found.")
    if not session:
        raise HTTPException(401, "Connect the GitHub App before using repository import.")
    digest = hashlib.sha256(session.encode()).hexdigest()
    ids = select(GitHubConnection.id).where(GitHubConnection.session_hash == digest, GitHubConnection.status == "connected")
    return db.scalars(select(GitHubRepository).where(GitHubRepository.project_id == project_id, GitHubRepository.connection_id.in_(ids)).order_by(GitHubRepository.created_at.desc()).limit(100)).all()


@router.post("/projects/{project_id}/imports/{repository_import_id}/retry", status_code=202)
def retry_import(project_id: str, repository_import_id: str, request: Request, background: BackgroundTasks, connection_id: str = Query(min_length=36, max_length=36), session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    _origin(request); connection = _connection(db, session, connection_id)
    row = db.get(GitHubRepository, repository_import_id)
    if row is None or row.project_id != project_id or row.connection_id != connection.id:
        raise HTTPException(404, "Repository import not found.")
    if row.status not in {"failed", "unsupported"}:
        raise HTTPException(409, "Only failed or unsupported imports can be retried.")
    row.status = "queued"; row.error_detail = None; db.commit()
    background.add_task(_run_import, row.id, _factory(db))
    return row


@router.delete("/projects/{project_id}/imports/{repository_import_id}", status_code=204)
def remove_import(project_id: str, repository_import_id: str, request: Request, connection_id: str = Query(min_length=36, max_length=36), session: str | None = Cookie(default=None, alias=SESSION_COOKIE), db: Session = Depends(get_db)):
    _origin(request); connection = _connection(db, session, connection_id)
    row = db.get(GitHubRepository, repository_import_id)
    if row is None or row.project_id != project_id or row.connection_id != connection.id:
        raise HTTPException(404, "Repository import not found.")
    if row.status in {"queued", "running"}:
        raise HTTPException(409, "Wait for the active import to finish before removing it.")
    settings = get_settings()
    workspace = Path(settings.github_workspace_dir or (Path(__file__).resolve().parents[3] / ".failproof" / "github")).expanduser().resolve()
    if row.workspace_relpath:
        try:
            target = resolve_snapshot_root(workspace, row.workspace_relpath)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(409, "Stored import path is unavailable or outside the managed GitHub workspace.") from exc
        shutil.rmtree(target)
    db.delete(row); db.commit()
    return Response(status_code=204)
