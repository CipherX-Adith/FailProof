import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app.api.github import callback, status as github_status
from app.core.config import Settings
from app.services import github_import
from app.services.github_import import GitHubFailure, get_branches, get_repositories, import_snapshot, resolve_snapshot_root, safe_repo_path


def test_repo_path_allowlist_blocks_traversal_secrets_and_vendor_content():
    assert safe_repo_path("src/app.py") == "python"
    assert safe_repo_path("requirements-prod.txt") == "manifest"
    assert safe_repo_path("package-lock.json") == "manifest"
    for path in ("../secret.py", "src/../secret.py", "src//app.py", "/absolute.py", "C:/outside.py", "src\\app.py", ".env", "secrets/token.txt", "node_modules/pkg/a.py", "src/private.pem", "src/data.json"):
        assert safe_repo_path(path) is None, path


def test_repository_listing_is_paginated_and_returns_only_public_metadata(monkeypatch):
    monkeypatch.setattr(github_import, "installation_token", lambda *args, **kwargs: "server-only-token")
    page_one = [{"id": i, "owner": {"login": "octo"}, "name": f"repo-{i}", "full_name": f"octo/repo-{i}", "html_url": f"https://github.com/octo/repo-{i}", "default_branch": "main"} for i in range(1, 101)]

    def handler(request):
        assert request.headers["authorization"] == "Bearer server-only-token"
        if request.url.params["page"] == "1":
            return httpx.Response(200, json={"repositories": page_one})
        return httpx.Response(200, json={"repositories": [{"id": 101, "owner": {"login": "octo"}, "name": "last", "full_name": "octo/last", "html_url": "https://github.com/octo/last", "default_branch": "trunk"}]})

    rows = get_repositories(SimpleNamespace(installation_id=42), settings=Settings(github_import_timeout_seconds=5), transport=httpx.MockTransport(handler))
    assert len(rows) == 101
    assert rows[-1]["default_branch"] == "trunk"
    assert "token" not in rows[-1]


def test_branch_list_paginates_and_pins_sha(monkeypatch):
    monkeypatch.setattr(github_import, "installation_token", lambda *args, **kwargs: "opaque")
    sha = "a" * 40

    def handler(request):
        page = request.url.params["page"]
        if page == "1":
            rows = [{"name": f"branch-{i}", "commit": {"sha": sha}} for i in range(100)]
        else:
            rows = [{"name": "main", "commit": {"sha": sha}}]
        return httpx.Response(200, json=rows)

    result = get_branches(SimpleNamespace(installation_id=5), "octo", "repo", repository_id=8, settings=Settings(github_import_timeout_seconds=5), transport=httpx.MockTransport(handler))
    assert len(result) == 101
    assert result[-1] == {"name": "main", "commit_sha": sha}


def test_bounded_blob_import_skips_secrets_symlinks_and_submodules(tmp_path, monkeypatch):
    python = b"def handler():\n    return True\n"
    manifest = b"requests==2.31.0\n"
    sha_py, sha_req, sha_secret, sha_link = "1" * 40, "2" * 40, "3" * 40, "4" * 40
    tree = [
        {"path": "app.py", "type": "blob", "mode": "100644", "size": len(python), "sha": sha_py},
        {"path": "requirements.txt", "type": "blob", "mode": "100644", "size": len(manifest), "sha": sha_req},
        {"path": ".env", "type": "blob", "mode": "100644", "size": 12, "sha": sha_secret},
        {"path": "link.py", "type": "blob", "mode": "120000", "size": 8, "sha": sha_link},
        {"path": "submodule", "type": "commit", "mode": "160000", "size": 0, "sha": "5" * 40},
    ]
    monkeypatch.setattr(github_import, "installation_token", lambda *args, **kwargs: "opaque")

    def handler(request):
        if "/git/trees/" in request.url.path:
            return httpx.Response(200, json={"truncated": False, "tree": tree})
        content = {sha_py: python, sha_req: manifest}[request.url.path.rsplit("/", 1)[-1]]
        return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(content).decode() + "\n"})

    settings = Settings(github_import_timeout_seconds=5, github_import_max_files=10, github_import_max_total_bytes=1024, github_import_max_file_bytes=1024)
    repository = SimpleNamespace(owner="octo", name="repo", github_repository_id=12, commit_sha="a" * 40, id="snapshot", total_files=0, indexed_file_count=0, skipped_file_count=0, imported_bytes=0, supported_scan_types=[], workspace_relpath=None)
    imported = import_snapshot(SimpleNamespace(installation_id=4), repository, tmp_path / "snapshot", settings=settings, transport=httpx.MockTransport(handler))
    assert [item["relative_path"] for item in imported] == ["app.py", "requirements.txt"]
    assert repository.supported_scan_types == ["dependencies", "static"]
    assert repository.skipped_file_count == 3
    assert (tmp_path / "snapshot" / "app.py").read_bytes() == python
    assert not (tmp_path / "snapshot" / ".env").exists()
    assert all("content_sha256" in row and "blob_sha" in row for row in imported)


def test_bounded_import_enforces_total_size_and_rejects_truncated_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(github_import, "installation_token", lambda *args, **kwargs: "opaque")
    py = b"x" * 700
    sha = "f" * 40
    tree = [{"path": "a.py", "type": "blob", "mode": "100644", "size": 700, "sha": sha}, {"path": "b.py", "type": "blob", "mode": "100644", "size": 700, "sha": "e" * 40}]
    monkeypatch_response = {"truncated": False, "tree": tree}

    def handler(request):
        if "/git/trees/" in request.url.path:
            return httpx.Response(200, json=monkeypatch_response)
        return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(py).decode()})

    settings = Settings(github_import_timeout_seconds=5, github_import_max_files=10, github_import_max_total_bytes=1024, github_import_max_file_bytes=1024)
    repository = SimpleNamespace(owner="o", name="r", github_repository_id=12, commit_sha="a" * 40, id="snap", total_files=0, indexed_file_count=0, skipped_file_count=0, imported_bytes=0, supported_scan_types=[], workspace_relpath=None)
    imported = import_snapshot(SimpleNamespace(installation_id=1), repository, tmp_path / "bounded", settings=settings, transport=httpx.MockTransport(handler))
    assert len(imported) == 1
    assert repository.skipped_file_count == 1
    assert repository.status == "completed_partial"

    monkeypatch_response["truncated"] = True
    with pytest.raises(GitHubFailure, match="truncated"):
        import_snapshot(SimpleNamespace(installation_id=1), repository, tmp_path / "truncated", settings=settings, transport=httpx.MockTransport(handler))


def test_github_rate_limit_is_reported_without_leaking_response_body():
    def handler(request):
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}, json={"message": "limited"})

    monkeypatch = httpx.MockTransport(handler)
    with httpx.Client(transport=monkeypatch) as client:
        with pytest.raises(GitHubFailure, match="rate limit"):
            github_import._request(client, "GET", "/installation/repositories", "should-not-appear")


def test_github_status_is_explicit_when_app_is_not_configured(db, monkeypatch):
    from app.api import github as github_api

    monkeypatch.setattr(github_api, "get_settings", lambda: Settings())
    result = github_status(None, db)
    assert result["configured"] is False
    assert result["connected"] is False
    assert result["read_only"] is True
    assert result["message"]


def test_browser_session_must_select_one_of_its_installations(db):
    import hashlib
    from datetime import datetime, timedelta, timezone
    from fastapi import HTTPException
    from app.api.github import _connection
    from app.models import GitHubConnection

    raw = "browser-session-token"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    for installation_id in (51, 52):
        db.add(GitHubConnection(session_hash=digest, github_user_id=4, github_login="octo", installation_id=installation_id, account_login=f"account-{installation_id}", account_type="Organization", status="connected", expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
    db.commit()
    with pytest.raises(HTTPException) as ambiguous:
        _connection(db, raw)
    assert ambiguous.value.status_code == 422
    chosen = db.query(GitHubConnection).filter_by(installation_id=52).one()
    assert _connection(db, raw, chosen.id).id == chosen.id
    with pytest.raises(HTTPException) as foreign:
        _connection(db, "another-browser", chosen.id)
    assert foreign.value.status_code == 401


def test_snapshot_resolver_rejects_symlinks_and_escape(tmp_path):
    workspace = tmp_path / "workspace"
    snapshot = workspace / "snapshots" / "safe"
    snapshot.mkdir(parents=True)
    assert resolve_snapshot_root(workspace, "snapshots/safe") == snapshot.resolve()
    with pytest.raises(ValueError):
        resolve_snapshot_root(workspace, "../outside")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (workspace / "snapshots" / "linked").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available in this environment.")
    with pytest.raises(ValueError, match="symbolic link"):
        resolve_snapshot_root(workspace, "snapshots/linked")


def test_github_setup_callback_rejects_invalid_state_before_network(db, monkeypatch):
    from fastapi import HTTPException
    from app.api import github as github_api

    monkeypatch.setattr(github_api, "get_settings", lambda: Settings(github_app_id="123", github_app_slug="failproof", github_client_id="client", github_client_secret="secret", github_app_private_key_path="app.pem", github_callback_url="http://localhost:8000/api/github/callback"))
    monkeypatch.setattr(github_api, "exchange_user_authorization", lambda *args, **kwargs: pytest.fail("invalid callback state must not make a GitHub request"))
    with pytest.raises(HTTPException) as exc:
        callback(code="oauth-code", state="a" * 32, failproof_github_state="b" * 32, db=db)
    assert exc.value.status_code == 400


def test_installation_token_is_scoped_and_read_only(monkeypatch):
    monkeypatch.setattr(github_import, "_app_jwt", lambda settings: "app-jwt-not-returned-to-browser")

    def handler(request):
        assert request.url.path == "/app/installations/42/access_tokens"
        assert request.headers["authorization"] == "Bearer app-jwt-not-returned-to-browser"
        assert json.loads(request.read()) == {"permissions": {"contents": "read", "metadata": "read"}, "repository_ids": [7]}
        return httpx.Response(201, json={"token": "installation-token"})

    token = github_import.installation_token(42, repository_ids=[7], settings=Settings(github_import_timeout_seconds=5), transport=httpx.MockTransport(handler))
    assert token == "installation-token"


def test_valid_setup_callback_stores_only_hashed_session_and_uses_http_only_cookie(db, monkeypatch):
    import hashlib
    from app.api import github as github_api
    from app.models import GitHubConnection

    settings = Settings(github_app_id="123", github_app_slug="failproof", github_client_id="client", github_client_secret="secret", github_app_private_key_path="ignored-by-mock.pem", github_callback_url="http://localhost:8000/api/github/callback")
    monkeypatch.setattr(github_api, "get_settings", lambda: settings)
    monkeypatch.setattr(github_api, "exchange_user_authorization", lambda code: ({"user_id": 18, "login": "octo-user"}, [{"installation_id": 5, "account_id": 9, "account_login": "example-org", "account_type": "Organization"}]))
    state = "s" * 32
    response = callback(code="oauth-code", state=state, failproof_github_state=state, session=None, db=db)
    assert response.status_code == 303
    cookie_headers = response.headers.getlist("set-cookie")
    session_cookie = next(value for value in cookie_headers if "failproof_github_session=" in value)
    assert "HttpOnly" in session_cookie and "Path=/api" in session_cookie
    session_value = session_cookie.split("failproof_github_session=", 1)[1].split(";", 1)[0]
    row = db.query(GitHubConnection).one()
    assert row.session_hash == hashlib.sha256(session_value.encode()).hexdigest()
    assert session_value not in row.session_hash
    assert row.account_login == "example-org"
    assert row.github_login == "octo-user"


def test_oauth_exchange_filters_only_authenticated_users_app_installations(monkeypatch):
    settings = Settings(github_app_id="123", github_client_id="client", github_client_secret="secret", github_callback_url="http://localhost:8000/api/github/callback")
    seen = []

    def handler(request):
        seen.append((request.method, request.url.host, request.url.path))
        if request.url.host == "github.com":
            return httpx.Response(200, json={"access_token": "never-persist"})
        if request.url.path == "/user":
            assert request.headers["authorization"] == "Bearer never-persist"
            return httpx.Response(200, json={"id": 8, "login": "octo"})
        if request.url.path == "/user/installations":
            return httpx.Response(200, json={"installations": [
                {"id": 44, "app_id": 123, "account": {"id": 9, "login": "org", "type": "Organization"}, "permissions": {"contents": "read"}},
                {"id": 99, "app_id": 999, "account": {"id": 10, "login": "other", "type": "Organization"}, "permissions": {"contents": "read"}},
            ]})
        raise AssertionError(request.url)

    user, installs = github_import.exchange_user_authorization("oauth-code", settings=settings, transport=httpx.MockTransport(handler))
    assert user == {"user_id": 8, "login": "octo"}
    assert [item["installation_id"] for item in installs] == [44]
    assert all("never-persist" not in str(item) for item in installs)


def test_scan_source_selection_requires_connected_import_and_records_commit(db):
    from fastapi import BackgroundTasks, HTTPException
    from app.api.security import start_scan
    from app.models import GitHubConnection, GitHubRepository, Project
    from app.schemas.security import ScanCreate
    from datetime import datetime, timedelta, timezone
    import hashlib
    import secrets

    project = Project(name="GitHub source", description="")
    db.add(project); db.flush()
    raw = secrets.token_urlsafe(32)
    connection = GitHubConnection(session_hash=hashlib.sha256(raw.encode()).hexdigest(), github_user_id=1, github_login="octo", installation_id=2, account_login="octo", account_type="User", status="connected", expires_at=datetime.now(timezone.utc) + timedelta(days=2))
    db.add(connection); db.flush()
    imported = GitHubRepository(project_id=project.id, connection_id=connection.id, github_repository_id=7, owner="octo", name="demo", full_name="octo/demo", html_url="https://github.com/octo/demo", default_branch="main", selected_branch="main", commit_sha="a" * 40, status="completed", supported_scan_types=["static"])
    db.add(imported); db.commit()
    with pytest.raises(HTTPException) as exc:
        start_scan(project.id, ScanCreate(scan_type="static", source_kind="github", github_repository_id=imported.id), BackgroundTasks(), db, None)
    assert exc.value.status_code == 401
    scan = start_scan(project.id, ScanCreate(scan_type="static", source_kind="github", github_repository_id=imported.id), BackgroundTasks(), db, raw)
    assert scan.configuration == {"approve_state_changes": False, "source_kind": "github", "github_repository_id": imported.id, "github_repository": "octo/demo", "github_commit_sha": "a" * 40}
    with pytest.raises(HTTPException) as unsupported:
        start_scan(project.id, ScanCreate(scan_type="dependencies", source_kind="github", github_repository_id=imported.id), BackgroundTasks(), db, raw)
    assert unsupported.value.status_code == 422
    with pytest.raises(HTTPException) as unsupported_api:
        start_scan(project.id, ScanCreate(scan_type="api_security", source_kind="github"), BackgroundTasks(), db, raw)
    assert unsupported_api.value.status_code == 422


def test_github_provenance_supplies_only_matching_snapshot_source_and_blocks_patch(tmp_path, db, monkeypatch):
    import hashlib
    from app.services import ai_investigation as investigation_module
    from app.models import GitHubConnection, GitHubImportFile, GitHubRepository, Project, SecurityEvidence, SecurityFinding, SecurityInvestigation, SecurityScan
    from app.services.ai_investigation import InvestigationError, _source_context, create_patch_proposal

    workspace = tmp_path / "github-workspace"
    root = workspace / "snapshots" / "snapshot-id"
    root.mkdir(parents=True)
    content = "def handler():\n    return True\n"
    file_path = root / "app.py"
    file_path.write_bytes(content.encode("utf-8"))
    commit = "a" * 40
    blob = "b" * 40
    monkeypatch.setattr(investigation_module, "get_settings", lambda: Settings(github_workspace_dir=str(workspace)))
    project = Project(name="Snapshot investigation", description="")
    db.add(project); db.flush()
    connection = GitHubConnection(session_hash="c" * 64, github_user_id=7, github_login="octo", installation_id=9, account_login="octo", account_type="User", status="connected", expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    db.add(connection); db.flush()
    imported = GitHubRepository(id="snapshot-id", project_id=project.id, connection_id=connection.id, github_repository_id=77, owner="octo", name="demo", full_name="octo/demo", html_url="https://github.com/octo/demo", default_branch="main", selected_branch="main", commit_sha=commit, status="completed", workspace_relpath="snapshots/snapshot-id", supported_scan_types=["static"])
    db.add(imported); db.flush()
    digest = hashlib.sha256(content.encode()).hexdigest()
    file_record = GitHubImportFile(repository_link_id=imported.id, relative_path="app.py", blob_sha=blob, content_sha256=digest, size_bytes=len(content), file_kind="python")
    scan = SecurityScan(id="github-scan", project_id=project.id, scan_type="static", status="completed", configuration={"source_kind": "github", "github_repository_id": imported.id})
    finding = SecurityFinding(project_id=project.id, fingerprint="d" * 64, title="Static finding", description="Signal", category="static-analysis", severity="low", confidence="medium", status="suspected", source="bandit", scan_type="static", scanner="Bandit", rule_id="B101", affected_resource="app.py", remediation="Review", references=[], last_scan_id=scan.id)
    db.add_all([file_record, scan, finding]); db.flush()
    evidence = SecurityEvidence(finding_id=finding.id, scan_id=scan.id, evidence_type="scanner", details={"github_provenance": {"repository_import_id": imported.id, "repository": imported.full_name, "commit_sha": commit, "path": "app.py", "blob_sha": blob, "content_sha256": digest}}, relative_path="app.py", line_number=2, redacted=True)
    investigation = SecurityInvestigation(project_id=project.id, finding_id=finding.id, status="completed")
    db.add_all([evidence, investigation]); db.commit()
    assert db.get(GitHubRepository, imported.id).status == "completed"
    assert db.scalar(select(GitHubImportFile).where(GitHubImportFile.repository_link_id == imported.id, GitHubImportFile.relative_path == "app.py")).content_sha256 == digest
    assert resolve_snapshot_root(workspace, "snapshots/snapshot-id") == root.resolve()
    excerpts, locations = _source_context(db, finding, [evidence])
    assert excerpts and excerpts[0]["path"] == "app.py"
    assert locations[evidence.id]["absolute_path"] == str(file_path.resolve())
    evidence.details["github_provenance"]["content_sha256"] = "0" * 64
    db.flush()
    assert _source_context(db, finding, [evidence]) == ([], {})
    evidence.details["github_provenance"]["content_sha256"] = digest
    db.flush()
    with pytest.raises(InvestigationError, match="immutable review inputs"):
        create_patch_proposal(db, finding, investigation)


def test_github_scan_reconciliation_does_not_resolve_local_findings(db):
    from app.models import Project, SecurityFinding, SecurityScan
    from app.services.security_scanning import persist_issues

    project = Project(name="Reconcile scope", description="")
    db.add(project); db.flush()
    local_scan = SecurityScan(id="local-scan", project_id=project.id, scan_type="static", status="completed", configuration={"source_kind": "local"})
    github_scan = SecurityScan(id="github-scan-scope", project_id=project.id, scan_type="static", status="completed", configuration={"source_kind": "github", "github_repository_id": "repo-snapshot"})
    finding = SecurityFinding(project_id=project.id, fingerprint="e" * 64, title="Local signal", description="Existing local result", category="static-analysis", severity="low", confidence="medium", status="suspected", source="bandit", scan_type="static", scanner="Bandit", rule_id="B101", affected_resource="app.py", remediation="Review", references=[], last_scan_id=local_scan.id)
    db.add_all([local_scan, github_scan, finding]); db.commit()
    persist_issues(db, github_scan, [], reconcile=True)
    db.commit()
    assert db.get(SecurityFinding, finding.id).status == "suspected"
