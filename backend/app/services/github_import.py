"""Bounded, read-only GitHub App access and snapshot importer."""
import base64
import hashlib
import re
import secrets
import time
import threading
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from app.core.config import get_settings

API = "https://api.github.com"
EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__", ".venv", "venv", ".next", ".cache"}
SECRET_NAMES = re.compile(r"(?i)(^|/)(\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|credentials?(?:\..*)?|secrets?(?:\..*)?|id_(?:rsa|ed25519|ecdsa|dsa)(?:[._-].*)?|.*\.(?:pem|key|p12|pfx|keystore|jks))$")
SECRET_CONTENT = re.compile(rb"""(?ix)(-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|"(?:private_key|client_secret)"\s*:\s*"|(?:password|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9_./+=-]{8,})""")
SUPPORTED = {"python": "static", "manifest": "dependencies"}
_SEM_LOCK = threading.Lock()
_SEMAPHORES: dict[int, threading.BoundedSemaphore] = {}


def import_semaphore(limit: int):
    with _SEM_LOCK:
        return _SEMAPHORES.setdefault(limit, threading.BoundedSemaphore(limit))


class GitHubFailure(Exception):
    pass


def _json(response: httpx.Response):
    try:
        return response.json()
    except (ValueError, TypeError) as exc:
        raise GitHubFailure("GitHub returned a malformed API response.") from exc


def safe_repo_path(value: str) -> str | None:
    if not value or "\\" in value or value.startswith("/") or "\x00" in value or re.match(r"^[A-Za-z]:", value) or any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} or ":" in part for part in path.parts) or path.is_absolute():
        return None
    if any(part.lower() in EXCLUDED_DIRS for part in path.parts[:-1]) or SECRET_NAMES.search(value):
        return None
    name = path.name
    if name.endswith(".py"):
        return "python"
    if re.fullmatch(r"requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt", name, re.I):
        return "manifest"
    if name in {"package.json", "package-lock.json"}:
        return "manifest"
    return None


def resolve_snapshot_root(workspace: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("Stored GitHub snapshot path is invalid.")
    workspace = workspace.resolve(strict=True)
    candidate = workspace / relative
    cursor = candidate
    while cursor != workspace:
        if cursor.is_symlink():
            raise ValueError("Stored GitHub snapshot path contains an unexpected symbolic link.")
        cursor = cursor.parent
        if workspace not in cursor.parents and cursor != workspace:
            raise ValueError("Stored GitHub snapshot path is outside the managed workspace.")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(workspace)
    if not resolved.is_dir():
        raise ValueError("Imported GitHub snapshot is unavailable.")
    return resolved


def _app_jwt(settings=None) -> str:
    settings = settings or get_settings()
    if not settings.github_app_id or not settings.github_app_private_key_path:
        raise GitHubFailure("GitHub App credentials are not configured on the backend.")
    key_path = Path(settings.github_app_private_key_path).expanduser().resolve()
    try:
        key = key_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GitHubFailure("The configured GitHub App private key is unavailable.") from exc
    try:
        import jwt
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": settings.github_app_id}, key, algorithm="RS256")
    except ImportError as exc:
        raise GitHubFailure("Install the backend GitHub authentication dependency before connecting GitHub.") from exc
    except Exception as exc:
        raise GitHubFailure("The configured GitHub App private key could not sign an app token.") from exc


def _message(response: httpx.Response) -> str:
    if response.status_code in (401, 403):
        if response.headers.get("X-RateLimit-Remaining") == "0" or response.headers.get("Retry-After"):
            return "GitHub rate limit reached. Wait before retrying."
        return "GitHub authorization expired, was revoked, or lacks read-only repository access. Reconnect the GitHub App."
    if response.status_code == 404:
        return "The repository or commit is no longer accessible to this installation."
    if response.status_code == 429:
        return "GitHub rate limit reached. Wait before retrying."
    return f"GitHub returned HTTP {response.status_code}. Retry later or review the GitHub App configuration."


def _request(client: httpx.Client, method: str, path: str, token: str, **kwargs):
    max_response_bytes = kwargs.pop("max_response_bytes", 2_000_000)
    try:
        with client.stream(method, f"{API}{path}", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, follow_redirects=False, **kwargs) as response:
            if not response.is_success:
                raise GitHubFailure(_message(response))
            body = bytearray()
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > max_response_bytes:
                    raise GitHubFailure("GitHub API response exceeded the configured safe response-size bound.")
                body.extend(chunk)
            return httpx.Response(response.status_code, headers=response.headers, content=bytes(body), request=response.request)
    except httpx.TimeoutException as exc:
        raise GitHubFailure("GitHub request timed out.") from exc
    except httpx.HTTPError as exc:
        raise GitHubFailure("GitHub network request failed.") from exc


def installation_token(installation_id: int, *, repository_ids: list[int] | None = None, settings=None, transport=None) -> str:
    settings = settings or get_settings()
    jwt_token = _app_jwt(settings)
    with httpx.Client(timeout=min(15, settings.github_import_timeout_seconds), transport=transport, trust_env=False) as client:
        payload = {"permissions": {"contents": "read", "metadata": "read"}}
        if repository_ids is not None:
            if not repository_ids or any(not isinstance(item, int) or item <= 0 for item in repository_ids):
                raise GitHubFailure("Installation token repository scope is invalid.")
            payload["repository_ids"] = repository_ids
        response = _request(client, "POST", f"/app/installations/{installation_id}/access_tokens", jwt_token, json=payload)
        payload = _json(response)
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise GitHubFailure("GitHub did not return an installation token.")
        return token


def check_installation(installation_id: int, *, settings=None, transport=None) -> dict:
    settings = settings or get_settings()
    jwt_token = _app_jwt(settings)
    with httpx.Client(timeout=settings.github_import_timeout_seconds, transport=transport, trust_env=False) as client:
        response = _request(client, "GET", f"/app/installations/{installation_id}", jwt_token)
        data = _json(response)
        if not isinstance(data, dict):
            raise GitHubFailure("GitHub returned malformed installation metadata.")
        return data


def exchange_user_authorization(code: str, *, settings=None, transport=None) -> tuple[dict, list[dict]]:
    """Exchange one OAuth code, verify the GitHub user, and retain only their app installs."""
    settings = settings or get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        raise GitHubFailure("GitHub App OAuth client credentials are not configured on the backend.")
    try:
        with httpx.Client(timeout=15, transport=transport, trust_env=False) as client:
            response = client.post("https://github.com/login/oauth/access_token", data={"client_id": settings.github_client_id, "client_secret": settings.github_client_secret, "code": code, "redirect_uri": settings.github_callback_url}, headers={"Accept": "application/json"}, follow_redirects=False)
            if not response.is_success or len(response.content) > 64_000:
                raise GitHubFailure("GitHub authorization code exchange failed.")
            auth = _json(response)
            token = auth.get("access_token") if isinstance(auth, dict) else None
            if not isinstance(token, str) or not token or auth.get("error"):
                raise GitHubFailure("GitHub did not accept this authorization. Reconnect and try again.")
            user = _json(_request(client, "GET", "/user", token))
            if not isinstance(user, dict) or not isinstance(user.get("id"), int) or not isinstance(user.get("login"), str):
                raise GitHubFailure("GitHub returned malformed authenticated-user metadata.")
            installations = []
            for page in range(1, 21):
                payload = _json(_request(client, "GET", "/user/installations", token, params={"per_page": 100, "page": page}))
                rows = payload.get("installations") if isinstance(payload, dict) else None
                if not isinstance(rows, list):
                    raise GitHubFailure("GitHub returned a malformed installation list.")
                for row in rows:
                    if not isinstance(row, dict) or row.get("app_id") != int(settings.github_app_id):
                        continue
                    account = row.get("account")
                    permissions = row.get("permissions")
                    if not isinstance(row.get("id"), int) or row["id"] <= 0 or not isinstance(account, dict) or not isinstance(account.get("login"), str):
                        raise GitHubFailure("GitHub returned malformed installation metadata.")
                    if not isinstance(permissions, dict) or permissions.get("contents") != "read":
                        raise GitHubFailure("GitHub App installation must grant Contents read-only permission.")
                    installations.append({"installation_id": row["id"], "account_id": int(account.get("id") or 0), "account_login": account["login"][:100], "account_type": str(account.get("type") or "User")[:32]})
                if len(rows) < 100:
                    return {"user_id": user["id"], "login": user["login"][:100]}, installations
            raise GitHubFailure("Installation list exceeded the supported pagination limit.")
    except httpx.TimeoutException as exc:
        raise GitHubFailure("GitHub authorization request timed out.") from exc
    except httpx.HTTPError as exc:
        raise GitHubFailure("GitHub authorization network request failed.") from exc


def get_repositories(connection, *, settings=None, transport=None) -> list[dict]:
    settings = settings or get_settings()
    token = installation_token(connection.installation_id, settings=settings, transport=transport)
    output = []
    with httpx.Client(timeout=settings.github_import_timeout_seconds, transport=transport, trust_env=False) as client:
        for page in range(1, 21):
            payload = _json(_request(client, "GET", "/installation/repositories", token, params={"per_page": 100, "page": page}))
            rows = payload.get("repositories") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                raise GitHubFailure("GitHub returned a malformed repository list.")
            for row in rows:
                owner = row.get("owner") if isinstance(row, dict) else None
                if not isinstance(owner, dict) or not isinstance(row.get("id"), int) or row["id"] <= 0 or not all(isinstance(row.get(key), str) for key in ("name", "full_name", "html_url")) or not isinstance(owner.get("login"), str):
                    raise GitHubFailure("GitHub returned malformed repository metadata.")
                if row["full_name"].casefold() != f"{owner['login']}/{row['name']}".casefold() or row["html_url"] != f"https://github.com/{row['full_name']}":
                    raise GitHubFailure("GitHub returned invalid repository identity metadata.")
                output.append({"id": row["id"], "owner": owner["login"][:100], "name": row["name"][:100], "full_name": row["full_name"][:201], "html_url": row["html_url"][:500], "default_branch": str(row.get("default_branch") or "")[:255]})
            if len(rows) < 100:
                return output
    raise GitHubFailure("Repository list exceeded the supported pagination limit.")


def get_branches(connection, owner: str, repo: str, *, repository_id: int, settings=None, transport=None) -> list[dict]:
    settings = settings or get_settings()
    token = installation_token(connection.installation_id, repository_ids=[repository_id], settings=settings, transport=transport)
    output = []
    with httpx.Client(timeout=min(15, settings.github_import_timeout_seconds), transport=transport, trust_env=False) as client:
        for page in range(1, 21):
            payload = _json(_request(client, "GET", f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/branches", token, params={"per_page": 100, "page": page}))
            if not isinstance(payload, list):
                raise GitHubFailure("GitHub returned a malformed branch list.")
            for row in payload:
                if not isinstance(row, dict):
                    raise GitHubFailure("GitHub returned malformed branch metadata.")
                commit = row.get("commit")
                if not isinstance(row.get("name"), str) or not isinstance(commit, dict) or not isinstance(commit.get("sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", commit["sha"]):
                    raise GitHubFailure("GitHub returned malformed branch metadata.")
                output.append({"name": row["name"][:255], "commit_sha": commit["sha"]})
            if len(payload) < 100:
                return output
    raise GitHubFailure("Branch list exceeded the supported pagination limit.")


def resolve_branch(connection, owner: str, repo: str, branch: str, *, repository_id: int, settings=None, transport=None) -> str:
    branches = get_branches(connection, owner, repo, repository_id=repository_id, settings=settings, transport=transport)
    match = next((row for row in branches if row["name"] == branch), None)
    if not match or not re.fullmatch(r"[0-9a-f]{40}", match["commit_sha"]):
        raise GitHubFailure("Selected branch is unavailable or has no valid commit SHA.")
    return match["commit_sha"]


def import_snapshot(connection, repository, destination: Path, *, settings=None, transport=None, on_progress=None) -> list[dict]:
    """Fetch tree/blob metadata at one SHA and write only bounded allowlisted text files."""
    settings = settings or get_settings()
    if not re.fullmatch(r"[0-9a-f]{40}", repository.commit_sha):
        raise GitHubFailure("Import commit is not an immutable SHA.")
    token = installation_token(connection.installation_id, repository_ids=[repository.github_repository_id], settings=settings, transport=transport)
    started, total, skipped = time.monotonic(), 0, 0
    output: list[dict] = []
    limited = False
    destination.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=min(10, settings.github_import_timeout_seconds), transport=transport, trust_env=False) as client:
        base = f"/repos/{quote(repository.owner, safe='')}/{quote(repository.name, safe='')}"
        tree = _json(_request(client, "GET", f"{base}/git/trees/{repository.commit_sha}", token, params={"recursive": "1"}, max_response_bytes=16_000_000))
        if time.monotonic() - started > settings.github_import_timeout_seconds:
            raise GitHubFailure("Repository import exceeded its processing time limit.")
        if not isinstance(tree, dict) or tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
            raise GitHubFailure("GitHub returned a truncated or malformed source tree; snapshot import stopped without a partial scan claim.")
        items = tree["tree"]
        repository.total_files = len(items)
        candidates = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "blob" or item.get("mode") not in {"100644", "100755"}:
                skipped += 1
                continue
            kind = safe_repo_path(str(item.get("path", "")))
            if not kind:
                skipped += 1
                continue
            size = item.get("size")
            if not isinstance(size, int) or size < 0 or size > settings.github_import_max_file_bytes or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("sha", ""))):
                skipped += 1
                continue
            candidates.append((item, kind))
        if len(candidates) > settings.github_import_max_files:
            skipped += len(candidates) - settings.github_import_max_files
            candidates = candidates[:settings.github_import_max_files]
            limited = True
        for item, kind in candidates:
            if time.monotonic() - started > settings.github_import_timeout_seconds:
                raise GitHubFailure("Repository import exceeded its processing time limit.")
            size = item["size"]
            if total + size > settings.github_import_max_total_bytes:
                skipped += len(candidates) - len(output)
                limited = True
                break
            blob = _json(_request(client, "GET", f"{base}/git/blobs/{item['sha']}", token))
            if time.monotonic() - started > settings.github_import_timeout_seconds:
                raise GitHubFailure("Repository import exceeded its processing time limit.")
            if not isinstance(blob, dict):
                skipped += 1
                continue
            if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
                skipped += 1
                continue
            try:
                content = base64.b64decode(blob["content"], validate=False)
            except (ValueError, TypeError):
                skipped += 1
                continue
            content = content.replace(b"\r\n", b"\n")
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue
            if len(content) != size or b"\x00" in content or SECRET_CONTENT.search(content):
                skipped += 1
                continue
            relative = str(item["path"])
            resolved = (destination / Path(*PurePosixPath(relative).parts)).resolve()
            try:
                resolved.relative_to(destination.resolve())
            except ValueError as exc:
                raise GitHubFailure("Repository tree included an unsafe path; import stopped.") from exc
            resolved.parent.mkdir(parents=True, exist_ok=True)
            # exclusive creation prevents overwriting pre-existing files/symlinks
            with resolved.open("xb") as handle:
                handle.write(content)
            total += len(content)
            row = {"relative_path": relative, "blob_sha": str(item["sha"]), "content_sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content), "file_kind": kind}
            output.append(row)
            if on_progress:
                on_progress(len(output), skipped, total)
    repository.indexed_file_count = len(output)
    repository.skipped_file_count = skipped
    repository.imported_bytes = total
    repository.supported_scan_types = sorted({SUPPORTED[row["file_kind"]] for row in output})
    repository.workspace_relpath = f"snapshots/{repository.id}"
    repository.status = "completed_partial" if limited else "completed"
    return output


def new_session_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()
