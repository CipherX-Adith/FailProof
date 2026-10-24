# FailProof AI

FailProof AI is an evidence-driven software engineering and security workspace. Its guiding principle is: **AI proposes. Execution proves. Evidence verifies.** The current workbench supports API discovery and deterministic verification, with an evidence-backed Security Center for explicitly authorized local source and bundled-demo scans.

## Architecture

- `frontend/`: React, TypeScript, Vite, Tailwind CSS, and a purpose-built responsive workbench. The Vite development server proxies `/api` to FastAPI.
- `backend/app/api`: REST routes; `schemas`: validated Pydantic contracts; `services`: OpenAPI import, deterministic test generation, and bounded HTTP execution; `models` and `db`: SQLAlchemy persistence; `core`: environment configuration.
- `backend/tests`: route and persistence tests using an isolated in-memory SQLite database.
- SQLite schema initialization currently uses SQLAlchemy `Base.metadata.create_all` at application startup. This is documented and suitable for the initial schema; introduce Alembic before evolving deployed schemas.
- Security scanning is an optional, bounded adapter layer. Static analysis uses Bandit; Python advisories use pip-audit; JavaScript advisories use `npm audit` against the existing lockfile; API and business checks use the existing HTTPX executor and bundled loopback demo.
- Findings and evidence are persisted with scan history. Scanner signals are classified as suspected or confirmed according to what was actually observed. A blocked, failed, partial, or unavailable scan never means “clean.”
- Optional AI investigation uses a backend-only Google Gemini adapter (official `google-genai` SDK) or the retained OpenAI-compatible adapter. AI hypotheses, proposed tests, approved proposals, executor results, and reviewable patch diffs are stored separately. AI never changes a finding's confirmation status.

## Prerequisites

- Python 3.10 or newer
- Node.js 20 or newer and npm

## Install

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
python -m pip install -r backend/requirements-security.txt
cd frontend
npm install
```

The frontend uses its Vite proxy during local development. No secrets belong in frontend environment variables.

The verified Python dependency constraints are FastAPI `>=0.162.0,<0.163`, Starlette `>=1.3.1,<2.0`, and pytest `>=9.1.1,<10.0`. The Starlette upper bound is paired with the FastAPI release metadata and tested together; do not override it independently. Recreate or update the backend environment after changing requirements.

## Configure

Edit `.env` for local backend settings. `DATABASE_URL` defaults to `sqlite:///./failproof.db`; `FRONTEND_ORIGIN` defaults to `http://localhost:5173`. Set `FAILPROOF_SCAN_ALLOWED_ROOTS` to directories the backend operator authorizes for local scans (semicolon-separated on Windows, colon-separated on POSIX). The Security Center additionally requires an explicit per-project source authorization and rejects directories outside these roots. `FAILPROOF_SCAN_TEMP_DIR` can point to a writable local temp directory. Keep credentials out of source control and logs. No API keys are needed.

AI investigation is optional. For Gemini, set `FAILPROOF_AI_PROVIDER=gemini`, `GEMINI_API_KEY`, and `GEMINI_MODEL=gemini-3.8-flash` in the repository-root `.env`. The backend uses Google's official `google-genai` Python SDK and checks the configured model with a read-only model lookup before reporting Gemini as connected. The key is sent only by the backend and is never returned by the API or sent to the frontend. If `.env` already exists, keep it and edit only those settings; never replace the file with `.env.example`. The `.env.example` contains placeholders only. Rotate any Gemini key exposed in chat or screenshots before entering its replacement locally. If using the retained OpenAI-compatible adapter instead, configure `FAILPROOF_AI_PROVIDER=openai-compatible`, `FAILPROOF_AI_BASE_URL`, `FAILPROOF_AI_MODEL`, and `FAILPROOF_AI_API_KEY`. The deterministic scripted mock remains separately labeled `failproof-demo-mock`; provider errors never fall back to mock results. `FAILPROOF_AI_TIMEOUT_SECONDS` and `FAILPROOF_AI_MAX_RESPONSE_BYTES` bound investigation calls. Provider use may incur charges; check Google AI Studio/provider terms before enabling it. The configured default `gemini-3.8-flash` is a current stable model in Google's Gemini model catalog; model availability may depend on the API project.

The backend reads the repository-root `.env` whether it is launched from the repository root or `backend`. In PowerShell, open the existing file locally with `notepad .env`, set the Gemini provider and model, and enter a rotated key on the `GEMINI_API_KEY=` line. Do not place the key in frontend configuration, source files, or command history.

Vite's API proxy defaults to `http://127.0.0.1:8000`. For a different local backend port, set `FAILPROOF_API_PROXY_TARGET` in the frontend process environment before starting Vite. This is a development setting; production reverse-proxy behavior is not configured here.

## Start the backend

From the repository root:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check: `GET http://127.0.0.1:8000/api/health`. Interactive API documentation is at `/docs`.

## Start the frontend

In a second terminal:

```powershell
cd frontend
npm run dev
```

Open the URL printed by Vite (normally `http://localhost:5173`). Create a project from the toolbar; it is persisted in SQLite and appears in the project explorer and overview.

### Gemini live smoke test

With the rotated key configured in the backend `.env` and the backend virtual environment active, run a single small structured generation request from the repository root:

```powershell
cd backend
python -m app.gemini_smoke
```

The command prints only whether the request succeeded and the returned provider/model. It never prints the key. A success confirms one live Gemini request; unit tests and the provider status model lookup do not constitute this generation smoke test. A key or model failure, quota/rate limit, timeout, malformed response, or network error is reported without mock fallback.

The backend install includes Google's official SDK documented at [Google Gen AI Python SDK](https://googleapis.github.io/python-genai/). The default model is listed in the [Gemini API model catalog](https://ai.google.dev/gemini-api/docs/models).

## API Explorer and bundled demo

Select a project and open **API Explorer**. Registering a target requires explicit authorization and is currently limited by the backend to the bundled demo at `http://127.0.0.1:8765`. OpenAPI files are uploaded directly (maximum 1 MiB); the server does not fetch specification URLs. JSON and YAML OpenAPI 3.0.x/3.1.x are supported. YAML aliases, external references, and parameter/request-body/response references are rejected; local schema references are resolved during discovery.

Start the intentionally vulnerable, synthetic demo API in a third terminal from the repository root, using the project virtual environment:

```powershell
$env:FAILPROOF_DEMO_ENABLED = '1'
python -m uvicorn demo_api.app:app --host 127.0.0.1 --port 8765
```

The demo refuses to start unless `FAILPROOF_DEMO_ENABLED=1`, binds only to loopback in this command, and rejects non-loopback clients. Its default SQLite file is `demo_api/demo.sqlite3` and contains synthetic records only. Do not expose the demo service to a network. To reset its state, stop the server and remove that SQLite file.

Upload `demo_api/openapi.yaml` in API Explorer. Review generated cases before running them. Safe methods can run after target authorization. POST/PUT/PATCH/DELETE cases are blocked unless the target was registered with the explicit non-safe-method approval and the operator separately approves those methods for the run. Each run is limited to 50 requests, runs sequentially, times out each request after 3 seconds, caps request/response bodies at 64 KiB, disables redirects and environment proxy use, and records sanitized evidence. Credentials, cookie parameters, and sensitive headers are not supported. The executor will only connect to the fixed demo loopback address.

The demo intentionally contains synthetic defects exercised by the specification: a too-short validation code is accepted, a required field is optional at runtime, document ownership is not checked, and duplicate captures are accepted. This is a local demonstration, not a security test target for production data.

### Ownership-rule reproduction

The imported rule sends `GET /users/alice/documents/bob-private` and expects `403`. The observed demo response is `200` with `requested_by: alice` and the synthetic document whose `owner` is `bob`. The demo route deliberately ignores the stored owner, so this is a confirmed violation of the synthetic OpenAPI rule and the response discloses the fixture record. The route has no authentication or caller identity context, however, so the run does not establish access by an authenticated unauthorized user in a production service. The secure contract behavior is to derive the caller identity from trusted authentication context, compare it with the document owner, and return a denial without disclosing the document. The 9 state-changing cases that are blocked without per-run and target approval are not vulnerabilities.

### Repeatable local evidence demo

Use separate terminals from the repository root. This walkthrough uses only the bundled synthetic demo and the explicitly allowlisted scanner fixture.

1. Start the synthetic API using the commands above.
2. In the backend terminal, set the fixture allowlist and local mock provider before starting FastAPI:

   ```powershell
   $env:FAILPROOF_SCAN_ALLOWED_ROOTS = (Resolve-Path .\backend\tests\fixtures\security).Path
   $env:FAILPROOF_AI_PROVIDER = 'openai-compatible'
   $env:FAILPROOF_AI_BASE_URL = 'http://127.0.0.1:8766/v1'
   $env:FAILPROOF_AI_MODEL = 'failproof-demo-mock'
   $env:FAILPROOF_AI_API_KEY = 'local-demo-only'
   cd backend
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

   In another terminal, run `cd frontend; npm run dev` and create a project in the UI.
3. In API Explorer, authorize the bundled loopback target, import `demo_api/openapi.yaml`, generate the deterministic cases, and run the safe `GET /health` case. The run and sanitized response are stored in history.
4. In Security Center, register the same fixture directory and authorize its bounded scan. Run **Static analysis** to observe the actual Bandit findings, then open a finding and inspect its evidence. Run **API security** to reproduce the ownership contract mismatch; unsafe state-changing checks remain blocked unless separately approved.
5. Start the local scripted mock in a fourth terminal: `python -m uvicorn demo_api.mock_ai_provider:app --host 127.0.0.1 --port 8766`. Return to the UI and investigate the Bandit finding. The mock is loopback-only and returns visibly labeled scripted examples; it is not a live model and its hypothesis, proposed test, and patch are not security conclusions.
6. The UI labels this provider as **Scripted mock results** and labels each investigation as a mock result. Review the mock test proposal and diff. The diff is a deliberately limited example that warns shell=False can change string-command behavior. It is never applied. Patch approval and application remain unavailable until isolated application and baseline preservation exist.

The mock provider does not use a real API key and makes no outbound requests. Its `local-demo-only` value is a placeholder. Do not reuse it with a hosted provider.

### Safe API smoke test

With the backend and bundled demo running, this PowerShell example creates a project, registers only the loopback demo, imports the bundled contract, generates deterministic tests, and executes exactly one `GET /health` case. It does not enable or run state-changing methods:

```powershell
$base = 'http://127.0.0.1:8000/api'
$project = Invoke-RestMethod -Method Post -Uri "$base/projects" -ContentType 'application/json' -Body (@{name='Local smoke test';description='Synthetic demo only'} | ConvertTo-Json)
$target = Invoke-RestMethod -Method Post -Uri "$base/projects/$($project.id)/targets" -ContentType 'application/json' -Body (@{name='Bundled demo';base_url='http://127.0.0.1:8765';authorized=$true;approve_non_safe_methods=$false} | ConvertTo-Json)
$spec = Get-Content .\demo_api\openapi.yaml -Raw
Invoke-WebRequest -Method Post -Uri "$base/targets/$($target.id)/specifications?filename=openapi.yaml" -ContentType 'application/yaml' -Body $spec | Out-Null
Invoke-RestMethod -Method Post -Uri "$base/targets/$($target.id)/tests/generate" | Out-Null
$health = Invoke-RestMethod -Uri "$base/targets/$($target.id)/endpoints?method=GET&q=%2Fhealth" | Select-Object -First 1
$cases = Invoke-RestMethod -Uri "$base/endpoints/$($health.id)/tests"
$safeCase = $cases | Where-Object { $_.category -eq 'valid' } | Select-Object -First 1
if (-not $safeCase) { throw 'No deterministic safe GET /health case was generated.' }
$run = Invoke-RestMethod -Method Post -Uri "$base/targets/$($target.id)/runs" -ContentType 'application/json' -Body (@{test_ids=@($safeCase.id);approve_non_safe=$false} | ConvertTo-Json)
$run | ConvertTo-Json -Depth 8
```

The returned run includes the actual HTTP result and recorded evidence. A blocked or failed result is not a pass.

### Scan and inspect evidence

Install the optional scanner tools with `python -m pip install -r backend/requirements-security.txt`. Start the backend with `FAILPROOF_SCAN_ALLOWED_ROOTS` set to the fixture directory shown above. Then register that same directory for the project and run Bandit from PowerShell (using the `$project` created in the safe API smoke test above):

```powershell
$base = 'http://127.0.0.1:8000/api'
$source = (Resolve-Path .\backend\tests\fixtures\security).Path
Invoke-RestMethod -Method Put -Uri "$base/projects/$($project.id)/security/source" -ContentType 'application/json' -Body (@{source_path=$source;authorized=$true} | ConvertTo-Json) | Out-Null
$scan = Invoke-RestMethod -Method Post -Uri "$base/projects/$($project.id)/security/scans" -ContentType 'application/json' -Body (@{scan_type='static'} | ConvertTo-Json)
do { Start-Sleep -Milliseconds 500; $scan = Invoke-RestMethod -Uri "$base/security/scans/$($scan.id)" } while ($scan.status -in @('queued','running'))
$findings = Invoke-RestMethod -Uri "$base/projects/$($project.id)/security/findings?source=bandit"
$findings | Select-Object id,title,severity,status,affected_resource
$findingId = ($findings | Select-Object -First 1).id
Invoke-RestMethod -Uri "$base/security/findings/$findingId" | ConvertTo-Json -Depth 10
```

The finding detail includes the persisted evidence records and source locations. The UI's Security Center also lists scan summaries, findings, and evidence. Dependency scans use `scan_type='dependencies'`; advisory scans may need network access to pip-audit or npm audit services and report unavailable or incomplete results when those services cannot be reached.

## Security Center and scan scope

Open **Security Center** for a project. Registering a source requires checking the authorization box, and the backend must also have that directory beneath `FAILPROOF_SCAN_ALLOWED_ROOTS`. Source files are copied to a temporary staging directory for Bandit; symlinked directories, common generated/vendor folders, oversized files, and excess file counts are excluded. Dependency scans read local `requirements*.txt` and `package-lock.json` files. pip-audit and npm audit query their advisory services; network errors or missing tools are reported as blocked/incomplete. The app does not install or update dependencies when a scan runs.

Bandit reports code patterns, not exploitability, so its results are suspected. Advisory database matches are confirmed matches for a package/version, not proof that the application is exploitable. API checks and synthetic business rules only target the separately authorized bundled loopback API; state-changing checks need both target configuration and a per-run approval. No arbitrary host, repository URL, or production target is scanned.

Every scan records its status, tool availability, summary, warnings/errors, findings, and evidence. Findings retain first/last-seen data and stable fingerprints; they resolve only after a complete scan of the same category no longer reports them. Evidence redacts common secret-shaped values and is size bounded. Static/dependency scans are read-only. The deterministic demo checks can create only synthetic demo records.

Install optional scanner tools with `python -m pip install -r backend/requirements-security.txt`. If a tool is not installed, its scan reports that limitation rather than returning a clean result. On first startup, `create_all` adds the scan tables to the configured database; there is no destructive database reset. This project does not yet have Alembic migrations, authentication, a multi-user authorization model, arbitrary target support, Semgrep, or automated AI code remediation.

Security API: source registration at `GET/PUT /api/projects/{project_id}/security/source`; start/list scans at `POST/GET /api/projects/{project_id}/security/scans`; inspect a scan at `GET /api/security/scans/{scan_id}`; list/filter findings at `GET /api/projects/{project_id}/security/findings`; and inspect finding evidence at `GET /api/security/findings/{finding_id}`.

## AI investigation and proposal workflow

Select a real persisted finding and choose **Investigate finding**. The backend sends only that finding's metadata, up to ten sanitized evidence records, related scan summaries, and a small excerpt around an evidence-linked source line when the registered directory is still authorized. Context is size bounded. Source code, scanner text, and response bodies are explicitly treated as untrusted data. The system validates evidence IDs and source locations returned by the model; unverified references are labeled and cannot become source facts. AI confidence is explanatory only and never confirms, resolves, or changes the finding.

The provider may propose bounded tests. Manual proposals remain review-only. API proposals must map to a currently authorized endpoint on the bundled loopback demo, use declared path/query parameters, and cite finding evidence. Tests are saved separately from the existing executable test records. A user must approve a proposal; state-changing methods additionally require the existing target-level approval and a per-run approval. The existing bounded HTTP executor records the actual status, response evidence, and run independently of the model's expectation. Unsupported methods and targets remain unexecutable proposals.

For evidence-linked source-code findings, the provider may propose a unified diff. The server rejects traversal, absolute paths, symlinks escaping the authorized directory, unrelated files/hunks, binary patches, secret-shaped text, and oversized output. A fixed `git apply --check` applicability check is read-only and runs against the currently authorized source directory. The exact UTF-8 diff bytes are passed to Git so Windows text-mode newline conversion cannot corrupt LF hunk lines; proposals created by the earlier text-mode check may retain `not-applicable`, so regenerate them to check again. Proposal records fingerprint the authorized root, source-file bytes, and diff; detail/list reads mark proposals stale if the root, source, or diff changes (or if a legacy record has no baseline). **Patch approval, application, isolated worktrees/copies for application, and regression verification are unavailable.** Approval and application routes refuse the operation until safe isolated application and baseline preservation exist. A generated diff or successful applicability check is not an applied or verified repair.

The API exposes provider status at `GET /api/ai/status`; investigation creation/history/detail at `POST /api/security/findings/{finding_id}/investigations`, `GET /api/security/findings/{finding_id}/investigations`, and `GET /api/security/investigations/{investigation_id}`; test proposal generation/list/decision/execution beneath `/api/security/investigations/{investigation_id}/test-proposals` and `/api/security/test-proposals/{proposal_id}`; and patch generation/list/detail/decision/apply/verification beneath `/api/security/investigations/{investigation_id}/patch-proposals`, `/api/security/findings/{finding_id}/patch-proposals`, and `/api/security/patch-proposals/{proposal_id}`. Creation routes accept `Idempotency-Key` for safe client retries.

This project has no user authentication or multi-user approval identity. The approval endpoints are explicit workflow state, not identity enforcement. Keep the backend local and restrict access to trusted operators.

Phase 2 records targets, imported specifications, discovered endpoints, generated cases, runs, and results in the existing SQLite database. Startup uses `create_all` plus a small idempotent additive migration for patch baseline columns; this does not replace a production migration framework. Add Alembic before future schema evolution in deployed environments.

## API

- `GET /api/health`
- `GET /api/projects`
- `POST /api/projects` (`name`, optional `description`, optional HTTP(S) `repository_url`)
- `GET /api/projects/{project_id}`

Project input is validated, project identifiers are generated server-side, and missing projects return 404. CORS allows only the configured frontend origin and the API does not fetch repository URLs.

## Checks

```powershell
cd backend
python -m pytest -q
python -m pip check
python -m pip_audit --requirement requirements.txt
python -m pip_audit --requirement requirements-security.txt
cd ..\frontend
npm run build
npm test
npm audit
npm ls --depth=0
```

Audit commands query external advisory services and require network access. A successful `pip check` or `npm ls` checks installed dependency consistency, not known vulnerabilities. In this verification environment, `npm audit` could not reach `registry.npmjs.org` (`ENOTFOUND`), and `pip-audit` failed while bootstrapping/upgrading pip, wheel, and setuptools in its temporary environment; neither result is a clean vulnerability audit. Run both audit commands in a network-enabled environment with a writable temp directory before relying on advisory coverage.

## Current status

Implemented: responsive light-theme application shell, project management, API target registration with strict demo-only boundary, bounded OpenAPI import and endpoint discovery, deterministic reviewable test generation, HTTPX test execution, persisted sanitized result evidence and history, an expandable execution console, an evidence-backed Security Center with bounded static/dependency/demo checks, and an optional evidence-grounded AI investigation service with validated test and patch proposals.

Not yet implemented: unrestricted remote API testing, credential management/authenticated API testing, Semgrep, patch approval/application, isolated patch execution, automated patch regression verification, reports, user authentication, or production database migrations. Patch staleness fingerprints detect source drift, but they do not provide the isolation/baseline preservation required for applying a patch. Provider-backed investigations require a user-configured compatible API and may incur provider charges; the bundled scripted provider is explicitly a mock. A successful live end-to-end request requires the separately started local demo service; unit tests use HTTPX mock transports and do not by themselves prove a running service integration.

## GitHub repository import — Stage 1

The Security Center can connect a GitHub App installation and import a repository snapshot without a personal access token. The installation token and GitHub App JWT stay on the backend; the browser receives only an HttpOnly, short-lived session cookie. This flow is intended for a trusted, single-user local demonstration because the application does not yet have multi-user sign-in or project-level user authorization.

### Register the GitHub App

1. Create a GitHub App under your GitHub account or organization. Set the App's **Callback URL** to `http://localhost:8000/api/github/callback`; configure its OAuth client ID and secret in backend-only environment settings. Keep the exact host consistent (`localhost`, not a mixture of `localhost` and `127.0.0.1`). The browser OAuth flow verifies installations through the authenticated user's `/user/installations` list; it does not trust an installation ID supplied by a setup URL. GitHub setup URL installation IDs can be spoofed; see [GitHub's Setup URL guidance](https://docs.github.com/en/apps/creating-github-apps/registering-github-app/about-the-setup-url).
2. Grant only **Repository permissions → Contents: Read-only**. Metadata is read automatically. Do not grant contents write, pull request write, or organization administration. Enable installation for the account(s) that should be available.
3. Generate the App private key and keep the downloaded PEM outside source control. Add App ID, App slug, OAuth client ID/secret, and absolute PEM path to root `.env` using `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_PRIVATE_KEY_PATH`, and `GITHUB_CALLBACK_URL`. Never put the PEM contents in `.env`, source files, or frontend settings. The OAuth code is exchanged server-side only to identify the user and list their App installations; it is not saved.
4. Install the App in the account(s) whose repositories should be visible. Restart the backend, open Security Center, and choose **Connect GitHub**. If the user has not yet installed the App, use the installation link shown beside the connect control, then connect again. Installing the app on an account does not imply that a successful repository API request or import has happened; the UI shows the actual connection/import state.

### Import and scan

Select a repository visible to that installation, choose a branch, then import. FailProof resolves the branch to a commit SHA and imports only that immutable commit. The current defaults are 1,200 candidate files, 20 MB total accepted file bytes, 1 MB per file, 90 seconds, and 2 concurrent imports; these can be bounded with the `FAILPROOF_GITHUB_IMPORT_*` environment variables. The tree response itself is capped at 16 MB. Only Python source, Python requirements manifests, and `package.json`/`package-lock.json` are eligible. Common generated/vendor/cache directories, binary blobs, non-regular blobs (including symlinks and gitlinks), secret-named files, and files matching selected private-key/API-key patterns are skipped. Imports do not execute scripts, install packages, run Docker, run tests, or unpack archives. Only the bounded source snippets needed for a finding investigation can be sent to Gemini, subject to the existing sanitizer and context limits.

The UI records the commit SHA, indexed/skipped counts, supported scan types, import status, and errors. Reaching the file-count or byte budget marks the import `completed_partial`; those snapshots can be scanned, but the UI labels them as a bounded subset rather than a complete repository analysis. Scans selected from GitHub include repository, commit, path, blob SHA, and content SHA-256 provenance in source finding evidence and scan details. GitHub snapshot paths are validated beneath a separate `.failproof/github` workspace; the local scan allowlist remains unchanged. GitHub snapshots are immutable inputs: AI patch proposals for those findings are unavailable, and patch approval/application are unavailable until a safe isolated worktree/copy mechanism exists.

### Configuration variables

`GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_PRIVATE_KEY_PATH`, and `GITHUB_CALLBACK_URL` are required to enable the flow. The private key file path must be readable by the backend process and should be protected with local OS permissions. `FAILPROOF_GITHUB_WORKSPACE_DIR` optionally chooses a dedicated import workspace; the default is the ignored repository-local `.failproof/github/`. Limits may be overridden with `FAILPROOF_GITHUB_IMPORT_MAX_FILES`, `FAILPROOF_GITHUB_IMPORT_MAX_TOTAL_BYTES`, `FAILPROOF_GITHUB_IMPORT_MAX_FILE_BYTES`, `FAILPROOF_GITHUB_IMPORT_TIMEOUT_SECONDS`, and `FAILPROOF_GITHUB_IMPORT_CONCURRENCY`. The importer uses Git Trees and Git Blobs endpoints, so no archive extraction or archive size limit is involved. User OAuth tokens are used transiently to authenticate the account and are not persisted; installation tokens are generated server-side with read-only contents and metadata permissions.

### Tests and limitations

GitHub API tests use mocked HTTP responses; they require no GitHub credentials or network. Install the backend requirements including `PyJWT[crypto]`. The complete backend test command remains `python -m pytest backend/tests`. The frontend tests/build remain `cd frontend; npm test` and `npm run build`. This stage has no PR creation/write, automated patching, arbitrary repository execution, commit checkout, full language coverage, live GitHub connection test, or multi-user authorization. GitHub rate limits can delay repository listing/import. GitHub can truncate very large recursive trees; those imports fail instead of claiming a complete scan. Scanners currently cover Python with Bandit and supported dependency manifests with pip-audit/npm audit; unsupported types are reported. The initial database approach creates additive tables with SQLAlchemy `create_all`; it does not migrate an existing deployed database schema with Alembic.
