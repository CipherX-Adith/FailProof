# FailProof AI

FailProof AI is an evidence-driven software engineering and security workspace. Its guiding principle is: **AI proposes. Execution proves. Evidence verifies.** Phase 1 establishes project management and the Verification Workbench shell; it does not claim that code has been scanned or verified.

## Architecture

- `frontend/`: React, TypeScript, Vite, Tailwind CSS, and a purpose-built responsive workbench. The Vite development server proxies `/api` to FastAPI.
- `backend/app/api`: REST routes; `schemas`: validated Pydantic contracts; `services`: OpenAPI import, deterministic test generation, and bounded HTTP execution; `models` and `db`: SQLAlchemy persistence; `core`: environment configuration.
- `backend/tests`: route and persistence tests using an isolated in-memory SQLite database.
- SQLite schema initialization currently uses SQLAlchemy `Base.metadata.create_all` at application startup. This is documented and suitable for the initial schema; introduce Alembic before evolving deployed schemas.
- AI is optional and no provider keys or model responses are configured in Phase 1.

## Prerequisites

- Python 3.10 or newer
- Node.js 20 or newer and npm

## Install

```powershell
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
cd frontend
npm install
```

The frontend uses its Vite proxy during local development. No secrets belong in frontend environment variables.

## Configure

Edit `.env` for local backend settings. `DATABASE_URL` defaults to `sqlite:///./failproof.db`; `FRONTEND_ORIGIN` defaults to `http://localhost:5173`. Keep credentials out of source control and logs. No API keys are needed.

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

Phase 2 records targets, imported specifications, discovered endpoints, generated cases, runs, and results in the existing SQLite database. Startup uses `create_all`; this adds new tables but does not migrate altered existing tables. Add Alembic before future schema evolution in deployed environments.

## API

- `GET /api/health`
- `GET /api/projects`
- `POST /api/projects` (`name`, optional `description`, optional HTTP(S) `repository_url`)
- `GET /api/projects/{project_id}`

Project input is validated, project identifiers are generated server-side, and missing projects return 404. CORS allows only the configured frontend origin and the API does not fetch repository URLs.

## Checks

```powershell
cd backend
python -m pytest
cd ..\frontend
npm run build
npm test
```

## Current status

Implemented: responsive light-theme application shell, project management, API target registration with strict demo-only boundary, bounded OpenAPI import and endpoint discovery, deterministic reviewable test generation, HTTPX test execution, persisted sanitized result evidence and history, an expandable execution console, and the isolated synthetic vulnerable demo API.

Not yet implemented: unrestricted remote API testing, credential management/authenticated API testing, static or dependency scanning, AI analysis or patching, isolated patch execution, regression verification, reports, user authentication, or production database migrations. A successful live end-to-end request requires the separately started local demo service; unit tests use HTTPX mock transports and do not by themselves prove a running service integration.
