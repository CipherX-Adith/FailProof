# FailProof AI

FailProof AI is an evidence-driven software engineering and security workspace. Its guiding principle is: **AI proposes. Execution proves. Evidence verifies.** Phase 1 establishes project management and the Verification Workbench shell; it does not claim that code has been scanned or verified.

## Architecture

- `frontend/`: React, TypeScript, Vite, Tailwind CSS, and a purpose-built responsive workbench. The Vite development server proxies `/api` to FastAPI.
- `backend/app/api`: REST routes; `schemas`: validated Pydantic contracts; `services`: future business logic boundary; `models` and `db`: SQLAlchemy persistence; `core`: environment configuration.
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

Edit `.env` for local backend settings. `DATABASE_URL` defaults to `sqlite:///./failproof.db`; `FRONTEND_ORIGIN` defaults to `http://localhost:5173`. Keep credentials out of source control and logs. No API keys are needed for Phase 1.

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

Implemented: responsive light-theme application shell, primary navigation, project explorer, project creation and persistence, overview with explicit unrun/unknown states, contextual evidence inspector, expandable execution console, API error and loading states, FastAPI project endpoints, SQLite storage, validation, and backend route/persistence tests.

Not yet implemented: API specification import, endpoint discovery, test authoring or execution, static or dependency scanning, dynamic testing, business-logic analysis, findings/evidence persistence, AI analysis or patching, isolated patch execution, regression verification, reports, authentication, and production database migrations. Navigation for later capabilities is intentionally presented as an unimplemented workspace state rather than a claim of functionality.
