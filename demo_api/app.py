import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

DB_PATH = Path(os.environ.get("FAILPROOF_DEMO_DB", Path(__file__).with_name("demo.sqlite3")))


@asynccontextmanager
async def lifespan(_app):
    if os.environ.get("FAILPROOF_DEMO_ENABLED") != "1":
        raise RuntimeError("Demo API is disabled. Set FAILPROOF_DEMO_ENABLED=1 for local development only.")
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS captures (order_id TEXT PRIMARY KEY, capture_count INTEGER NOT NULL)")
    yield


app = FastAPI(title="FailProof Synthetic Demo API", version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def loopback_only(request: Request, call_next):
    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1", "testclient"}:
        return JSONResponse(status_code=403, content={"detail": "Demo API is restricted to loopback clients."})
    return await call_next(request)


class CodeInput(BaseModel):
    code: str


class RequiredInput(BaseModel):
    # Deliberate defect: the published contract requires reference, runtime model does not.
    reference: str | None = None


class CaptureInput(BaseModel):
    amount: int = 10


@app.get("/health")
def health():
    return {"status": "ok", "service": "synthetic-demo"}


@app.post("/validate")
def validate_code(payload: CodeInput):
    # Deliberate defect: no minLength check even though OpenAPI declares five characters.
    return {"accepted": True, "code_length": len(payload.code)}


@app.post("/required")
def accept_required(payload: RequiredInput):
    return {"accepted": True, "reference": payload.reference}


@app.get("/users/{user_id}/documents/{document_id}")
def read_document(user_id: str, document_id: str):
    documents = {"bob-private": {"owner": "bob", "title": "Synthetic payroll memo"}}
    document = documents.get(document_id)
    if document is None:
        return JSONResponse(status_code=404, content={"detail": "Document not found"})
    # Deliberate defect: ignores document.owner and returns it to any user_id.
    return {"requested_by": user_id, "document": document}


@app.post("/orders/{order_id}/capture")
def capture_order(order_id: str, payload: CaptureInput):
    with sqlite3.connect(DB_PATH) as connection:
        row = connection.execute("SELECT capture_count FROM captures WHERE order_id = ?", (order_id,)).fetchone()
        count = (row[0] if row else 0) + 1
        connection.execute("INSERT INTO captures(order_id, capture_count) VALUES (?, ?) ON CONFLICT(order_id) DO UPDATE SET capture_count = excluded.capture_count", (order_id, count))
    # Deliberate defect: duplicate captures are allowed rather than returning a conflict.
    return JSONResponse(status_code=201 if count == 1 else 200, content={"order_id": order_id, "capture_count": count, "amount": payload.amount})
