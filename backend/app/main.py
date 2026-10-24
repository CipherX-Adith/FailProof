import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import engine
from app import models  # noqa: F401 - register SQLAlchemy models before schema creation

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")
Base.metadata.create_all(bind=engine)

app = FastAPI(title="FailProof AI", version="0.1.0", description="Evidence-driven software verification workspace")
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
app.include_router(router)
