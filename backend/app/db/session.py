from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings


def build_engine(database_url: str | None = None):
    url = database_url or get_settings().database_url
    kwargs = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=kwargs, pool_pre_ping=True)


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
