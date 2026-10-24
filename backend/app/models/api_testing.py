from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def now_utc():
    return datetime.now(timezone.utc)


class ApiTarget(Base):
    __tablename__ = "api_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    base_url: Mapped[str] = mapped_column(String(200), nullable=False)
    spec_source: Mapped[str] = mapped_column(String(30), nullable=False, default="upload")
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="registered")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)


class ApiSpecification(Base):
    __tablename__ = "api_specifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("api_targets.id", ondelete="CASCADE"), index=True)
    openapi_version: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("api_targets.id", ondelete="CASCADE"), index=True)
    specification_id: Mapped[str] = mapped_column(ForeignKey("api_specifications.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    operation_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    summary: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    parameters: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    request_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    required_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    responses: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    configured_rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class GeneratedTest(Base):
    __tablename__ = "generated_tests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("api_targets.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("api_endpoints.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    request_body: Mapped[dict | list | str | None] = mapped_column(JSON, nullable=True)
    expected_statuses: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    repetitions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class TestRun(Base):
    __tablename__ = "api_test_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("api_targets.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class TestResult(Base):
    __tablename__ = "api_test_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    run_id: Mapped[str] = mapped_column(ForeignKey("api_test_runs.id", ondelete="CASCADE"), index=True)
    test_id: Mapped[str] = mapped_column(ForeignKey("generated_tests.id"), index=True)
    endpoint_path: Mapped[str] = mapped_column(String(500), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    actual_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
