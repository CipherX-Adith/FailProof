from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    base_url: HttpUrl = "http://127.0.0.1:8765"
    authorized: Literal[True]
    approve_non_safe_methods: bool = False

    model_config = ConfigDict(str_strip_whitespace=True)


class TargetRead(BaseModel):
    id: str
    project_id: str
    name: str
    base_url: str
    spec_source: str
    authorized: bool
    status: str
    registered_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SpecificationRead(BaseModel):
    id: str
    target_id: str
    openapi_version: str
    title: str
    source_filename: str
    sha256: str
    imported_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EndpointRead(BaseModel):
    id: str
    target_id: str
    path: str
    method: str
    operation_id: str | None
    summary: str
    parameters: list[dict[str, Any]]
    request_schema: dict[str, Any] | None
    required_fields: list[str]
    responses: dict[str, dict[str, Any]]

    model_config = ConfigDict(from_attributes=True)


class GeneratedTestRead(BaseModel):
    id: str
    endpoint_id: str
    name: str
    category: str
    parameters: dict[str, Any]
    request_body: Any | None
    expected_statuses: list[str]
    expected_behavior: str
    rationale: str
    requires_approval: bool
    repetitions: int

    model_config = ConfigDict(from_attributes=True)


class RunRequest(BaseModel):
    test_ids: list[str] | None = Field(default=None, max_length=50)
    approve_non_safe: bool = False


class TestResultRead(BaseModel):
    id: str
    test_id: str
    endpoint_path: str
    method: str
    state: str
    actual_status: int | None
    duration_ms: float | None
    error_detail: str | None
    evidence: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TestRunRead(BaseModel):
    id: str
    target_id: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    result_count: int
    results: list[TestResultRead] = []

    model_config = ConfigDict(from_attributes=True)
