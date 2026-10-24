from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SourceRegistration(BaseModel):
    source_path: str = Field(min_length=1, max_length=1000)
    authorized: Literal[True]


class SourceRead(BaseModel):
    configured: bool
    source_name: str | None = None
    authorized: bool = False
    registered_at: datetime | None = None


class ScanCreate(BaseModel):
    scan_type: Literal["static", "dependencies", "api_security", "business_logic"]
    approve_state_changes: bool = False
    source_kind: Literal["local", "github"] = "local"
    github_repository_id: str | None = Field(default=None, min_length=36, max_length=36)


class ScanRead(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    scanner_availability: dict[str, str]
    errors: list[str]
    warnings: list[str]
    configuration: dict[str, Any]
    summary: str
    finding_count: int

    model_config = ConfigDict(from_attributes=True)


class EvidenceRead(BaseModel):
    id: str
    scan_id: str
    evidence_type: str
    details: dict[str, Any]
    expected_result: str | None
    actual_result: str | None
    relative_path: str | None
    line_number: int | None
    redacted: bool
    truncated: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingRead(BaseModel):
    id: str
    project_id: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    status: str
    source: str
    scan_type: str
    scanner: str
    rule_id: str
    affected_resource: str
    cwe_id: str | None
    cve_id: str | None
    remediation: str
    references: list[str]
    first_detected_at: datetime
    last_observed_at: datetime
    last_scan_id: str | None
    evidence: list[EvidenceRead] = []

    model_config = ConfigDict(from_attributes=True)

