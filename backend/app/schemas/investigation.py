from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GroundedObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=1500)
    evidence_ids: list[str] = Field(default_factory=list, max_length=10)


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    evidence_id: str = Field(min_length=1, max_length=36)


class InvestigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=1500)
    likely_root_cause: str = Field(min_length=1, max_length=3000)
    confidence: Literal["low", "medium", "high"]
    confidence_explanation: str = Field(min_length=1, max_length=1500)
    evidence_references: list[str] = Field(default_factory=list, max_length=30)
    code_references: list[SourceReference] = Field(default_factory=list, max_length=20)
    supporting_observations: list[GroundedObservation] = Field(default_factory=list, max_length=20)
    contradictory_or_missing_evidence: list[str] = Field(default_factory=list, max_length=20)
    alternative_explanations: list[str] = Field(default_factory=list, max_length=10)
    preconditions: list[str] = Field(default_factory=list, max_length=20)
    potential_impact: str = Field(min_length=1, max_length=1500)
    limitations: list[str] = Field(default_factory=list, max_length=20)
    validation_steps: list[str] = Field(default_factory=list, max_length=20)
    remediation_approach: str = Field(min_length=1, max_length=1500)


class TestProposalOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    execution_mode: Literal["demo-api", "manual"] = "manual"
    purpose: str = Field(min_length=1, max_length=1000)
    endpoint_id: str | None = Field(default=None, max_length=64)
    preconditions: list[str] = Field(default_factory=list, max_length=10)
    parameters: dict[str, Any] = Field(default_factory=dict)
    request_body: Any | None = None
    expected_statuses: list[str] = Field(min_length=1, max_length=3)
    expected_behavior: str = Field(min_length=1, max_length=1000)
    assertions: list[str] = Field(default_factory=list, max_length=10)
    evidence_references: list[str] = Field(default_factory=list, max_length=10)


class TestProposalBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposals: list[TestProposalOutput] = Field(min_length=1, max_length=3)


class PatchProposalOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    unified_diff: str = Field(min_length=1, max_length=50_000)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_references: list[str] = Field(default_factory=list, max_length=20)


class InvestigationRead(BaseModel):
    id: str
    project_id: str
    finding_id: str
    provider: str | None
    model: str | None
    status: str
    evidence_references: list[str]
    verified_code_references: list[dict]
    summary: str
    likely_root_cause: str
    confidence: str
    confidence_explanation: str
    supporting_observations: list[dict]
    contradictory_or_missing_evidence: list[str]
    alternative_explanations: list[str]
    preconditions: list[str]
    potential_impact: str
    limitations: list[str]
    validation_steps: list[str]
    remediation_approach: str
    unverified_references: list[str]
    error_detail: str | None
    created_at: datetime
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class TestProposalRead(BaseModel):
    id: str
    project_id: str
    finding_id: str
    investigation_id: str
    execution_mode: str
    endpoint_id: str | None
    title: str
    purpose: str
    preconditions: list[str]
    parameters: dict[str, Any]
    request_body: Any | None
    expected_statuses: list[str]
    expected_behavior: str
    assertions: list[str]
    evidence_references: list[str]
    state_changing: bool
    safety_classification: str
    status: str
    execution_status: str | None
    test_run_id: str | None
    test_result_id: str | None
    decision_note: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PatchProposalRead(BaseModel):
    id: str
    project_id: str
    finding_id: str
    investigation_id: str
    diff: str
    rationale: str
    files_changed: list[str]
    evidence_references: list[str]
    applicability: str
    status: str
    decision_note: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DecisionRequest(BaseModel):
    note: str = Field(default="", max_length=1000)


class ExecuteProposalRequest(BaseModel):
    approve_state_changes: bool = False
