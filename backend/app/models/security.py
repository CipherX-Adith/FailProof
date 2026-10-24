from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def now_utc():
    return datetime.now(timezone.utc)


class ProjectScanConfig(Base):
    __tablename__ = "project_scan_config"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    source_root: Mapped[str] = mapped_column(Text, nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)


class SecurityScan(Base):
    __tablename__ = "security_scans"
    __table_args__ = (Index("ix_security_scans_project_started", "project_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanner_availability: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    errors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    warnings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    configuration: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="Scan queued.")
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_security_findings_fingerprint"),
        Index("ix_security_findings_project_status", "project_id", "status"),
        Index("ix_security_findings_project_severity", "project_id", "severity"),
        Index("ix_security_findings_source_scope", "project_id", "scan_type", "source"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", index=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="suspected", index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    affected_resource: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="Review the evidence and consult the linked advisory or rule guidance.")
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    last_scan_id: Mapped[str | None] = mapped_column(ForeignKey("security_scans.id", ondelete="SET NULL"), nullable=True, index=True)


class SecurityEvidence(Base):
    __tablename__ = "security_evidence"
    __table_args__ = (Index("ix_security_evidence_finding_created", "finding_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(40), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    expected_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    actual_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    relative_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)


class SecurityInvestigation(Base):
    __tablename__ = "security_investigations"
    __table_args__ = (
        UniqueConstraint("finding_id", "idempotency_key", name="uq_investigation_finding_idempotency"),
        Index("ix_investigations_finding_created", "finding_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(80), nullable=True)
    model: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    evidence_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verified_code_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    likely_root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    confidence_explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    supporting_observations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    contradictory_or_missing_evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    alternative_explanations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    potential_impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    limitations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validation_steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    remediation_approach: Mapped[str] = mapped_column(Text, nullable=False, default="")
    unverified_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecurityTestProposal(Base):
    __tablename__ = "security_test_proposals"
    __table_args__ = (Index("ix_test_proposals_finding_created", "finding_id", "created_at"), UniqueConstraint("investigation_id", "idempotency_key", name="uq_test_proposal_idempotency"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("security_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    execution_mode: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    endpoint_id: Mapped[str | None] = mapped_column(ForeignKey("api_endpoints.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    request_body: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON, nullable=True)
    expected_statuses: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    assertions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    state_changing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    safety_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    execution_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    test_run_id: Mapped[str | None] = mapped_column(ForeignKey("api_test_runs.id", ondelete="SET NULL"), nullable=True)
    test_result_id: Mapped[str | None] = mapped_column(ForeignKey("api_test_results.id", ondelete="SET NULL"), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)


class SecurityPatchProposal(Base):
    __tablename__ = "security_patch_proposals"
    __table_args__ = (Index("ix_patch_proposals_finding_created", "finding_id", "created_at"), UniqueConstraint("investigation_id", "idempotency_key", name="uq_patch_proposal_idempotency"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("security_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    files_changed: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    applicability: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    # Hashes bind a review-only proposal to the authorized source bytes used by
    # its applicability check. Nullable columns keep old records explicitly unbound.
    baseline_fingerprints: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    diff_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
