from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def now_utc():
    return datetime.now(timezone.utc)


class GitHubConnection(Base):
    """Browser-bound GitHub App installation connection; no OAuth token is persisted."""

    __tablename__ = "github_connections"
    __table_args__ = (
        Index("ix_github_connections_installation", "installation_id"),
        UniqueConstraint("session_hash", "installation_id", name="uq_github_connection_session_installation"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    session_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    github_user_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    github_login: Mapped[str] = mapped_column(String(100), nullable=False)
    installation_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    account_login: Mapped[str] = mapped_column(String(100), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="connected", index=True)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GitHubRepository(Base):
    """One immutable repository commit imported into a project snapshot."""

    __tablename__ = "github_repositories"
    __table_args__ = (
        UniqueConstraint("project_id", "connection_id", "github_repository_id", "commit_sha", name="uq_github_project_repository_commit"),
        Index("ix_github_repositories_project_status", "project_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    connection_id: Mapped[str] = mapped_column(ForeignKey("github_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    github_repository_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    full_name: Mapped[str] = mapped_column(String(201), nullable=False)
    html_url: Mapped[str] = mapped_column(String(500), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    selected_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    workspace_relpath: Mapped[str | None] = mapped_column(String(120), nullable=True)
    total_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indexed_file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    imported_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    supported_scan_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now_utc, onupdate=now_utc)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GitHubImportFile(Base):
    __tablename__ = "github_import_files"
    __table_args__ = (
        UniqueConstraint("repository_link_id", "relative_path", name="uq_github_import_file_path"),
        Index("ix_github_import_files_link", "repository_link_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    repository_link_id: Mapped[str] = mapped_column(ForeignKey("github_repositories.id", ondelete="CASCADE"), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    blob_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    file_kind: Mapped[str] = mapped_column(String(32), nullable=False)
