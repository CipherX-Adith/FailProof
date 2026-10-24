"""Small, additive schema upgrades for the initial SQLite-backed project."""

from sqlalchemy import Engine, inspect


def upgrade_patch_proposal_baseline(engine: Engine) -> None:
    """Add baseline-binding columns without rewriting existing proposal rows."""
    inspector = inspect(engine)
    if "security_patch_proposals" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("security_patch_proposals")}
    additions = {
        "baseline_fingerprints": "JSON",
        "diff_sha256": "VARCHAR(64)",
    }
    missing = [(name, ddl) for name, ddl in additions.items() if name not in existing]
    if not missing:
        return
    preparer = engine.dialect.identifier_preparer
    table = preparer.quote("security_patch_proposals")
    with engine.begin() as connection:
        for name, ddl in missing:
            column = preparer.quote(name)
            connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def upgrade_github_connection_sessions(engine: Engine) -> None:
    """Allow multiple GitHub App installations per browser session."""
    inspector = inspect(engine)
    if "github_connections" not in inspector.get_table_names():
        return
    unique_single_session = [idx["name"] for idx in inspector.get_indexes("github_connections")
                             if idx.get("unique") and idx.get("column_names") == ["session_hash"]]
    legacy_constraint = any(item.get("column_names") == ["session_hash"] for item in inspector.get_unique_constraints("github_connections"))
    if engine.dialect.name == "sqlite":
        with engine.connect() as connection:
            ddl = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE type='table' AND name='github_connections'").scalar_one_or_none() or ""
        normalized_ddl = " ".join(ddl.lower().replace('"', "").split())
        legacy_constraint = legacy_constraint or "session_hash varchar(64) not null unique" in normalized_ddl or "unique (session_hash)" in normalized_ddl
    if engine.dialect.name == "sqlite" and legacy_constraint:
        # Preserve all connection rows while replacing the old UNIQUE(session_hash)
        # table constraint with the intended composite uniqueness.
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("""CREATE TABLE github_connections_new (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    session_hash VARCHAR(64) NOT NULL,
                    github_user_id BIGINT NOT NULL,
                    github_login VARCHAR(100) NOT NULL,
                    installation_id BIGINT NOT NULL,
                    account_login VARCHAR(100) NOT NULL,
                    account_type VARCHAR(32) NOT NULL,
                    status VARCHAR(24) NOT NULL,
                    connected_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    CONSTRAINT uq_github_connection_session_installation UNIQUE (session_hash, installation_id)
                )""")
                columns = "id, session_hash, github_user_id, github_login, installation_id, account_login, account_type, status, connected_at, expires_at"
                connection.exec_driver_sql(f"INSERT INTO github_connections_new ({columns}) SELECT {columns} FROM github_connections")
                connection.exec_driver_sql("DROP TABLE github_connections")
                connection.exec_driver_sql("ALTER TABLE github_connections_new RENAME TO github_connections")
                connection.exec_driver_sql("CREATE INDEX ix_github_connections_session_hash ON github_connections (session_hash)")
                connection.exec_driver_sql("CREATE INDEX ix_github_connections_installation ON github_connections (installation_id)")
                connection.exec_driver_sql("CREATE INDEX ix_github_connections_status ON github_connections (status)")
                transaction.commit()
            except Exception:
                transaction.rollback()
                raise
            finally:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        return
    with engine.begin() as connection:
        for name in unique_single_session:
            quoted = engine.dialect.identifier_preparer.quote(name)
            connection.exec_driver_sql(f"DROP INDEX IF EXISTS {quoted}")
