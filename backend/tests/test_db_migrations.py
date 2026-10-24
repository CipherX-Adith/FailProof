from sqlalchemy import create_engine, inspect

from app.db.migrations import upgrade_patch_proposal_baseline


def test_patch_baseline_migration_adds_columns_without_rewriting_legacy_rows():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE security_patch_proposals (id VARCHAR(36) PRIMARY KEY, status VARCHAR(32) NOT NULL)")
        connection.exec_driver_sql("INSERT INTO security_patch_proposals (id, status) VALUES ('legacy', 'draft')")

    upgrade_patch_proposal_baseline(engine)
    upgrade_patch_proposal_baseline(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("security_patch_proposals")}
    assert {"baseline_fingerprints", "diff_sha256"}.issubset(columns)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT id, status FROM security_patch_proposals").one() == ("legacy", "draft")
    engine.dispose()
def test_github_connection_migration_preserves_rows_and_allows_multiple_installations(tmp_path):
    from sqlalchemy import create_engine, inspect
    from app.db.migrations import upgrade_github_connection_sessions

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy-github.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql("""CREATE TABLE github_connections (
            id VARCHAR(36) PRIMARY KEY, session_hash VARCHAR(64) NOT NULL UNIQUE,
            github_user_id BIGINT NOT NULL, github_login VARCHAR(100) NOT NULL,
            installation_id BIGINT NOT NULL, account_login VARCHAR(100) NOT NULL,
            account_type VARCHAR(32) NOT NULL, status VARCHAR(24) NOT NULL,
            connected_at DATETIME NOT NULL, expires_at DATETIME NOT NULL
        )""")
        conn.exec_driver_sql("INSERT INTO github_connections VALUES ('connection', 'digest', 4, 'user', 5, 'org', 'Organization', 'connected', '2026-01-01', '2027-01-01')")

    upgrade_github_connection_sessions(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO github_connections VALUES ('connection-2', 'digest', 4, 'user', 6, 'org-2', 'Organization', 'connected', '2026-01-01', '2027-01-01')")
        assert conn.exec_driver_sql("SELECT COUNT(*) FROM github_connections WHERE session_hash='digest'").scalar_one() == 2
    unique = inspect(engine).get_unique_constraints("github_connections")
    assert any(item["column_names"] == ["session_hash", "installation_id"] for item in unique)
    engine.dispose()
