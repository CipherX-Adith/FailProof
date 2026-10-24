import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routes import create_project, get_project, health, list_projects
from app.schemas.project import ProjectCreate


def test_health():
    assert health() == {"status": "ok"}


def test_create_list_and_retrieve_project(db):
    payload = ProjectCreate(name="Payments API", description="Checkout service", repository_url="https://github.com/acme/payments")
    project = create_project(payload, db)
    assert project.name == "Payments API"
    assert project.id
    assert list_projects(db) == [project]
    assert get_project(project.id, db) == project


def test_missing_project_returns_404(db):
    with pytest.raises(HTTPException) as error:
        get_project("missing", db)
    assert error.value.status_code == 404
    assert error.value.detail == "Project not found"


def test_project_input_validation():
    for value in ({"name": "   "}, {"name": "x" * 101}, {"name": "Good", "repository_url": "javascript:alert(1)"}):
        with pytest.raises(ValidationError):
            ProjectCreate.model_validate(value)


def test_projects_persist_across_sessions(db):
    project = create_project(ProjectCreate(name="Persisted"), db)
    project_id = project.id
    db.expire_all()
    assert get_project(project_id, db).name == "Persisted"
