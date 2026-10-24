import json
import importlib.util
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from app.api.api_testing import generate_tests, get_run, register_target, run_tests
from app.models import ApiEndpoint, ApiSpecification, ApiTarget, GeneratedTest, Project
from app.schemas.api_testing import RunRequest, TargetCreate
from app.services.http_execution import execute_case
from app.services.openapi_import import MAX_SPEC_BYTES, SpecificationError, parse_openapi, persist_endpoint
from app.services.test_generation import generate_for_endpoint

DEMO_SPEC = Path(__file__).parents[2] / "demo_api" / "openapi.yaml"


def test_openapi_parses_endpoints_parameters_and_response_codes():
    parsed = parse_openapi(DEMO_SPEC.read_bytes(), "openapi.yaml")
    assert parsed.version == "3.0.3"
    assert parsed.title == "FailProof Synthetic Demo API"
    assert len(parsed.endpoints) == 5
    capture = next(item for item in parsed.endpoints if item["operation_id"] == "captureSyntheticOrder")
    assert capture["method"] == "POST"
    assert capture["required_fields"] == ["amount"]
    assert set(capture["responses"]) == {"201", "409", "422"}


@pytest.mark.parametrize("raw,filename", [
    (b"{not-json", "spec.json"),
    (b"openapi: 2.0\ninfo: {title: old, version: '1'}\npaths: {}", "spec.yaml"),
    (b"openapi: 3.0.3\ninfo: {title: bad, version: '1'}\npaths: [/x]", "spec.yaml"),
    (b"openapi: 3.0.3\ninfo: {title: alias, version: '1'}\npaths: &p {}\nother: *p", "spec.yaml"),
])
def test_invalid_or_unsupported_specifications_are_rejected(raw, filename):
    with pytest.raises(SpecificationError):
        parse_openapi(raw, filename)


def test_upload_size_limit_is_enforced_by_parser():
    with pytest.raises(SpecificationError, match="1 MB"):
        parse_openapi(b"x" * (MAX_SPEC_BYTES + 1), "large.json")


def test_generation_is_stable_and_uses_contract_and_explicit_rules(db):
    project = Project(name="Demo", description="")
    db.add(project); db.flush()
    target = ApiTarget(project_id=project.id, name="Demo", base_url="http://127.0.0.1:8765", authorized=True, status="ready", config={})
    db.add(target); db.flush()
    parsed = parse_openapi(DEMO_SPEC.read_bytes(), "openapi.yaml")
    spec = ApiSpecification(target_id=target.id, openapi_version=parsed.version, title=parsed.title, source_filename="openapi.yaml", sha256=parsed.digest)
    db.add(spec); db.flush()
    endpoints = [persist_endpoint(target.id, spec.id, item) for item in parsed.endpoints]
    capture = next(item for item in endpoints if item.operation_id == "captureSyntheticOrder")
    first = generate_for_endpoint(target, capture, capture.configured_rules)
    again = generate_for_endpoint(target, capture, capture.configured_rules)
    assert [test.id for test in first] == [test.id for test in again]
    duplicate = next(test for test in first if test.category == "duplicate-operation")
    assert duplicate.expected_statuses == ["201", "409"]
    assert duplicate.repetitions == 2
    validate = next(item for item in endpoints if item.operation_id == "validateCode")
    validate_tests = generate_for_endpoint(target, validate)
    assert any(test.category == "incorrect-type" for test in validate_tests)
    assert any(test.category == "boundary-value" for test in validate_tests)


def test_target_registration_requires_project_and_allows_only_local_demo(db):
    project = Project(name="Demo", description="")
    db.add(project); db.commit()
    created = register_target(project.id, TargetCreate(name="Demo", authorized=True), db)
    assert created.base_url == "http://127.0.0.1:8765"
    assert created.authorized is True
    with pytest.raises(HTTPException) as error:
        register_target(project.id, TargetCreate(name="Remote", base_url="https://example.com", authorized=True), db)
    assert error.value.status_code == 400


def _target(**changes):
    values = {"id": "target", "project_id": "project", "name": "demo", "base_url": "http://127.0.0.1:8765", "spec_source": "upload", "authorized": True, "status": "ready", "config": {}}
    values.update(changes)
    return ApiTarget(**values)


def _execution_items(method="GET", path="/health", body=None, statuses=None, params=None, requires_approval=False, repetitions=1):
    endpoint = ApiEndpoint(id="endpoint", target_id="target", specification_id="spec", path=path, method=method, operation_id="operation", summary="", parameters=params or [], request_schema=None, required_fields=[], responses={})
    case = GeneratedTest(id="case", target_id="target", endpoint_id="endpoint", name="case", category="valid", parameters={}, request_body=body, expected_statuses=statuses or ["200"], expected_behavior="", rationale="", requires_approval=requires_approval, repetitions=repetitions)
    return endpoint, case


def test_http_execution_compares_status_and_sanitizes_evidence():
    endpoint, case = _execution_items(method="POST", path="/validate", body={"password": "sensitive-value", "code": "abc", "note": "api_key=inline-request-secret"}, statuses=["200"])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"token": "secret-value", "message": "Bearer secret-token password=inline-response-secret", "url": "https://user:pass@example.test/resource"}))
    result = execute_case(_target(), endpoint, case, approve_non_safe=True, transport=transport)
    assert result["state"] == "passed"
    serialized = json.dumps(result["evidence"])
    assert all(secret not in serialized for secret in ("sensitive-value", "secret-value", "secret-token", "inline-request-secret", "inline-response-secret", "user:pass"))
    assert result["actual_status"] == 200


def test_http_execution_blocks_sensitive_query_parameters():
    endpoint, case = _execution_items(params=[{"name": "access_token", "in": "query", "required": True, "schema": {"type": "string"}}])
    case.parameters = {"access_token": "do-not-store"}
    result = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    assert result["state"] == "blocked"
    assert "do-not-store" not in json.dumps(result["evidence"])


def test_http_execution_marks_comparison_failure_and_unreachable_error():
    endpoint, case = _execution_items(statuses=["204"])
    failed = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    assert failed["state"] == "failed"
    def unreachable(request):
        raise httpx.ConnectError("refused", request=request)
    error = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(unreachable))
    assert error["state"] == "error"
    assert error["actual_status"] is None
    timeout = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timed out", request=request))))
    assert timeout["state"] == "error"


def test_response_size_and_redirects_are_not_followed():
    endpoint, case = _execution_items()
    huge = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 70000)))
    assert huge["state"] == "error"
    redirect = execute_case(_target(), endpoint, case, transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "http://169.254.169.254/"})))
    assert redirect["state"] == "failed"
    assert redirect["actual_status"] == 302


def test_bundled_demo_has_documented_synthetic_defects(monkeypatch):
    demo_path = DEMO_SPEC.parent / "app.py"
    spec = importlib.util.spec_from_file_location("failproof_demo_test_app", demo_path)
    demo = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(demo)
    db_path = Path(__file__).with_name("demo-test.sqlite3")
    monkeypatch.setattr(demo, "DB_PATH", db_path)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS captures (order_id TEXT PRIMARY KEY, capture_count INTEGER NOT NULL)")
        connection.execute("DELETE FROM captures")
        connection.commit()
    finally:
        connection.close()
    assert demo.validate_code(demo.CodeInput(code="x"))["accepted"] is True
    assert demo.accept_required(demo.RequiredInput())["accepted"] is True
    assert demo.read_document("alice", "bob-private")["document"]["owner"] == "bob"
    first = demo.capture_order("case-order", demo.CaptureInput(amount=10))
    second = demo.capture_order("case-order", demo.CaptureInput(amount=10))
    assert first.status_code == 201 and second.status_code == 200


def test_target_restrictions_and_approval_block_before_http():
    endpoint, case = _execution_items(method="POST", path="/orders/demo/capture", statuses=["201"], requires_approval=True)
    blocked = execute_case(_target(), endpoint, case)
    assert blocked["state"] == "blocked"
    remote = execute_case(_target(base_url="http://169.254.169.254:80"), *_execution_items())
    assert remote["state"] == "blocked"


def test_test_run_results_are_persisted_and_retrievable(db, monkeypatch):
    project = Project(name="Persist", description="")
    db.add(project); db.flush()
    target = ApiTarget(project_id=project.id, name="demo", base_url="http://127.0.0.1:8765", authorized=True, status="ready", config={})
    db.add(target); db.flush()
    parsed = parse_openapi(DEMO_SPEC.read_bytes(), "openapi.yaml")
    spec = ApiSpecification(target_id=target.id, openapi_version=parsed.version, title=parsed.title, source_filename="openapi.yaml", sha256=parsed.digest)
    db.add(spec); db.flush()
    for item in parsed.endpoints:
        db.add(persist_endpoint(target.id, spec.id, item))
    db.commit()
    generated = generate_tests(target.id, db)
    assert generated
    monkeypatch.setattr("app.api.api_testing.execute_case", lambda *args, **kwargs: {"state": "passed", "error_detail": None, "actual_status": 200, "duration_ms": 3.2, "evidence": {"responses": [{"status": 200}]}})
    run = run_tests(target.id, RunRequest(test_ids=[generated[0].id]), db)
    assert run["result_count"] == 1
    assert get_run(run["id"], db)["results"][0].state == "passed"
