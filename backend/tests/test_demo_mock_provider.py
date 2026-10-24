import importlib.util
import json
from pathlib import Path


MOCK_FILE = Path(__file__).parents[2] / "demo_api" / "mock_ai_provider.py"
SPEC = importlib.util.spec_from_file_location("failproof_demo_mock_ai", MOCK_FILE)
assert SPEC and SPEC.loader
mock_ai = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mock_ai)


def payload(prompt: str) -> dict:
    return {"messages": [{"role": "user", "content": prompt}]}


def prompt(instruction: str, context: dict) -> str:
    return f"{instruction}\n\nUNTRUSTED_EVIDENCE_JSON:\n{json.dumps(context)}"


def sample_context() -> dict:
    return {
        "finding": {"id": "finding-real", "title": "Observed synthetic contract mismatch", "category": "static-analysis"},
        "evidence": [{"id": "evidence-real", "details": {"expected_statuses": ["403"]}}],
        "source_excerpts": [{"path": "vulnerable.py", "line": 5, "excerpt": "1: import subprocess\n5:     return subprocess.run(command, shell=True, check=False)"}],
    }


def test_mock_investigation_uses_supplied_evidence_and_labels_hypothesis():
    completion = mock_ai.mock_completion(payload(prompt("Investigate this existing finding.", sample_context())))
    result = json.loads(completion["choices"][0]["message"]["content"])
    assert completion["model"] == "failproof-demo-mock"
    assert result["evidence_references"] == ["evidence-real"]
    assert result["code_references"] == [{"path": "vulnerable.py", "line": 5, "evidence_id": "evidence-real"}]
    assert "not model-generated" in result["summary"]
    assert "not establish exploitability" in result["contradictory_or_missing_evidence"][0]


def test_mock_test_proposal_is_linked_to_a_supplied_loopback_endpoint():
    context = sample_context()
    context["supported_demo_endpoints"] = [{"id": "endpoint-real", "method": "GET", "path": "/users/{user_id}/documents/{document_id}", "parameters": [{"name": "user_id", "in": "path", "schema": {"example": "alice"}}, {"name": "document_id", "in": "path", "schema": {"example": "bob-private"}}]}]
    result = json.loads(mock_ai.mock_completion(payload(prompt("Propose up to three additional constrained tests.", context)))["choices"][0]["message"]["content"])
    proposal = result["proposals"][0]
    assert proposal["endpoint_id"] == "endpoint-real"
    assert proposal["parameters"] == {"user_id": "alice", "document_id": "bob-private"}
    assert proposal["expected_statuses"] == ["403"]
    assert proposal["evidence_references"] == ["evidence-real"]


def test_mock_patch_is_evidence_linked_and_explicitly_not_a_verified_fix():
    result = json.loads(mock_ai.mock_completion(payload(prompt("Propose a minimal code change as a unified diff only.", sample_context())))["choices"][0]["message"]["content"])
    assert "--- a/vulnerable.py" in result["unified_diff"]
    assert "shell=True" in result["unified_diff"] and "shell=False" in result["unified_diff"]
    assert result["evidence_references"] == ["evidence-real"]
    assert "Mock-only" in result["rationale"] and "real regression suite" in result["rationale"]
