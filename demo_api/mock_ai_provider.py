"""Loopback-only deterministic OpenAI-compatible provider for local demos.

Responses are scripted examples, not model output or security conclusions.
"""

import json
import re
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="FailProof Local Mock AI Provider")
PROMPT_MARKER = "UNTRUSTED_EVIDENCE_JSON:\n"


def _context(prompt: str) -> dict:
    if PROMPT_MARKER not in prompt:
        raise ValueError("Expected a FailProof evidence payload.")
    value = json.loads(prompt.split(PROMPT_MARKER, 1)[1])
    if not isinstance(value, dict):
        raise ValueError("Evidence payload must be an object.")
    return value


def _evidence(context: dict) -> dict:
    rows = context.get("evidence")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict) or not isinstance(rows[0].get("id"), str):
        raise ValueError("The demo requires a persisted evidence record.")
    return rows[0]


def _investigation(context: dict) -> dict:
    item = _evidence(context)
    finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
    references = [item["id"]]
    code_references = []
    excerpts = context.get("source_excerpts")
    if isinstance(excerpts, list) and excerpts and isinstance(excerpts[0], dict):
        excerpt = excerpts[0]
        if isinstance(excerpt.get("path"), str) and isinstance(excerpt.get("line"), int):
            code_references.append({"path": excerpt["path"], "line": excerpt["line"], "evidence_id": item["id"]})
    return {
        "summary": "Mock provider demonstration: the persisted evidence is available for review; this response is not model-generated.",
        "likely_root_cause": "A possible cause is the behavior described by the finding and its attached evidence. This is a scripted hypothesis and needs independent validation.",
        "confidence": "low",
        "confidence_explanation": "This deterministic mock only checks that FailProof can pass real evidence through the provider contract.",
        "evidence_references": references,
        "code_references": code_references,
        "supporting_observations": [{"text": f"Persisted evidence {item['id']} is attached to the selected finding.", "evidence_ids": references}],
        "contradictory_or_missing_evidence": ["A mock response does not establish exploitability or production impact."],
        "alternative_explanations": ["The observed behavior may be limited to the synthetic demonstration fixture."],
        "preconditions": ["Review the original scanner or HTTP observation before drawing conclusions."],
        "potential_impact": "No impact is asserted by the mock provider.",
        "limitations": ["Scripted local mock; not a live AI analysis."],
        "validation_steps": ["Inspect the cited evidence and reproduce the behavior using the authorized local demo."],
        "remediation_approach": f"Review the existing remediation guidance for {str(finding.get('title', 'this finding'))[:120]}.",
    }


def _test_proposals(context: dict) -> dict:
    item = _evidence(context)
    endpoints = context.get("supported_demo_endpoints")
    if isinstance(endpoints, list) and endpoints and isinstance(endpoints[0], dict):
        endpoint = endpoints[0]
        parameters = {}
        for value in endpoint.get("parameters", []):
            if value.get("in") not in {"path", "query"}:
                continue
            example = value.get("schema", {}).get("example")
            parameters[value["name"]] = example if example is not None else ("alice" if value["name"] == "user_id" else "bob-private" if value["name"] == "document_id" else "demo")
        expected = item.get("details", {}).get("expected_statuses", ["200"])
        if not isinstance(expected, list) or not expected:
            expected = ["200"]
        proposal = {
            "title": "Repeat the observed demo contract check",
            "execution_mode": "demo-api",
            "purpose": "Mock example: repeat the existing deterministic check against the same authorized loopback endpoint.",
            "endpoint_id": endpoint["id"],
            "preconditions": ["Use only the registered synthetic loopback demo."],
            "parameters": parameters,
            "request_body": None,
            "expected_statuses": expected[:3],
            "expected_behavior": "The registered demo contract is respected.",
            "assertions": ["Compare the actual response with the imported contract rule."],
            "evidence_references": [item["id"]],
        }
    else:
        proposal = {
            "title": "Review the source behavior linked to the finding",
            "execution_mode": "manual",
            "purpose": "Mock example: review the cited source and decide whether a focused regression test is warranted.",
            "endpoint_id": None,
            "preconditions": ["Inspect the referenced source line and surrounding call sites."],
            "parameters": {},
            "request_body": None,
            "expected_statuses": ["200"],
            "expected_behavior": "A reviewer records the actual expected behavior before implementing a test.",
            "assertions": ["Do not treat this manual proposal as an executed test."],
            "evidence_references": [item["id"]],
        }
    return {"proposals": [proposal]}


def _patch_proposal(context: dict) -> dict:
    item = _evidence(context)
    excerpts = context.get("source_excerpts")
    if not isinstance(excerpts, list) or not excerpts or not isinstance(excerpts[0], dict):
        raise ValueError("The finding has no evidence-linked source excerpt.")
    excerpt = excerpts[0]
    path = excerpt.get("path")
    line_number = excerpt.get("line")
    lines = str(excerpt.get("excerpt", "")).splitlines()
    matched = next((line for line in lines if "shell=True" in line), None)
    if not isinstance(path, str) or not isinstance(line_number, int) or matched is None:
        raise ValueError("The mock patch only supports the bundled shell=True fixture line.")
    original = re.sub(r"^\d+: ?", "", matched)
    replacement = original.replace("shell=True", "shell=False")
    if original == replacement or "\n" in original or original.startswith(("+", "-")):
        raise ValueError("The evidence-linked mock patch could not be constructed.")
    diff = f"--- a/{path}\n+++ b/{path}\n@@ -{line_number} +{line_number} @@\n-{original}\n+{replacement}\n"
    return {
        "unified_diff": diff,
        "rationale": "Mock-only review example. Disabling shell interpretation may change behavior for string commands; convert and validate arguments and run a real regression suite before considering any fix.",
        "evidence_references": [item["id"]],
    }


def mock_completion(payload: dict) -> dict:
    messages = payload.get("messages")
    user = next((row.get("content") for row in reversed(messages or []) if row.get("role") == "user"), None)
    if not isinstance(user, str):
        raise ValueError("A user prompt is required.")
    context = _context(user)
    if "Propose a minimal code change as a unified diff only." in user:
        result = _patch_proposal(context)
    elif "Propose up to three additional constrained tests." in user:
        result = _test_proposals(context)
    else:
        result = _investigation(context)
    return {"id": "chatcmpl-failproof-mock", "object": "chat.completion", "created": int(time.time()), "model": "failproof-demo-mock", "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(result)}, "finish_reason": "stop"}]}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    host = request.client.host if request.client else ""
    if host not in {"127.0.0.1", "::1", "testclient"}:
        return JSONResponse(status_code=403, content={"error": "loopback clients only"})
    try:
        payload = await request.json()
        return mock_completion(payload)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return JSONResponse(status_code=422, content={"error": "invalid mock-provider request"})
