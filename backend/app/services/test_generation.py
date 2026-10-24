import hashlib
import json
from typing import Any

from app.models.api_testing import ApiEndpoint, ApiTarget, GeneratedTest


def _sample(schema: dict[str, Any] | None) -> Any:
    schema = schema or {}
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object":
        props = schema.get("properties", {})
        return {key: _sample(props[key]) for key in schema.get("required", []) if key in props}
    if kind == "array":
        return [_sample(schema.get("items", {}))]
    if kind == "string":
        minimum = int(schema.get("minLength", 1))
        if minimum > 512:
            return None
        return "x" * max(1, minimum)
    if kind == "integer":
        return int(schema.get("minimum", 1))
    if kind == "number":
        return float(schema.get("minimum", 1))
    if kind == "boolean":
        return True
    return None


def _valid_statuses(endpoint: ApiEndpoint) -> list[str]:
    return [code for code in endpoint.responses if code.isdigit() and 200 <= int(code) < 300] or [code for code in endpoint.responses if code.upper() == "2XX"]


def _error_statuses(endpoint: ApiEndpoint) -> list[str]:
    return [code for code in endpoint.responses if code.isdigit() and 400 <= int(code) < 500] or [code for code in endpoint.responses if code.upper() == "4XX"]


def _test_id(target_id: str, endpoint: ApiEndpoint, category: str, parameters: dict, body: Any, name: str) -> str:
    payload = json.dumps([target_id, endpoint.method, endpoint.path, category, parameters, body, name], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _make(target: ApiTarget, endpoint: ApiEndpoint, *, name: str, category: str, parameters: dict, body: Any, statuses: list[str], behavior: str, rationale: str, approval: bool = False, repetitions: int = 1) -> GeneratedTest:
    test_id = _test_id(target.id, endpoint, category, parameters, body, name)
    return GeneratedTest(id=test_id, target_id=target.id, endpoint_id=endpoint.id, name=name, category=category, parameters=parameters, request_body=body, expected_statuses=statuses, expected_behavior=behavior, rationale=rationale, requires_approval=approval, repetitions=repetitions)


def generate_for_endpoint(target: ApiTarget, endpoint: ApiEndpoint, rules: list[dict] | None = None) -> list[GeneratedTest]:
    tests: list[GeneratedTest] = []
    params: dict[str, Any] = {}
    for parameter in endpoint.parameters:
        if parameter["in"] in {"path", "query", "header", "cookie"} and parameter.get("required"):
            params[parameter["name"]] = _sample(parameter.get("schema"))
    body = _sample(endpoint.request_schema)
    if body is not None and endpoint.request_schema and endpoint.request_schema.get("type") == "object":
        for key in endpoint.required_fields:
            props = endpoint.request_schema.get("properties", {})
            if key in props and key not in body:
                body[key] = _sample(props[key])
    success = _valid_statuses(endpoint)
    errors = _error_statuses(endpoint)
    safe = endpoint.method in {"GET", "HEAD", "OPTIONS"}
    if success:
        tests.append(_make(target, endpoint, name="Schema-conforming request", category="valid", parameters=params, body=body, statuses=success, behavior=f"Return one of the documented success statuses: {', '.join(success)}.", rationale="Values are deterministically derived from the OpenAPI schema and required parameters.", approval=not safe))
    if errors and endpoint.request_schema and endpoint.request_schema.get("type") == "object" and endpoint.required_fields:
        missing = dict(body or {})
        missing.pop(endpoint.required_fields[0], None)
        tests.append(_make(target, endpoint, name=f"Omit required field: {endpoint.required_fields[0]}", category="missing-required", parameters=params, body=missing, statuses=errors, behavior=f"Reject the request with a documented client error: {', '.join(errors)}.", rationale=f"The OpenAPI request schema marks '{endpoint.required_fields[0]}' as required." , approval=not safe))
    if errors and endpoint.request_schema and endpoint.request_schema.get("type") == "object":
        props = endpoint.request_schema.get("properties", {})
        for key, schema in props.items():
            if schema.get("type") in {"string", "integer", "number", "boolean", "object", "array"}:
                invalid = dict(body or {})
                invalid[key] = {"string": 17, "integer": "wrong-type", "number": "wrong-type", "boolean": "wrong-type", "object": "wrong-type", "array": "wrong-type"}[schema["type"]]
                tests.append(_make(target, endpoint, name=f"Incorrect type for {key}", category="incorrect-type", parameters=params, body=invalid, statuses=errors, behavior=f"Reject the invalid request with a documented client error: {', '.join(errors)}.", rationale=f"'{key}' is declared as {schema['type']} in the OpenAPI schema.", approval=not safe))
                break
        for key, schema in props.items():
            boundary = None
            rationale = None
            if schema.get("type") == "string" and int(schema.get("minLength", 0)) > 0:
                boundary = "x" * max(0, int(schema["minLength"]) - 1)
                rationale = f"'{key}' is shorter than its declared minLength of {schema['minLength']}."
            elif schema.get("type") in {"integer", "number"} and "minimum" in schema:
                boundary = schema["minimum"] - 1
                rationale = f"'{key}' is below its declared minimum of {schema['minimum']}."
            elif schema.get("type") in {"integer", "number"} and "maximum" in schema:
                boundary = schema["maximum"] + 1
                rationale = f"'{key}' is above its declared maximum of {schema['maximum']}."
            if rationale:
                invalid = dict(body or {})
                invalid[key] = boundary
                tests.append(_make(target, endpoint, name=f"Boundary violation for {key}", category="boundary-value", parameters=params, body=invalid, statuses=errors, behavior=f"Reject values outside the documented boundary: {', '.join(errors)}.", rationale=rationale, approval=not safe))
        for parameter in endpoint.parameters:
            schema = parameter.get("schema") or {}
            allowed = schema.get("enum")
            if isinstance(allowed, list) and allowed and parameter.get("in") in {"path", "query"}:
                invalid_value = "__invalid_enum_value__"
                while invalid_value in allowed:
                    invalid_value += "_"
                invalid = dict(params); invalid[parameter["name"]] = invalid_value
                tests.append(_make(target, endpoint, name=f"Invalid value for {parameter['name']}", category="invalid-parameter", parameters=invalid, body=body, statuses=errors, behavior=f"Reject a value outside the documented parameter enum: {', '.join(errors)}.", rationale=f"'{parameter['name']}' accepts only values in its declared enum.", approval=not safe))
    if errors:
        for parameter in endpoint.parameters:
            if parameter.get("required") and parameter.get("in") in {"path", "query"}:
                invalid_params = dict(params)
                invalid_params.pop(parameter["name"], None)
                if parameter["in"] == "query":
                    tests.append(_make(target, endpoint, name=f"Omit required parameter: {parameter['name']}", category="missing-required-parameter", parameters=invalid_params, body=body, statuses=errors, behavior=f"Reject the request with a documented client error: {', '.join(errors)}.", rationale=f"'{parameter['name']}' is declared required in the OpenAPI specification.", approval=not safe))
    for rule in rules or []:
        if not isinstance(rule, dict) or not isinstance(rule.get("name"), str):
            continue
        category = str(rule.get("category", "configured-rule"))[:40]
        statuses = [str(s) for s in rule.get("expected_statuses", [])]
        if not statuses:
            continue
        repetitions = max(1, min(int(rule.get("repetitions", 1)), 3))
        tests.append(_make(target, endpoint, name=rule["name"][:200], category=category, parameters=rule.get("parameters", {}), body=rule.get("request_body"), statuses=statuses, behavior=str(rule.get("expected_behavior", ""))[:1000], rationale=str(rule.get("rationale", "Explicit project rule in the uploaded specification."))[:1000], approval=not safe or repetitions > 1, repetitions=repetitions))
    return tests[:100]
