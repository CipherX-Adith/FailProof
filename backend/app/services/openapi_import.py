import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.tokens import AliasToken

from app.models.api_testing import ApiEndpoint

MAX_SPEC_BYTES = 1_000_000
METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


class SpecificationError(ValueError):
    pass


@dataclass
class ParsedSpecification:
    version: str
    title: str
    digest: str
    endpoints: list[dict[str, Any]]


def _schema(document: dict, schema: Any) -> dict | None:
    if not isinstance(schema, dict):
        return None
    ref = schema.get("$ref")
    if ref is not None and (not isinstance(ref, str) or not ref.startswith("#/components/schemas/")):
        raise SpecificationError("Only local references to components/schemas are supported.")
    if isinstance(ref, str):
        current: Any = document
        for part in ref[2:].split("/"):
            current = current.get(part) if isinstance(current, dict) else None
        if isinstance(current, dict):
            resolved = dict(current)
            resolved.update({key: value for key, value in schema.items() if key != "$ref"})
            return resolved
        raise SpecificationError(f"Unresolved schema reference: {ref}.")
    return schema


def parse_openapi(raw: bytes, filename: str) -> ParsedSpecification:
    if not raw:
        raise SpecificationError("The uploaded specification is empty.")
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecificationError("Specification exceeds the 1 MB upload limit.")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SpecificationError("Specification must be UTF-8 encoded JSON or YAML.") from exc
    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if extension == "json":
            document = json.loads(content)
        elif extension in {"yaml", "yml"}:
            if any(isinstance(token, AliasToken) for token in yaml.scan(content)):
                raise SpecificationError("YAML aliases are not supported.")
            document = yaml.safe_load(content)
        else:
            raise SpecificationError("Upload a .json, .yaml, or .yml specification.")
    except SpecificationError:
        raise
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SpecificationError(f"Could not parse specification: {exc.__class__.__name__}.") from exc
    if not isinstance(document, dict):
        raise SpecificationError("OpenAPI document must be a JSON or YAML object.")
    version = document.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.(0|1)\.\d+", version):
        raise SpecificationError("Supported OpenAPI versions are 3.0.x and 3.1.x.")
    info = document.get("info")
    paths = document.get("paths")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str) or not isinstance(info.get("version"), str) or not isinstance(paths, dict):
        raise SpecificationError("OpenAPI document must include info.title, info.version, and a paths object.")
    endpoints: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise SpecificationError("Each path must start with '/' and contain an operation object.")
        path_parameters = path_item.get("parameters", [])
        if not isinstance(path_parameters, list):
            raise SpecificationError(f"Path parameters for {path} must be a list.")
        for method, operation in path_item.items():
            if method.lower() not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise SpecificationError(f"Operation {method.upper()} {path} must be an object.")
            responses = operation.get("responses")
            if not isinstance(responses, dict) or not responses:
                raise SpecificationError(f"Operation {method.upper()} {path} must document responses.")
            operation_parameters = operation.get("parameters", [])
            if not isinstance(operation_parameters, list):
                raise SpecificationError(f"Parameters for {method.upper()} {path} must be a list.")
            merged: dict[tuple[str, str], dict] = {}
            for parameter in path_parameters + operation_parameters:
                if isinstance(parameter, dict) and "$ref" in parameter:
                    raise SpecificationError("Referenced parameters are not supported; inline the parameter definitions.")
                if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str) or parameter.get("in") not in {"path", "query", "header", "cookie"}:
                    raise SpecificationError(f"Invalid parameter declaration in {method.upper()} {path}.")
                merged[(parameter["in"], parameter["name"])] = parameter
            normalized_parameters = []
            for p in merged.values():
                if "schema" in p and not isinstance(p["schema"], dict):
                    raise SpecificationError(f"Schema for parameter {p['name']} must be an object.")
                normalized_parameters.append({"name": p["name"], "in": p["in"], "required": bool(p.get("required", p["in"] == "path")), "schema": _schema(document, p.get("schema", {})), "description": p.get("description", "")})
            body_schema = None
            required_fields: list[str] = []
            request_body = operation.get("requestBody")
            if request_body:
                if not isinstance(request_body, dict):
                    raise SpecificationError(f"Request body for {method.upper()} {path} must be an object.")
                if "$ref" in request_body:
                    raise SpecificationError("Referenced request bodies are not supported; inline the request body.")
                content_map = request_body.get("content", {})
                if not isinstance(content_map, dict):
                    raise SpecificationError(f"Request body content for {method.upper()} {path} must be an object.")
                media = content_map.get("application/json") or next((v for k, v in content_map.items() if k.endswith("+json")), None)
                if content_map and media is None:
                    raise SpecificationError(f"Request body for {method.upper()} {path} must use JSON media type.")
                body_schema = _schema(document, media.get("schema") if isinstance(media, dict) else None)
                if body_schema:
                    required_fields = list(body_schema.get("required", []))
            normalized_responses = {}
            for code, response in responses.items():
                if not (str(code).lower() == "default" or re.fullmatch(r"[1-5](?:\d{2}|xx)", str(code), re.I)):
                    raise SpecificationError(f"Invalid response status key '{code}' for {method.upper()} {path}.")
                if not isinstance(response, dict):
                    raise SpecificationError(f"Response {code} for {method.upper()} {path} must be an object.")
                if "$ref" in response:
                    raise SpecificationError("Referenced responses are not supported; inline the response definitions.")
                content = response.get("content") or {}
                response_schemas = {}
                for media_type, media_object in content.items():
                    if isinstance(media_object, dict) and media_object.get("schema") is not None:
                        response_schemas[media_type] = _schema(document, media_object["schema"])
                normalized_responses[str(code)] = {"description": response.get("description", ""), "content_types": list(content.keys()), "schemas": response_schemas}
            endpoints.append({"path": path, "method": method.upper(), "operation_id": operation.get("operationId"), "summary": operation.get("summary") or operation.get("description", ""), "parameters": normalized_parameters, "request_schema": body_schema, "required_fields": required_fields, "responses": normalized_responses, "rules": operation.get("x-failproof-test-cases", [])})
            if len(endpoints) > 500:
                raise SpecificationError("Specification contains more than 500 operations.")
    if not endpoints:
        raise SpecificationError("No supported HTTP operations were found in paths.")
    return ParsedSpecification(version, info["title"][:200], hashlib.sha256(raw).hexdigest(), endpoints)


def persist_endpoint(target_id: str, specification_id: str, data: dict[str, Any]) -> ApiEndpoint:
    rules = data.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 10:
        raise SpecificationError("Each operation may define at most 10 x-failproof-test-cases rules.")
    endpoint_id = hashlib.sha256(f"{target_id}:{data['method']}:{data['path']}".encode()).hexdigest()[:32]
    return ApiEndpoint(id=endpoint_id, target_id=target_id, specification_id=specification_id, path=data["path"], method=data["method"], operation_id=data.get("operation_id"), summary=str(data.get("summary", ""))[:500], parameters=data["parameters"], request_schema=data["request_schema"], required_fields=data["required_fields"], responses=data["responses"], configured_rules=rules)
