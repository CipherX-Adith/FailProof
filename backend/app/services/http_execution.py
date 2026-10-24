import ipaddress
import json
import re
import socket
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx

from app.models.api_testing import ApiEndpoint, ApiTarget, GeneratedTest

DEMO_ORIGIN = "http://127.0.0.1:8765"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 64 * 1024
TIMEOUT_SECONDS = 3.0
CAPTURE_RESPONSE_HEADERS = ("content-type", "x-content-type-options", "x-frame-options", "content-security-policy", "strict-transport-security", "cache-control")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SENSITIVE = re.compile(r"authorization|\bauth\b|credential|cookie|token|secret|password|api[_-]?key|session", re.I)
BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")
SECRET_VALUE = re.compile(r"(?i)((?:token|password|secret|api[_-]?key|authorization)\s*[=:]\s*)(['\"]?)[^\s,'\";]+")
USERINFO = re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@")


class TargetBlocked(ValueError):
    pass


def validate_target(target: ApiTarget) -> None:
    parsed = urlsplit(target.base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 8765 or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TargetBlocked("Only the bundled demo API at http://127.0.0.1:8765 is permitted.")
    # This literal address prevents DNS rebinding and private-address resolution changes.
    resolved = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)}
    if resolved != {ipaddress.ip_address("127.0.0.1")}:
        raise TargetBlocked("Demo target resolved outside the approved loopback address.")


def _redact(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        safe = USERINFO.sub(r"\1[REDACTED]@", value)
        safe = BEARER.sub(r"\1 [REDACTED]", safe)
        return SECRET_VALUE.sub(r"\1[REDACTED]", safe)[:MAX_RESPONSE_BYTES]
    return value


def _expected(actual: list[int], expected: list[str]) -> bool:
    if len(actual) != len(expected):
        return False
    for status, rule in zip(actual, expected):
        rule = rule.upper()
        if rule.isdigit() and status != int(rule):
            return False
        if rule == "2XX" and not 200 <= status < 300:
            return False
        if rule == "4XX" and not 400 <= status < 500:
            return False
    return True


def _url_path(endpoint: ApiEndpoint, params: dict, run_id: str = "") -> str:
    path = endpoint.path
    for name in re.findall(r"\{([^}]+)\}", path):
        if name not in params:
            raise ValueError(f"Required path parameter '{name}' is missing.")
        path = path.replace("{" + name + "}", quote(str(params[name]).replace("$run_id", run_id[:8]), safe=""))
    query_values = {p["name"]: str(params[p["name"]]).replace("$run_id", run_id[:8]) for p in endpoint.parameters if p.get("in") == "query" and p["name"] in params}
    return path + ("?" + urlencode(query_values, doseq=True) if query_values else "")


def _safe_path(path: str) -> str:
    if "?" not in path:
        return path
    query = [(key, "[REDACTED]" if SENSITIVE.search(key) else value) for key, value in parse_qsl(path.split("?", 1)[1], keep_blank_values=True)]
    return path.split("?", 1)[0] + ("?" + urlencode(query) if query else "")


def execute_case(target: ApiTarget, endpoint: ApiEndpoint, case: GeneratedTest, *, run_id: str = "", approve_non_safe: bool = False, transport: httpx.BaseTransport | None = None) -> dict:
    if not target.authorized or target.status != "ready":
        return {"state": "blocked", "error_detail": "Target is not authorized and ready.", "actual_status": None, "duration_ms": None, "evidence": {}}
    try:
        validate_target(target)
    except (TargetBlocked, OSError, ValueError) as exc:
        return {"state": "blocked", "error_detail": str(exc)[:300], "actual_status": None, "duration_ms": None, "evidence": {}}
    if case.requires_approval and not approve_non_safe:
        return {"state": "blocked", "error_detail": "This test requires explicit approval because it uses a state-changing method or repeated operation.", "actual_status": None, "duration_ms": None, "evidence": {}}
    if endpoint.method not in SAFE_METHODS and not approve_non_safe:
        return {"state": "blocked", "error_detail": "State-changing HTTP methods require explicit approval.", "actual_status": None, "duration_ms": None, "evidence": {}}
    for parameter in endpoint.parameters:
        if parameter.get("required") and parameter.get("name") in case.parameters and SENSITIVE.search(parameter["name"]):
            return {"state": "blocked", "error_detail": "Credential-bearing parameters are not supported; no credentials were sent.", "actual_status": None, "duration_ms": None, "evidence": {}}
        if parameter.get("in") == "cookie" and parameter.get("required"):
            return {"state": "blocked", "error_detail": "Cookie parameters are not supported; no cookies were sent.", "actual_status": None, "duration_ms": None, "evidence": {}}
    try:
        path = _url_path(endpoint, case.parameters, run_id)
    except ValueError as exc:
        return {"state": "error", "error_detail": str(exc), "actual_status": None, "duration_ms": None, "evidence": {}}
    url = DEMO_ORIGIN + path
    statuses: list[int] = []
    captured: list[dict] = []
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False, transport=transport) as client:
            for _ in range(max(1, min(case.repetitions, 3))):
                # Resolve and validate the approved literal destination immediately before sending.
                validate_target(target)
                path = _url_path(endpoint, case.parameters, run_id)
                url = DEMO_ORIGIN + path
                headers = {"Accept": "application/json"}
                for parameter in endpoint.parameters:
                    if parameter.get("in") == "header" and parameter.get("name") in case.parameters:
                        name = parameter["name"]
                        if SENSITIVE.search(name) or name.lower() in {"host", "content-length", "content-type", "connection", "proxy-authorization"}:
                            return {"state": "blocked", "error_detail": "Sensitive or transport-control headers are not supported.", "actual_status": None, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "evidence": {}}
                        headers[name] = str(case.parameters[name])
                request = client.build_request(endpoint.method, url, json=case.request_body if case.request_body is not None else None, headers=headers)
                if len(request.content) > MAX_REQUEST_BYTES or len(path) > 4096:
                    return {"state": "error", "error_detail": "Request exceeded the configured 64 KB body or 4 KB path limit.", "actual_status": None, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "evidence": {"request": {"method": endpoint.method, "path": _safe_path(path), "headers": {"accept": "application/json", "content-type": "application/json" if case.request_body is not None else None}, "body": _redact(case.request_body)}}}
                response = client.send(request, stream=True)
                chunks, total = [], 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        response.close()
                        return {"state": "error", "error_detail": "Response exceeded the 64 KB limit.", "actual_status": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "evidence": {"request": {"method": endpoint.method, "path": _safe_path(path), "headers": {"Accept": "application/json"}, "body": _redact(case.request_body)}, "response": {"status": response.status_code, "truncated": True}}}
                    chunks.append(chunk)
                response_body = b"".join(chunks)
                statuses.append(response.status_code)
                try:
                    parsed_body = json.loads(response_body) if response_body else None
                except (json.JSONDecodeError, UnicodeDecodeError):
                    parsed_body = response_body.decode("utf-8", errors="replace")
                captured.append({"status": response.status_code, "headers": {key: response.headers[key] for key in CAPTURE_RESPONSE_HEADERS if key in response.headers}, "body": _redact(parsed_body)})
                response.close()
        duration = round((time.perf_counter() - started) * 1000, 2)
        passed = _expected(statuses, case.expected_statuses)
        return {"state": "passed" if passed else "failed", "error_detail": None, "actual_status": statuses[-1] if statuses else None, "duration_ms": duration, "evidence": {"request": {"method": endpoint.method, "path": _safe_path(path), "headers": {"Accept": "application/json"}, "body": _redact(case.request_body)}, "responses": captured, "expected_statuses": case.expected_statuses}}
    except (httpx.TimeoutException, httpx.NetworkError, httpx.RequestError) as exc:
        return {"state": "error", "error_detail": f"{exc.__class__.__name__}: target did not complete the request.", "actual_status": None, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "evidence": {"request": {"method": endpoint.method, "path": _safe_path(path), "headers": {"Accept": "application/json"}, "body": _redact(case.request_body)}}}
